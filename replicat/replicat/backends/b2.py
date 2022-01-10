import asyncio
import functools
import io
import logging
import sys

import backoff
import httpx

from .. import Backend, exceptions, utils

B2_API_VERSION = 2
B2_API_BASE_URL = f'https://api.backblazeb2.com/b2api/v{B2_API_VERSION}'

logger = logging.getLogger(__name__)


def on_error(func):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except httpx.HTTPStatusError as e:
            try:
                details = e.response.json()
            except ValueError:
                details = e.response.text
            e.args += (details,)
            if e.response.status_code == httpx.codes.UNAUTHORIZED:
                raise exceptions.AuthRequired
            raise

    return wrapper


def forbidden(e):
    return (
        isinstance(e, httpx.HTTPStatusError)
        and e.response.status_code == httpx.codes.FORBIDDEN
    )


async def on_backoff_reauth(details):
    exc = sys.exc_info()[1]
    if isinstance(exc, httpx.HTTPStatusError):
        try:
            retry_after = exc.response.headers['retry-after']
        except KeyError:
            pass
        else:
            await asyncio.sleep(int(retry_after) - details['wait'])

        if exc.response.status_code == httpx.codes.TOO_MANY_REQUESTS:
            return
        else:
            # Trigger re-auth as per B2 guidelines
            raise exceptions.AuthRequired


async def on_backoff_no_reauth(details):
    # Simply suppress it
    try:
        await on_backoff_reauth(details)
    except exceptions.AuthRequired:
        pass


backoff_decorator = functools.partial(
    backoff.on_exception,
    backoff.expo,
    httpx.HTTPError,
    max_time=64,
    giveup=forbidden,
)
backoff_no_reauth = backoff_decorator(on_backoff=[on_backoff_no_reauth])
backoff_reauth = backoff_decorator(on_backoff=[on_backoff_reauth])


class B2(Backend):

    client = utils.async_client()

    def __init__(self, connection_string, *, key_id, application_key):
        # Name or id
        self.bucket_identifier = connection_string
        self.key_id, self.application_key = key_id, application_key

    async def _list_buckets(self):
        url = f'{self.auth.apiUrl}/b2api/v{B2_API_VERSION}/b2_list_buckets'
        headers = {'Authorization': self.auth.authorizationToken}
        params = {'accountId': self.auth.accountId}
        response = await self.client.post(url, headers=headers, json=params)
        response.raise_for_status()
        return response.json()['buckets']

    async def _get_bucket_info(self):
        try:
            return self._bucket_info
        except AttributeError:
            for bucket in await self._list_buckets():
                if self.bucket_identifier in {bucket['bucketId'], bucket['bucketName']}:
                    self._bucket_info = utils.DefaultNamespace(**bucket)
                    return self._bucket_info

            raise exceptions.ReplicatError(
                f'Bucket {self.bucket_identifier} was not found'
            )

    @backoff_no_reauth
    async def authenticate(self):
        logger.debug('Authenticating')
        auth_url = f'{B2_API_BASE_URL}/b2_authorize_account'
        response = await self.client.get(
            auth_url, auth=(self.key_id, self.application_key)
        )
        response.raise_for_status()
        self.auth = utils.DefaultNamespace(**response.json())
        logger.debug('Authentication set')

    @utils.requires_auth
    @backoff_reauth
    @on_error
    async def exists(self, name):
        bucket_info = await self._get_bucket_info()
        url = f'{self.auth.downloadUrl}/file/{bucket_info.bucketName}/{name}'
        headers = {'Authorization': self.auth.authorizationToken}
        try:
            response = await self.client.head(url, headers=headers)
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == httpx.codes.NOT_FOUND:
                return False
            raise
        else:
            return True

    @utils.requires_auth
    @backoff_reauth
    @on_error
    async def upload(self, name, contents):
        url = f'{self.auth.apiUrl}/b2api/v{B2_API_VERSION}/b2_get_upload_url'
        bucket_info = await self._get_bucket_info()
        params = {'bucketId': bucket_info.bucketId}
        headers = {'Authorization': self.auth.authorizationToken}

        response = await self.client.post(url, json=params, headers=headers)
        response.raise_for_status()
        decoded = response.json()
        upload_url = decoded['uploadUrl']
        upload_token = decoded['authorizationToken']

        upload_headers = {
            'Authorization': upload_token,
            'X-Bz-File-Name': name,
            'Content-Type': 'application/octet-stream',
            'Content-Length': str(len(contents)),
            'X-Bz-Content-Sha1': 'do_not_verify',  # TODO
        }
        try:
            response = await self.client.post(
                upload_url, headers=upload_headers, data=contents
            )
            response.raise_for_status()
        except BaseException:
            if isinstance(contents, io.BytesIO):
                contents.seek(0)
            raise
        else:
            return response.json()

    @utils.requires_auth
    @backoff_reauth
    @on_error
    async def download(self, name):
        bucket_info = await self._get_bucket_info()
        url = f'{self.auth.downloadUrl}/file/{bucket_info.bucketName}/{name}'
        headers = {'Authorization': self.auth.authorizationToken}
        response = await self.client.get(url, headers=headers)
        response.raise_for_status()
        return response.read()

    @utils.requires_auth
    @backoff_reauth
    @on_error
    async def list_files(self, prefix=''):
        url = f'{self.auth.apiUrl}/b2api/v{B2_API_VERSION}/b2_list_file_versions'
        bucket_info = await self._get_bucket_info()
        files = []
        params = {
            'bucketId': bucket_info.bucketId,
            'maxFileCount': 10_000,
            'prefix': prefix,
        }
        headers = {'Authorization': self.auth.authorizationToken}

        while True:
            response = await self.client.post(url, json=params, headers=headers)
            decoded = response.json()
            for file in decoded['files']:
                files.append(file['fileName'])

            if decoded['nextFileName'] is None:
                break

            params['startFileName'] = decoded['nextFileName']

        return files

    @utils.requires_auth
    @backoff_reauth
    @on_error
    async def delete(self, name):
        url = f'{self.auth.apiUrl}/b2api/v{B2_API_VERSION}/b2_hide_file'
        bucket_info = await self._get_bucket_info()
        params = {'bucketId': bucket_info.bucketId, 'fileName': name}
        headers = {'Authorization': self.auth.authorizationToken}
        response = await self.client.post(url, json=params, headers=headers)
        response.raise_for_status()

    async def close(self):
        await self.client.aclose()
        del self.auth


Client = B2
