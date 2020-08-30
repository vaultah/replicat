import asyncio
import base64
import functools
import io
import logging
import sys
from contextlib import suppress

import backoff
import httpx

from .. import Backend
from .. import utils, exceptions

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

    # Trigger re-auth as per B2 guidelines
    raise exceptions.AuthRequired


async def on_backoff_no_reauth(details):
    # Simply suppress it
    with suppress(exceptions.AuthRequired):
        await on_backoff_reauth(details)


backoff_decorator = functools.partial(
    backoff.on_exception, backoff.expo, httpx.RequestError, max_time=60, giveup=forbidden
)
backoff_no_reauth = backoff_decorator(on_backoff=[on_backoff_no_reauth])
backoff_reauth = backoff_decorator(on_backoff=[on_backoff_reauth])


class B2(Backend):

    client = utils.async_client()

    def __init__(self, connection_string, *, key_id, application_key):
        # TODO: Allow bucket name later?
        self.bucket_id = connection_string
        self.key_id, self.application_key = key_id, application_key

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
    async def upload(self, name, contents):
        url = f'{self.auth.apiUrl}/b2api/v{B2_API_VERSION}/b2_get_upload_url'
        params = {'bucketId': self.bucket_id}
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
            'X-Bz-Content-Sha1': 'do_not_verify' # TODO
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
        # TODO: optimize somehow?
        url = f'{self.auth.downloadUrl}/b2api/v{B2_API_VERSION}/b2_download_file_by_id'
        versions = await self.list_files(prefix=name)
        upload_id = next(x['fileId'] for x in versions if x['action'] == 'upload')
        params = {'fileId': upload_id}
        headers = {'Authorization': self.auth.authorizationToken}
        response = await self.client.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.read()

    @utils.requires_auth
    @backoff_reauth
    @on_error
    async def list_files(self, prefix=''):
        files = []
        url = f'{self.auth.apiUrl}/b2api/v{B2_API_VERSION}/b2_list_file_versions'
        params = {'bucketId': self.bucket_id, 'maxFileCount': 10_000, 'prefix': prefix}
        headers = {'Authorization': self.auth.authorizationToken}

        while True:
            response = await self.client.post(url, json=params, headers=headers)
            decoded = response.json()
            files.extend(decoded['files'])
            if decoded['nextFileName'] is None and decoded['nextFileId'] is None:
                break

            params['startFileName'] = decoded['nextFileName']
            params['startFileId'] = decoded['nextFileId']

        return files

    @utils.requires_auth
    @backoff_reauth
    @on_error
    async def hide_file(self, name):
        url = f'{self.auth.apiUrl}/b2api/v{B2_API_VERSION}/b2_hide_file'
        params = {'bucketId': self.bucket_id, 'fileName': name}
        headers = {'Authorization': self.auth.authorizationToken}
        response = await self.client.post(url, json=params, headers=headers)
        response.raise_for_status()


Client = B2
