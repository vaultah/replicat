import asyncio
import functools
import logging
import sys
from urllib.parse import quote
from contextlib import suppress


import backoff
import httpx

from .. import exceptions, utils
from .base import Backend

logger = logging.getLogger(__name__)


def _check_403(e):
    return (
        isinstance(e, httpx.HTTPStatusError)
        and e.response.status_code == httpx.codes.FORBIDDEN
    )


async def _wait_and_trigger_reauth(details):
    exc = sys.exc_info()[1]
    if isinstance(exc, httpx.HTTPStatusError):
        try:
            retry_after = exc.response.headers['retry-after']
        except KeyError:
            pass
        else:
            logger.debug('B2 responded with the retry-after=%r header', retry_after)
            await asyncio.sleep(int(retry_after) - details['wait'])

        if exc.response.status_code == httpx.codes.TOO_MANY_REQUESTS:
            return
        else:
            # Trigger re-auth as per B2 guidelines
            raise exceptions.AuthRequired


async def _wait_without_reauth(details):
    # Simply suppress it
    with suppress(exceptions.AuthRequired):
        await _wait_and_trigger_reauth(details)


async def _raise_for_status_hook(response):
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        e.args += (await e.response.aread(),)
        logger.debug('Error requesting B2', exc_info=True)
        if e.response.status_code == httpx.codes.UNAUTHORIZED:
            raise exceptions.AuthRequired from e
        raise


_backoff_decorator = functools.partial(
    backoff.on_exception,
    backoff.expo,
    httpx.HTTPError,
    max_tries=4,
    giveup=_check_403,
)

backoff_no_reauth = _backoff_decorator(on_backoff=[_wait_without_reauth])
backoff_reauth = _backoff_decorator(on_backoff=[_wait_and_trigger_reauth])


class B2(Backend):
    def __init__(self, connection_string, *, key_id, application_key):
        # Name or id
        self._bucket_identifier = connection_string
        self._client = httpx.AsyncClient(
            timeout=None, event_hooks={'response': [_raise_for_status_hook]}
        )
        self.key_id, self.application_key = key_id, application_key

    @backoff_no_reauth
    async def authenticate(self):
        logger.debug('Requesting authorization')
        response = await self._client.get(
            'https://api.backblazeb2.com/b2api/v2/b2_authorize_account',
            auth=(self.key_id, self.application_key),
        )
        data = response.json()
        logger.debug('B2 authorization: %s', data)
        self._auth = utils.DefaultNamespace(**data)

        if (bucket_id := self._auth.allowed['bucketId']) is not None:
            if (bucket_name := self._auth.allowed['bucketName']) is None:
                raise exceptions.ReplicatError(
                    'Allowed bucketId is set, but bucketName is not, '
                    'meaning the bucket probably no longer exists'
                )

            if self._bucket_identifier not in {bucket_id, bucket_name}:
                raise exceptions.ReplicatError(
                    f'Key is restricted to the different bucket ({bucket_name})'
                )

            self._bucket = utils.DefaultNamespace(id=bucket_id, name=bucket_name)

    @utils.requires_auth
    @backoff_reauth
    async def _get_bucket(self):
        try:
            return self._bucket
        except AttributeError:
            response = await self._client.post(
                f'{self._auth.apiUrl}/b2api/v2/b2_list_buckets',
                json={'accountId': self._auth.accountId},
                headers={'authorization': self._auth.authorizationToken},
            )
            for bucket in response.json()['buckets']:
                bucket_id = bucket['bucketId']
                bucket_name = bucket['bucketName']
                if self._bucket_identifier in {bucket_id, bucket_name}:
                    logger.debug('Found a matching bucket: %s', bucket)
                    self._bucket = utils.DefaultNamespace(
                        id=bucket_id, name=bucket_name
                    )
                    return self._bucket

            raise exceptions.ReplicatError(
                f'Bucket {self._bucket_identifier} was not found'
            )

    @utils.requires_auth
    @backoff_reauth
    async def exists(self, name):
        bucket = await self._get_bucket()
        url = f'{self._auth.downloadUrl}/file/{bucket.name}/{name}'
        headers = {'authorization': self._auth.authorizationToken}
        try:
            await self._client.head(url, headers=headers)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == httpx.codes.NOT_FOUND:
                return False
            raise
        else:
            return True

    @utils.requires_auth
    @backoff_reauth
    async def _get_upload_url_token(self):
        url = f'{self._auth.apiUrl}/b2api/v2/b2_get_upload_url'
        bucket = await self._get_bucket()
        params = {'bucketId': bucket.id}
        headers = {'authorization': self._auth.authorizationToken}

        response = await self._client.post(url, json=params, headers=headers)
        decoded = response.json()
        return decoded['uploadUrl'], decoded['authorizationToken']

    @utils.requires_auth
    @backoff_reauth
    async def upload(self, name, data):
        upload_url, upload_token = await self._get_upload_url_token()
        upload_headers = {
            'authorization': upload_token,
            'x-bz-file-name': quote(name),
            'content-type': 'application/octet-stream',
            'content-length': str(len(data)),
            'x-bz-content-sha1': 'do_not_verify',  # TODO
        }
        await self._client.post(upload_url, headers=upload_headers, content=data)

    @utils.requires_auth
    @backoff_reauth
    async def upload_stream(self, name, stream, length):
        upload_url, upload_token = await self._get_upload_url_token()
        upload_headers = {
            'authorization': upload_token,
            'x-bz-file-name': quote(name),
            'content-type': 'application/octet-stream',
            'content-length': str(length),
            'x-bz-content-sha1': 'do_not_verify',  # TODO
        }
        try:
            await self._client.post(
                upload_url, headers=upload_headers, content=utils.aiter_chunks(stream)
            )
        except:
            stream.seek(0)
            raise

    @utils.requires_auth
    @backoff_reauth
    async def download(self, name):
        bucket = await self._get_bucket()
        url = f'{self._auth.downloadUrl}/file/{bucket.name}/{name}'
        headers = {'authorization': self._auth.authorizationToken}
        response = await self._client.get(url, headers=headers)
        return await response.aread()

    @utils.requires_auth
    @backoff_reauth
    async def download_stream(self, name, stream):
        bucket = await self._get_bucket()
        url = f'{self._auth.downloadUrl}/file/{bucket.name}/{name}'
        headers = {'authorization': self._auth.authorizationToken}

        async with self._client.stream('GET', url, headers=headers) as response:
            content_length = response.headers.get('content-length')
            if content_length is not None:
                content_length = int(content_length)

            try:
                stream.truncate(content_length)
                async for chunk in response.aiter_bytes(128_000):
                    stream.write(chunk)
            except:
                stream.seek(0)
                raise

    @utils.requires_auth
    @backoff_reauth
    async def _list_file_names(self, *, start_file_name=None, prefix=''):
        bucket = await self._get_bucket()
        params = {
            'bucketId': bucket.id,
            'maxFileCount': 10_000,
            'prefix': prefix,
        }
        if start_file_name is not None:
            params['startFileName'] = start_file_name

        headers = {'authorization': self._auth.authorizationToken}
        return await self._client.post(
            f'{self._auth.apiUrl}/b2api/v2/b2_list_file_names',
            json=params,
            headers=headers,
        )

    async def list_files(self, prefix=''):
        start_file_name = None

        while True:
            response = await self._list_file_names(
                start_file_name=start_file_name, prefix=prefix
            )
            decoded = response.json()
            for file in decoded['files']:
                yield file['fileName']

            if decoded['nextFileName'] is None:
                break

            start_file_name = decoded['nextFileName']

    @utils.requires_auth
    @backoff_reauth
    async def delete(self, name):
        url = f'{self._auth.apiUrl}/b2api/v2/b2_hide_file'
        bucket = await self._get_bucket()
        params = {'bucketId': bucket.id, 'fileName': name}
        headers = {'authorization': self._auth.authorizationToken}
        await self._client.post(url, json=params, headers=headers)

    async def close(self):
        with suppress(AttributeError):
            del self._auth

        with suppress(AttributeError):
            del self._bucket

        await self._client.aclose()


Client = B2
