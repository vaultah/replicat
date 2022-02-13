import asyncio
import functools
import logging
import sys
from urllib.parse import urlparse

import backoff
import httpx

from .. import exceptions, utils
from .s3c import S3Compatible

B2_API_BASE_URL = 'https://api.backblazeb2.com/b2api/v2'

logger = logging.getLogger(__name__)


def _check_403(e):
    return (
        isinstance(e, httpx.HTTPStatusError)
        and e.response.status_code == httpx.codes.FORBIDDEN
    )


async def _on_backoff_reauth(details):
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


async def _on_backoff_no_reauth(details):
    try:
        await _on_backoff_reauth(details)
    except exceptions.AuthRequired:
        # Simply suppress it
        pass


async def _raise_for_status_hook(response):
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        e.args += (await e.response.aread(),)
        if e.response.status_code == httpx.codes.UNAUTHORIZED:
            raise exceptions.AuthRequired
        raise


_backoff_decorator = functools.partial(
    backoff.on_exception,
    backoff.expo,
    httpx.HTTPError,
    max_tries=4,
    giveup=_check_403,
)

backoff_no_reauth = _backoff_decorator(on_backoff=[_on_backoff_no_reauth])
backoff_reauth = _backoff_decorator(on_backoff=[_on_backoff_reauth])


class B2(S3Compatible):
    client = utils.async_client(
        timeout=None, event_hooks={'response': [_raise_for_status_hook]}
    )

    def __init__(self, connection_string, *, key_id, application_key):
        # Name or id
        self._bucket_identifier = connection_string
        self.key_id, self.access_key = key_id, application_key

    @backoff_no_reauth
    async def authenticate(self):
        """This should normally be called once in the lifetime of this instance.
        We only use it to get the S3 endpoint and region"""
        logger.debug('Obtaining B2 account information')
        auth_url = f'{B2_API_BASE_URL}/b2_authorize_account'
        response = await self.client.get(auth_url, auth=(self.key_id, self.access_key))
        self._b2_auth = utils.DefaultNamespace(**response.json())

        # Set attributes for use with the S3-compatible adapter
        self.host = urlparse(self._b2_auth.s3ApiUrl).hostname
        # https://help.backblaze.com/hc/en-us/articles/360047425453
        # "The region will be the 2nd part of your S3 Endpoint"
        self.region = self.host.split('.', 2)[1]
        self.url = 'https://' + self.host

    @utils.requires_auth
    @backoff_reauth
    async def _get_bucket_info(self):
        if not hasattr(self, 'bucket_name'):
            response = await self.client.post(
                f'{self._b2_auth.apiUrl}/b2api/v2/b2_list_buckets',
                json={'accountId': self._b2_auth.accountId},
                headers={'Authorization': self._b2_auth.authorizationToken},
            )
            for bucket in response.json()['buckets']:
                bucket_id, bucket_name = bucket['bucketId'], bucket['bucketName']
                if self._bucket_identifier in {bucket_id, bucket_name}:
                    self.bucket_id, self.bucket_name = bucket_id, bucket_name
                    return

            raise exceptions.ReplicatError(
                f'Bucket {self._bucket_identifier} was not found'
            )

    @utils.requires_auth
    async def exists(self, name):
        await self._get_bucket_info()
        return await super().exists(name)

    @utils.requires_auth
    async def upload(self, name, data):
        await self._get_bucket_info()
        await super().upload(name)

    @utils.requires_auth
    async def upload_stream(self, name, data, stream, length):
        await self._get_bucket_info()
        await super().upload_stream(name, stream, length)

    @utils.requires_auth
    async def download(self, name):
        await self._get_bucket_info()
        return await super().download(name)

    @utils.requires_auth
    @backoff_reauth
    async def _list_file_names(self, *, start_file_name=None, prefix=''):
        params = {
            'bucketId': self.bucket_id,
            'maxFileCount': 10_000,
            'prefix': prefix,
        }
        if start_file_name is not None:
            params['startFileName'] = start_file_name

        headers = {'Authorization': self._b2_auth.authorizationToken}
        return await self.client.post(
            f'{self._b2_auth.apiUrl}/b2api/v2/b2_list_file_names',
            json=params,
            headers=headers,
        )

    async def list_files(self, prefix=''):
        await self._get_bucket_info()
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
    async def delete(self, name):
        await self._get_bucket_info()
        await super().delete(name)

    async def close(self):
        try:
            del self._b2_auth
        except AttributeError:
            pass

        await self.client.aclose()
        await super().close()


Client = B2
