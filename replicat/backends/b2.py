import asyncio
import functools
import hashlib
import hmac
import logging
import sys
from datetime import datetime
from urllib.parse import urlencode, urlparse
from xml.etree.ElementTree import XMLPullParser

import backoff
import httpx

from .. import exceptions, utils
from .base import Backend

EMPTY_PAYLOAD_DIGEST = hashlib.sha256().hexdigest()
B2_API_BASE_URL = 'https://api.backblazeb2.com/b2api/v2'

logger = logging.getLogger(__name__)


def _get_data_hexdigest(data):
    return hashlib.sha256(data).hexdigest()


def _get_stream_hexdigest(stream):
    hasher = hashlib.sha256()
    chunk_size = hasher.block_size * 10_000
    for chunk in iter(lambda: stream.read(chunk_size), b''):
        hasher.update(chunk)

    stream.seek(0)
    return hasher.hexdigest()


def _hmac_sha256(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()


def _make_signature_key(*, key, date, region, service):
    date_key = _hmac_sha256(b'AWS4' + key.encode(), date.encode())
    date_region_key = _hmac_sha256(date_key, region.encode())
    date_region_service_key = _hmac_sha256(date_region_key, service.encode())
    signing_key = _hmac_sha256(date_region_service_key, b'aws4_request')
    return signing_key


def _make_canonical_headers(headers):
    result = '\n'.join(f'{name}:{value}' for name, value in headers.items())
    result += '\n'
    return result


def _make_credential_scope(*, date, region, service):
    return '/'.join([date, region, service, 'aws4_request'])


def _make_canonical_request(
    *,
    method,
    canonical_uri,
    canonical_query,
    canonical_headers,
    signed_headers,
    payload_digest,
):
    return '\n'.join(
        [
            method,
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_digest,
        ]
    )


def _make_string_to_sign(amzdate, credential_scope, canonical_request):
    return '\n'.join(
        [
            'AWS4-HMAC-SHA256',
            amzdate,
            credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )


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
    max_tries=64,
    giveup=_check_403,
)

backoff_no_reauth = _backoff_decorator(on_backoff=[_on_backoff_no_reauth])
backoff_reauth = _backoff_decorator(on_backoff=[_on_backoff_reauth])


class B2(Backend):
    client = utils.async_client(
        timeout=None, event_hooks={'response': [_raise_for_status_hook]}
    )

    def __init__(self, connection_string, *, key_id, application_key):
        # Name or id
        self.bucket_identifier = connection_string
        self.key_id, self.application_key = key_id, application_key

    @backoff_no_reauth
    async def authenticate(self):
        """This should normally be called once in the lifetime of this instance.
        We only use it to get the S3 endpoint and region"""
        logger.debug('Obtaining B2 account information')
        auth_url = f'{B2_API_BASE_URL}/b2_authorize_account'
        response = await self.client.get(
            auth_url, auth=(self.key_id, self.application_key)
        )
        self._auth = utils.DefaultNamespace(**response.json())
        self._auth.s3Hostname = urlparse(self._auth.s3ApiUrl).hostname
        # https://help.backblaze.com/hc/en-us/articles/360047425453
        # "The region will be the 2nd part of your S3 Endpoint"
        self._auth.s3Region = self._auth.s3Hostname.split('.', 2)[1]

    @utils.requires_auth
    @backoff_reauth
    async def _list_buckets(self):
        url = f'{self._auth.apiUrl}/b2api/v2/b2_list_buckets'
        headers = {'Authorization': self._auth.authorizationToken}
        params = {'accountId': self._auth.accountId}
        response = await self.client.post(url, headers=headers, json=params)
        return response.json()['buckets']

    async def _get_bucket_name(self):
        # Select the bucket by its id or name. After we find it, cache the name
        # and use it for all calls from now on
        try:
            return self._bucket_name
        except AttributeError:
            for bucket in await self._list_buckets():
                if self.bucket_identifier in {bucket['bucketId'], bucket['bucketName']}:
                    self._bucket_name = bucket['bucketName']
                    return self._bucket_name

            raise exceptions.ReplicatError(
                f'Bucket {self.bucket_identifier} was not found'
            )

    async def _make_s3_request(
        self,
        method,
        canonical_uri,
        *,
        query=None,
        payload_digest,
        headers=None,
        **kwargs,
    ):
        url = self._auth.s3ApiUrl + canonical_uri
        if query:
            query_string = urlencode(sorted(query.items()))
            url += f'?{query_string}'
        else:
            query_string = ''

        if headers is None:
            headers = {}

        now = datetime.utcnow()
        x_amz_date = f'{now:%Y%m%dT%H%M%S}Z'
        date = f'{now:%Y%m%d}'

        canonical_headers = {'host': self._auth.s3Hostname, 'x-amz-date': x_amz_date}
        signed_headers = ";".join(canonical_headers)
        canonical_request = _make_canonical_request(
            method=method,
            canonical_uri=canonical_uri,
            canonical_query=query_string,
            canonical_headers=_make_canonical_headers(canonical_headers),
            signed_headers=signed_headers,
            payload_digest=payload_digest,
        )
        credential_scope = _make_credential_scope(
            date=date, region=self._auth.s3Region, service='s3'
        )
        string_to_sign = _make_string_to_sign(
            x_amz_date, credential_scope, canonical_request
        )
        signing_key = _make_signature_key(
            key=self.application_key,
            date=date,
            region=self._auth.s3Region,
            service='s3',
        )
        signature = _hmac_sha256(signing_key, string_to_sign.encode()).hex()
        authorization_header = (
            f'AWS4-HMAC-SHA256 Credential={self.key_id}/{credential_scope}, '
            f'SignedHeaders={signed_headers}, Signature={signature}'
        )

        headers['x-amz-date'] = x_amz_date
        headers['authorization'] = authorization_header
        return await self.client.request(method, url, headers=headers, **kwargs)

    @utils.requires_auth
    @backoff_reauth
    async def exists(self, name):
        bucket_name = await self._get_bucket_name()
        try:
            await self._make_s3_request(
                'HEAD',
                f'/{bucket_name}/{name}',
                payload_digest=EMPTY_PAYLOAD_DIGEST,
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == httpx.codes.NOT_FOUND:
                return False
            raise
        else:
            return True

    @utils.requires_auth
    @backoff_reauth
    async def _put_object(self, name, data, payload_digest):
        bucket_name = await self._get_bucket_name()
        await self._make_s3_request(
            'PUT',
            f'/{bucket_name}/{name}',
            content=data,
            payload_digest=payload_digest,
            headers={'content-length': str(len(data))},
        )

    async def upload(self, name, data):
        payload_digest = _get_data_hexdigest(data)
        await self._put_object(name, data, payload_digest)

    @utils.requires_auth
    @backoff_reauth
    async def _put_object_stream(self, name, stream, length, payload_digest):
        bucket_name = await self._get_bucket_name()
        try:
            await self._make_s3_request(
                'PUT',
                f'/{bucket_name}/{name}',
                content=utils.aiter_chunks(stream),
                payload_digest=payload_digest,
                headers={'content-length': str(length)},
            )
        except BaseException:
            stream.seek(0)
            raise

    async def upload_stream(self, name, stream, length):
        payload_digest = _get_stream_hexdigest(stream)
        await self._put_object_stream(name, stream, length, payload_digest)

    @utils.requires_auth
    @backoff_reauth
    async def download(self, name):
        bucket_name = await self._get_bucket_name()
        response = await self._make_s3_request(
            'GET',
            f'/{bucket_name}/{name}',
            payload_digest=EMPTY_PAYLOAD_DIGEST,
        )
        return await response.aread()

    @utils.requires_auth
    @backoff_reauth
    async def _list_objects(self, *, continuation_token=None, prefix=''):
        bucket_name = await self._get_bucket_name()
        query = {'list-type': '2'}

        if continuation_token is not None:
            query['continuation-token'] = continuation_token

        if prefix:
            query['prefix'] = prefix

        return await self._make_s3_request(
            'GET',
            f'/{bucket_name}',
            query=query,
            payload_digest=EMPTY_PAYLOAD_DIGEST,
        )

    async def list_files(self, prefix=''):
        is_truncated = True
        continuation_token = None

        while is_truncated:
            response = await self._list_objects(
                continuation_token=continuation_token, prefix=prefix
            )
            parser = XMLPullParser()
            async for data in response.aiter_bytes(128_000):
                parser.feed(data)

            for _, element in parser.read_events():
                tag = element.tag.rpartition('}')[2]
                if tag == 'IsTruncated' and element.text == 'false':
                    is_truncated = False
                elif tag == 'NextContinuationToken':
                    continuation_token = element.text
                elif tag == 'Key':
                    yield element.text

    @utils.requires_auth
    @backoff_reauth
    async def delete(self, name):
        bucket_name = await self._get_bucket_name()
        await self._make_s3_request(
            'DELETE',
            f'/{bucket_name}/{name}',
            payload_digest=EMPTY_PAYLOAD_DIGEST,
        )

    async def close(self):
        for attr in ('_auth', '_bucket_name'):
            try:
                delattr(self, attr)
            except AttributeError:
                pass

        await self.client.aclose()


Client = B2
