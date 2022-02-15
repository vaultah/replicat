import hashlib
import hmac
import logging
from datetime import datetime
from urllib.parse import urlencode
from xml.etree.ElementTree import XMLPullParser

import backoff
import httpx

from .. import utils
from .base import Backend

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


def _hmac_sha256_digest(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()


def _make_signature_key(*, key, date, region, service):
    date_key = _hmac_sha256_digest(b'AWS4' + key.encode(), date.encode())
    date_region_key = _hmac_sha256_digest(date_key, region.encode())
    date_region_service_key = _hmac_sha256_digest(date_region_key, service.encode())
    signing_key = _hmac_sha256_digest(date_region_service_key, b'aws4_request')
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
            _get_data_hexdigest(canonical_request.encode()),
        ]
    )


def _check_403(e):
    return (
        isinstance(e, httpx.HTTPStatusError)
        and e.response.status_code == httpx.codes.FORBIDDEN
    )


async def _raise_for_status_hook(response):
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        e.args += (await e.response.aread(),)
        raise


backoff_on_httperror = backoff.on_exception(
    backoff.expo,
    httpx.HTTPError,
    max_tries=4,
    giveup=_check_403,
)
# No harm in precomputing this digest
_empty_payload_digest = _get_data_hexdigest(b'')


class S3Compatible(Backend, short_name='S3C'):
    client = utils.async_client(
        timeout=None, event_hooks={'response': [_raise_for_status_hook]}
    )

    def __init__(
        self, connection_string, *, key_id, access_key, region, host, scheme='https'
    ):
        self.bucket_name = connection_string
        self.key_id = key_id
        self.access_key = access_key
        self.region = region
        self.host = host
        self.scheme = scheme
        self.url = f'{scheme}://' + self.host

    async def _make_request(
        self,
        method,
        canonical_uri,
        *,
        query=None,
        payload_digest,
        headers=None,
        **kwargs,
    ):
        url = self.url + canonical_uri
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

        canonical_headers = {
            'host': self.host,
            'x-amz-content-sha256': payload_digest,
            'x-amz-date': x_amz_date,
        }
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
            date=date, region=self.region, service='s3'
        )
        string_to_sign = _make_string_to_sign(
            x_amz_date, credential_scope, canonical_request
        )
        signing_key = _make_signature_key(
            key=self.access_key,
            date=date,
            region=self.region,
            service='s3',
        )
        signature = _hmac_sha256_digest(signing_key, string_to_sign.encode()).hex()
        authorization_header = (
            f'AWS4-HMAC-SHA256 Credential={self.key_id}/{credential_scope}, '
            f'SignedHeaders={signed_headers}, Signature={signature}'
        )

        headers['x-amz-content-sha256'] = payload_digest
        headers['x-amz-date'] = x_amz_date
        headers['authorization'] = authorization_header
        return await self.client.request(method, url, headers=headers, **kwargs)

    @backoff_on_httperror
    async def exists(self, name):
        try:
            await self._make_request(
                'HEAD',
                f'/{self.bucket_name}/{name}',
                payload_digest=_empty_payload_digest,
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == httpx.codes.NOT_FOUND:
                return False
            raise
        else:
            return True

    @backoff_on_httperror
    async def _put_object(self, name, data, payload_digest):
        await self._make_request(
            'PUT',
            f'/{self.bucket_name}/{name}',
            content=data,
            payload_digest=payload_digest,
            headers={'content-length': str(len(data))},
        )

    async def upload(self, name, data):
        payload_digest = _get_data_hexdigest(data)
        await self._put_object(name, data, payload_digest)

    @backoff_on_httperror
    async def _put_object_stream(self, name, stream, length, payload_digest):
        try:
            await self._make_request(
                'PUT',
                f'/{self.bucket_name}/{name}',
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

    @backoff_on_httperror
    async def download(self, name):
        response = await self._make_request(
            'GET',
            f'/{self.bucket_name}/{name}',
            payload_digest=_empty_payload_digest,
        )
        return await response.aread()

    @backoff_on_httperror
    async def _list_objects(self, *, continuation_token=None, prefix=''):
        query = {'list-type': '2'}

        if continuation_token is not None:
            query['continuation-token'] = continuation_token

        if prefix:
            query['prefix'] = prefix

        return await self._make_request(
            'GET',
            f'/{self.bucket_name}',
            query=query,
            payload_digest=_empty_payload_digest,
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

    @backoff_on_httperror
    async def delete(self, name):
        await self._make_request(
            'DELETE',
            f'/{self.bucket_name}/{name}',
            payload_digest=_empty_payload_digest,
        )

    async def close(self):
        await self.client.aclose()


Client = S3Compatible
