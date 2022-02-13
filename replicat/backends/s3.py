from .s3c import Client as S3CompatibleClient


class S3(S3CompatibleClient):
    def __init__(self, connection_string, *, key_id, access_key, region):
        super().__init__(
            connection_string,
            key_id=key_id,
            access_key=access_key,
            region=region,
            host=f's3.{region}.amazonaws.com',
        )


Client = S3
