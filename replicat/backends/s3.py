from .s3c import S3Compatible


class S3(S3Compatible):
    def __init__(self, connection_string, *, key_id, access_key, region):
        super().__init__(
            connection_string,
            key_id=key_id,
            access_key=access_key,
            region=region,
            host=f's3.{region}.amazonaws.com',
        )


Client = S3Compatible
