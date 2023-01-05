class ReplicatError(Exception):
    pass


class InvalidConfig(ReplicatError):
    pass


class DecryptionError(ReplicatError):
    pass


class AuthRequired(ReplicatError):
    pass
