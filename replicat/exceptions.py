class ReplicatError(Exception):
    pass


class DecryptionError(ReplicatError):
    pass


class AuthRequired(ReplicatError):
    pass


class Locked(ReplicatError):
    pass
