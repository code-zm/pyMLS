from enum import Enum

class HandshakeType(Enum):
    ADD = "add"
    UPDATE = "update"
    REMOVE = "remove"
    COMMIT = "commit"

