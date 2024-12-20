from typing import Optional, List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from enum import Enum
import json


class HandshakeType(Enum):
    """
    Enumeration for handshake message types.
    """
    ADD = "add"
    UPDATE = "update"
    REMOVE = "remove"
    COMMIT = "commit"


class HandshakeMessage:
    """
    Base class for all MLS handshake messages.
    """
    def __init__(self, messageType: HandshakeType, senderId: bytes):
        self.messageType = messageType
        self.senderId = senderId

    def serialize(self) -> bytes:
        """
        Serialize the handshake message. Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement serialize method.")

    @staticmethod
    def deserialize(data: bytes) -> "HandshakeMessage":
        """
        Deserialize a handshake message from JSON format and return the appropriate subclass.
        """
        try:
            message = json.loads(data)
            proposalType = message.get("proposalType")
            if proposalType == HandshakeType.ADD.value:
                return Add.deserialize(data)
            elif proposalType == HandshakeType.UPDATE.value:
                return Update.deserialize(data)
            elif proposalType == HandshakeType.REMOVE.value:
                return Remove.deserialize(data)
            elif proposalType == HandshakeType.COMMIT.value:
                return Commit.deserialize(data)
            else:
                raise ValueError(f"Unsupported handshake message type: {proposalType}")
        except json.JSONDecodeError as e:
            raise ValueError("Invalid JSON data") from e


class Add(HandshakeMessage):
    """
    Represents an Add handshake message.
    """
    def __init__(self, senderId: bytes, publicKey: bytes):
        super().__init__(HandshakeType.ADD, senderId)
        self.publicKey = publicKey

    def serialize(self) -> bytes:
        """
        Serialize the Add message into JSON format.
        """
        data = {
            "proposalType": self.messageType.value,
            "senderId": self.senderId.hex(),
            "publicKey": self.publicKey.hex(),
        }
        return json.dumps(data).encode("utf-8")

    @staticmethod
    def deserialize(data: bytes) -> "Add":
        """
        Deserialize an Add message from JSON format.
        """
        message = json.loads(data)
        if message["proposalType"] != HandshakeType.ADD.value:
            raise ValueError("Invalid Add message")
        return Add(
            senderId=bytes.fromhex(message["senderId"]),
            publicKey=bytes.fromhex(message["publicKey"]),
        )


class Update(HandshakeMessage):
    """
    Represents an Update handshake message.
    """
    def __init__(self, senderId: bytes, newPublicKey: bytes):
        super().__init__(HandshakeType.UPDATE, senderId)
        self.newPublicKey = newPublicKey

    def serialize(self) -> bytes:
        """
        Serialize the Update message into JSON format.
        """
        data = {
            "proposalType": self.messageType.value,
            "senderId": self.senderId.hex(),
            "publicKey": self.newPublicKey.hex(),
        }
        return json.dumps(data).encode("utf-8")

    @staticmethod
    def deserialize(data: bytes) -> "Update":
        """
        Deserialize an Update message from JSON format.
        """
        message = json.loads(data)
        if message["proposalType"] != HandshakeType.UPDATE.value:
            raise ValueError("Invalid Update message")
        return Update(
            senderId=bytes.fromhex(message["senderId"]),
            newPublicKey=bytes.fromhex(message["publicKey"]),
        )


class Remove(HandshakeMessage):
    """
    Represents a Remove handshake message.
    """
    def __init__(self, senderId: bytes, memberIndex: int):
        super().__init__(HandshakeType.REMOVE, senderId)
        self.memberIndex = memberIndex

    def serialize(self) -> bytes:
        """
        Serialize the Remove message into JSON format.
        """
        data = {
            "proposalType": self.messageType.value,
            "senderId": self.senderId.hex(),
            "memberIndex": self.memberIndex,
        }
        return json.dumps(data).encode("utf-8")

    @staticmethod
    def deserialize(data: bytes) -> "Remove":
        """
        Deserialize a Remove message from JSON format.
        """
        message = json.loads(data)
        if message["proposalType"] != HandshakeType.REMOVE.value:
            raise ValueError("Invalid Remove message")
        return Remove(
            senderId=bytes.fromhex(message["senderId"]),
            memberIndex=message["memberIndex"],
        )


class Commit(HandshakeMessage):
    """
    Represents a Commit handshake message.
    """
    def __init__(self, senderId: bytes, proposals: List[HandshakeMessage], commitSecret: bytes, groupContext: bytes):
        super().__init__(HandshakeType.COMMIT, senderId)
        self.proposals = proposals
        self.commitSecret = commitSecret
        self.groupContext = groupContext
        self.signature = None

    def serialize(self) -> bytes:
        """
        Serialize the Commit message into JSON format.
        """
        serialized_proposals = [proposal.serialize().decode("utf-8") for proposal in self.proposals]
        data = {
            "proposalType": self.messageType.value,
            "senderId": self.senderId.hex(),
            "proposals": serialized_proposals,
            "commitSecret": self.commitSecret.hex(),
            "groupContext": self.groupContext.hex(),
            "signature": self.signature.hex() if self.signature else None,
        }
        return json.dumps(data).encode("utf-8")

    @staticmethod
    def deserialize(data: bytes) -> "Commit":
        """
        Deserialize a Commit message from JSON format.
        """
        message = json.loads(data)
        if message["proposalType"] != HandshakeType.COMMIT.value:
            raise ValueError("Invalid Commit message")
        proposals = [
            HandshakeMessage.deserialize(json.dumps(p).encode("utf-8"))
            for p in message["proposals"]
        ]
        return Commit(
            senderId=bytes.fromhex(message["senderId"]),
            proposals=proposals,
            commitSecret=bytes.fromhex(message["commitSecret"]),
            groupContext=bytes.fromhex(message["groupContext"]),
        )

    def sign(self, privateKey: Ed25519PrivateKey):
        """
        Sign the Commit message using the given private key.
        """
        serializedCommit = self.serialize()
        self.signature = privateKey.sign(serializedCommit)

    def verify(self, publicKey: bytes) -> bool:
        """
        Verify the signature of the Commit message using the given public key.
        """
        if self.signature is None:
            raise ValueError("Commit message is not signed.")
        verifierKey = Ed25519PublicKey.from_public_bytes(publicKey)
        serializedCommit = self.serialize()
        try:
            verifierKey.verify(self.signature, serializedCommit)
            return True
        except Exception:
            return False
