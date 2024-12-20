from typing import Optional, List, Type, Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from enum import Enum
from .KeyPackage import KeyPackage
from .HandshakeTypes import HandshakeType
from .Proposals import AddProposal, UpdateProposal, RemoveProposal
from .Commit import Commit
import json

class HandshakeMessage:
    """
    Base class for all MLS handshake messages.
    """
    def __init__(self, messageType: HandshakeType, senderId: bytes):
        """
        Initialize a HandshakeMessage.

        :param messageType: The type of the handshake message.
        :param senderId: The identifier of the sender.
        """
        self.messageType = messageType
        self.senderId = senderId

    def serialize(self) -> bytes:
        """
        Serialize the handshake message. Must be implemented by subclasses.

        :return: The serialized handshake message as bytes.
        """
        raise NotImplementedError("Subclasses must implement the serialize method.")

    @staticmethod
    def deserialize(data: bytes) -> Union["AddProposal", "UpdateProposal", "RemoveProposal", "Commit"]:
        """
        Deserialize a handshake message from JSON format and return the appropriate subclass.

        :param data: The serialized handshake message as bytes.
        :return: An instance of the appropriate handshake message subclass.
        :raises ValueError: If the message type is not supported or the data is invalid.
        """
        try:
            # Decode the JSON data
            message = json.loads(data.decode("utf-8"))

            # Determine the type of handshake message
            proposalType = message.get("proposalType")
            if proposalType == HandshakeType.ADD.value:
                return AddProposal.deserialize(data)
            elif proposalType == HandshakeType.UPDATE.value:
                return UpdateProposal.deserialize(data)
            elif proposalType == HandshakeType.REMOVE.value:
                return RemoveProposal.deserialize(data)
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
    def __init__(self, senderId: bytes, keyPackage: KeyPackage):
        super().__init__(HandshakeType.ADD, senderId)
        self.keyPackage = keyPackage

    def serialize(self) -> bytes:
        """
        Serialize the Add handshake message.
        """
        data = {
            "proposalType": self.messageType.value,
            "senderId": self.senderId.hex(),
            "keyPackage": self.keyPackage.serialize().hex(),
        }
        return json.dumps(data).encode("utf-8")

    @staticmethod
    def deserialize(data: bytes) -> "Add":
        """
        Deserialize an Add handshake message from JSON format.
        """
        try:
            message = json.loads(data)
            if message.get("proposalType") != HandshakeType.ADD.value:
                raise ValueError("Invalid proposal type for Add message.")
            senderId = bytes.fromhex(message["senderId"])
            keyPackage = KeyPackage.deserialize(bytes.fromhex(message["keyPackage"]))
            return Add(senderId=senderId, keyPackage=keyPackage)
        except KeyError as e:
            raise ValueError(f"Missing required field in Add message: {e}")
        except json.JSONDecodeError as e:
            raise ValueError("Invalid JSON data for Add message") from e

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
