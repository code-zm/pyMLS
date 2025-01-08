import struct
from typing import List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .TranscriptHashManager import TranscriptHashManager
from .KeyPackage import KeyPackage
from .HandshakeMessages import HandshakeMessage, HandshakeType
from . import serialize

DEBUG = True

class AddProposal(HandshakeMessage):
    """
    Represents an AddProposal in the MLS protocol, containing a KeyPackage.
    """
    def __init__(self, keyPackage: KeyPackage = None):
        if keyPackage:
            super().__init__(HandshakeType.ADD, keyPackage.serialize())
        self.keyPackage = keyPackage

    def serialize(self) -> bytes:
        """
        Serialize the AddProposal into binary format.
        """
        serialized = super().serialize()
        if DEBUG:
            print(f"Serializing AddProposal: keyPackage={self.keyPackage}")
            print(f"[SERIALIZEDDATA]{serialized}")
        return serialized

    def deserialize(self, data: bytes) -> "AddProposal":
        """
        Deserialize an AddProposal from binary format.
        """
        message = HandshakeMessage()
        message.deserialize(data)
        self.keyPackage = KeyPackage()
        self.keyPackage.deserialize(message.payload)
        if DEBUG:
            print(f"Deserializing AddProposal: keyPackage={self.keyPackage}")
        return self


class UpdateProposal(HandshakeMessage):
    """
    Represents an UpdateProposal in the MLS protocol.
    """
    def __init__(self, keyPackage: KeyPackage = None):
        if keyPackage:
            super().__init__(HandshakeType.UPDATE, keyPackage.serialize())
        self.keyPackage = keyPackage

    def serialize(self) -> bytes:
        """
        Serialize the UpdateProposal into binary format.
        """
        serialized = super().serialize()
        if DEBUG:
            print(f"Serializing UpdateProposal: keyPackage={self.keyPackage}")
            print(f"[SERIALIZEDDATA]{serialized}")
        return serialized

    def deserialize(self, data: bytes) -> "UpdateProposal":
        """
        Deserialize an UpdateProposal from binary format.
        """
        message = HandshakeMessage()
        message.deserialize(data)
        self.keyPackage = KeyPackage()
        self.keyPackage.deserialize(message.payload)
        if DEBUG:
            print(f"Deserializing UpdateProposal: keyPackage={self.keyPackage}")
        return self


class RemoveProposal(HandshakeMessage):
    """
    Represents a RemoveProposal in the MLS protocol.
    """
    def __init__(self, memberIndex: int = None):
        if memberIndex:
            payload = serialize.ser_int(memberIndex)
            super().__init__(HandshakeType.REMOVE, payload)
        self.memberIndex = memberIndex

    def serialize(self) -> bytes:
        """
        Serialize the RemoveProposal into binary format.
        """
        serialized = super().serialize()
        if DEBUG:
            print(f"Serializing RemoveProposal: memberIndex={self.memberIndex}")
            print(f"[SERIALIZEDDATA]{serialized}")
        return serialized

    def deserialize(self, data: bytes) -> "RemoveProposal":
        """
        Deserialize a RemoveProposal from binary format.
        """
        message = HandshakeMessage()
        message.deserialize(data)
        self.memberIndex = serialize.deser_int(serialize.io_wrapper(message.payload))
        if DEBUG:
            print(f"Deserializing RemoveProposal: memberIndex={self.memberIndex}")
        return self


class ProposalSigner:
    """
    Provides functionality for signing and verifying proposals.
    """
    @staticmethod
    def signProposal(proposal: HandshakeMessage, privateKey: Ed25519PrivateKey, hashManager: TranscriptHashManager) -> bytes:
        """
        Signs a serialized proposal and updates the transcript hash.
        """
        serializedProposal = proposal.serialize()
        hashManager.updateHash(serializedProposal)  # Update the transcript hash
        signature = privateKey.sign(serializedProposal)
        if DEBUG:
            print(f"Proposal Signature: {signature.hex()}")
        return signature

    @staticmethod
    def verifyProposal(proposal: HandshakeMessage, signature: bytes, publicKey: bytes, hashManager: TranscriptHashManager) -> bool:
        """
        Verifies a signed proposal and updates the transcript hash.
        """
        try:
            serializedProposal = proposal.serialize()
            hashManager.updateHash(serializedProposal)  # Update the transcript hash
            verifierKey = Ed25519PublicKey.from_public_bytes(publicKey)
            verifierKey.verify(signature, serializedProposal)
            return True
        except Exception as e:
            if DEBUG:
                print(f"Error during proposal verification: {e}")
            return False


class ProposalList:
    """
    Represents a list of proposals and manages their integration with the TranscriptHashManager.
    """
    def __init__(self, proposals: List[HandshakeMessage], hashManager: TranscriptHashManager):
        self.proposals = proposals
        self.hashManager = hashManager

    def serialize(self) -> bytes:
        """
        Serializes the proposal list and updates the transcript hash.
        """
        serialized = serialize.ser_list(self.proposals)
        self.hashManager.updateHash(serialized)  # Update the transcript hash
        return serialized

    def addProposal(self, proposal: HandshakeMessage):
        """
        Adds a proposal to the list and updates the transcript hash.
        """
        self.proposals.append(proposal)
        self.hashManager.updateHash(self.serialize())  # Update the transcript hash

    def signList(self, privateKey: Ed25519PrivateKey) -> bytes:
        """
        Signs the serialized list of proposals.
        """
        serialized = self.serialize()
        return privateKey.sign(serialized)

    def verifyList(self, signature: bytes, publicKey: Ed25519PublicKey) -> bool:
        """
        Verifies the signed list of proposals.
        """
        serialized = self.serialize()
        try:
            publicKey.verify(signature, serialized)
            return True
        except Exception as e:
            if DEBUG:
                print(f"Proposal list verification failed: {e}")
            return False
