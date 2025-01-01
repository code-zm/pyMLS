import struct
from typing import List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .TranscriptHashManager import TranscriptHashManager
from .KeyPackage import KeyPackage
from .HandshakeMessages import HandshakeMessage, HandshakeType

DEBUG = True

class AddProposal(HandshakeMessage):
    """
    Represents an AddProposal in the MLS protocol, containing a KeyPackage.
    """
    def __init__(self, keyPackage: KeyPackage):
        super().__init__(HandshakeType.ADD, keyPackage.serialize())
        self.keyPackage = keyPackage

    def serializeBinary(self) -> bytes:
        """
        Serialize the AddProposal into binary format.
        """
        serialized = super().serializeBinary()
        if DEBUG:
            print(f"Serializing AddProposal: keyPackage={self.keyPackage}")
            print(f"[SERIALIZEDDATA]{serialized}")
        return serialized

    @staticmethod
    def deserializeBinary(data: bytes) -> "AddProposal":
        """
        Deserialize an AddProposal from binary format.
        """
        message = HandshakeMessage.deserializeBinary(data)
        keyPackage = KeyPackage.deserialize(message.payload)
        if DEBUG:
            print(f"Deserializing AddProposal: keyPackage={keyPackage}")
        return AddProposal(keyPackage)


class UpdateProposal(HandshakeMessage):
    """
    Represents an UpdateProposal in the MLS protocol.
    """
    def __init__(self, keyPackage: KeyPackage):
        super().__init__(HandshakeType.UPDATE, keyPackage.serialize())
        self.keyPackage = keyPackage

    def serializeBinary(self) -> bytes:
        """
        Serialize the UpdateProposal into binary format.
        """
        serialized = super().serializeBinary()
        if DEBUG:
            print(f"Serializing UpdateProposal: keyPackage={self.keyPackage}")
            print(f"[SERIALIZEDDATA]{serialized}")
        return serialized

    @staticmethod
    def deserializeBinary(data: bytes) -> "UpdateProposal":
        """
        Deserialize an UpdateProposal from binary format.
        """
        message = HandshakeMessage.deserializeBinary(data)
        keyPackage = KeyPackage.deserialize(message.payload)
        if DEBUG:
            print(f"Deserializing UpdateProposal: keyPackage={keyPackage}")
        return UpdateProposal(keyPackage)


class RemoveProposal(HandshakeMessage):
    """
    Represents a RemoveProposal in the MLS protocol.
    """
    def __init__(self, memberIndex: int):
        payload = struct.pack("!I", memberIndex)
        super().__init__(HandshakeType.REMOVE, payload)
        self.memberIndex = memberIndex

    def serializeBinary(self) -> bytes:
        """
        Serialize the RemoveProposal into binary format.
        """
        serialized = super().serializeBinary()
        if DEBUG:
            print(f"Serializing RemoveProposal: memberIndex={self.memberIndex}")
            print(f"[SERIALIZEDDATA]{serialized}")
        return serialized

    @staticmethod
    def deserializeBinary(data: bytes) -> "RemoveProposal":
        """
        Deserialize a RemoveProposal from binary format.
        """
        message = HandshakeMessage.deserializeBinary(data)
        memberIndex = struct.unpack("!I", message.payload[:4])[0]
        if DEBUG:
            print(f"Deserializing RemoveProposal: memberIndex={memberIndex}")
        return RemoveProposal(memberIndex)


class ProposalSigner:
    """
    Provides functionality for signing and verifying proposals.
    """
    @staticmethod
    def signProposal(proposal: HandshakeMessage, privateKey: Ed25519PrivateKey, hashManager: TranscriptHashManager) -> bytes:
        """
        Signs a serialized proposal and updates the transcript hash.
        """
        serializedProposal = proposal.serializeBinary()
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
            serializedProposal = proposal.serializeBinary()
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

    def serializeBinary(self) -> bytes:
        """
        Serializes the proposal list and updates the transcript hash.
        """
        serialized = b"".join([p.serializeBinary() for p in self.proposals])
        self.hashManager.updateHash(serialized)  # Update the transcript hash
        return serialized

    def addProposal(self, proposal: HandshakeMessage):
        """
        Adds a proposal to the list and updates the transcript hash.
        """
        self.proposals.append(proposal)
        self.hashManager.updateHash(self.serializeBinary())  # Update the transcript hash

    def signList(self, privateKey: Ed25519PrivateKey) -> bytes:
        """
        Signs the serialized list of proposals.
        """
        serialized = self.serializeBinary()
        return privateKey.sign(serialized)

    def verifyList(self, signature: bytes, publicKey: Ed25519PublicKey) -> bool:
        """
        Verifies the signed list of proposals.
        """
        serialized = self.serializeBinary()
        try:
            publicKey.verify(signature, serialized)
            return True
        except Exception as e:
            if DEBUG:
                print(f"Proposal list verification failed: {e}")
            return False
