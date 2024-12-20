from typing import Dict, Any, List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import json
from .TranscriptHashManager import TranscriptHashManager
from .KeyPackage import KeyPackage
from .HandshakeTypes import HandshakeType

DEBUG = False

class Proposal:
    """
    Base class for all MLS proposals.
    """
    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the proposal to a dictionary representation.
        """
        raise NotImplementedError("Subclasses must implement to_dict method.")

    def serialize(self) -> bytes:
        """
        Serializes the proposal to a JSON object.
        """
        try:
            data = self.to_dict()
            serialized = json.dumps(data, ensure_ascii=False)
            if DEBUG:
                print(f"Serialized Proposal: {serialized}")
            return serialized.encode("utf-8")
        except Exception as e:
            print(f"Error during Proposal serialization: {e}")
            raise

    @staticmethod
    def deserialize(data: bytes) -> "Proposal":
        """
        Deserializes a Proposal from a JSON object.
        """
        try:
            rawData = data.decode("utf-8").strip()
            if DEBUG:
                print(f"Raw Proposal Data: {rawData}")
            proposalData = json.loads(rawData)
            if DEBUG:
                print(f"Deserialized Proposal Data: {proposalData}")

            proposalType = proposalData["proposalType"]
            if proposalType == "AddProposal":
                return AddProposal.from_dict(proposalData)
            elif proposalType == "UpdateProposal":
                return UpdateProposal.from_dict(proposalData)
            elif proposalType == "RemoveProposal":
                return RemoveProposal.from_dict(proposalData)
            else:
                raise ValueError(f"Unknown Proposal Type: {proposalType}")
        except Exception as e:
            print(f"Error during Proposal deserialization: {e}")
            raise

class AddProposal:
    """
    Represents an AddProposal in the MLS protocol, containing a KeyPackage.
    """

    @property
    def publicKey(self) -> bytes:
        """
        Return the public key (init key) from the associated KeyPackage
        """
        return self.keyPackage.init_key

        
    def __init__(self, keyPackage: KeyPackage):
        """
        Initialize an AddProposal with a given KeyPackage.

        :param keyPackage: The KeyPackage associated with the AddProposal.
        """
        self.keyPackage = keyPackage

    def serialize(self) -> bytes:
        """
        Serialize the AddProposal, including the proposalType.

        :return: The serialized AddProposal as bytes.
        """
        data = {
            "proposalType": HandshakeType.ADD.value,  # Ensure proposalType is included
            "keyPackage": self.keyPackage.serialize().hex(),  # Serialize KeyPackage
        }
        return json.dumps(data).encode("utf-8")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposalType": "AddProposal",
            "keyPackage": self.keyPackage.serialize().hex(),
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "AddProposal":
        """
        Construct an AddProposal from a dictionary.

        :param data: A dictionary containing the AddProposal data.
        :return: An instance of AddProposal.
        """
        keyPackage = KeyPackage.deserialize(bytes.fromhex(data["keyPackage"]))
        return AddProposal(keyPackage)

    @staticmethod
    def deserialize(data: bytes) -> "AddProposal":
        """
        Deserialize an AddProposal from bytes.

        :param data: The serialized AddProposal as bytes.
        :return: An instance of AddProposal.
        """
        parsed = json.loads(data.decode("utf-8"))
        keyPackage = KeyPackage.deserialize(bytes.fromhex(parsed["keyPackage"]))
        return AddProposal(keyPackage)

class RemoveProposal(Proposal):
    """
    Represents a RemoveProposal in the MLS protocol.
    """
    def __init__(self, memberIndex: int):
        self.proposalType = "RemoveProposal"
        self.memberIndex = memberIndex

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposalType": "RemoveProposal",
            "memberIndex": self.memberIndex
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "RemoveProposal":
        return RemoveProposal(
            memberIndex=data["memberIndex"]
        )

class UpdateProposal(Proposal):
    """
    Represents an UpdateProposal in the MLS protocol.
    """
    def __init__(self, memberIndex: int, newPublicKey: bytes):
        self.proposalType = "UpdateProposal"
        self.memberIndex = memberIndex
        self.newPublicKey = newPublicKey

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposalType": "UpdateProposal",
            "memberIndex": self.memberIndex,
            "newPublicKey": self.newPublicKey.hex()
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "UpdateProposal":
        return UpdateProposal(
            memberIndex=data["memberIndex"],
            newPublicKey=bytes.fromhex(data["newPublicKey"]),
        )

class ProposalSigner:
    """
    Provides functionality for signing and verifying proposals.
    """
    @staticmethod
    def signProposal(proposal: Proposal, privateKey: Ed25519PrivateKey, hashManager: TranscriptHashManager) -> bytes:
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
    def verifyProposal(proposal: Proposal, signature: bytes, publicKey: bytes, hashManager: TranscriptHashManager) -> bool:
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
    def __init__(self, proposals: List[Proposal], hashManager: TranscriptHashManager):
        self.proposals = proposals
        self.hashManager = hashManager

    def serialize(self) -> bytes:
        """
        Serializes the proposal list and updates the transcript hash.
        """
        serialized = json.dumps([proposal.to_dict() for proposal in self.proposals], ensure_ascii=False).encode("utf-8")
        self.hashManager.updateHash(serialized)  # Update the transcript hash
        return serialized

    def addProposal(self, proposal: Proposal):
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
