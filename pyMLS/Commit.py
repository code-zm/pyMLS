from typing import List, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives import serialization
from jsonschema import validate, ValidationError
from pyMLS.Proposals import Proposal, AddProposal, RemoveProposal, UpdateProposal
from pyMLS.TranscriptHashManager import TranscriptHashManager  # Centralized manager
import json

DEBUG = False


class Commit:
    """
    Represents a Commit message in the MLS protocol.
    """

    # JSON Schema for Commit validation
    _commit_schema = {
        "type": "object",
        "properties": {
            "proposals": {
                "type": "array",
                "items": {"type": "object"}  # Serialized proposals as JSON objects
            },
            "commitSecret": {
                "type": "string",
                "pattern": "^[a-fA-F0-9]+$"  # Hexadecimal format
            },
            "groupContext": {
                "type": "string",
                "pattern": "^[a-fA-F0-9]+$"  # Hexadecimal format
            },
            "signature": {
                "type": "string",
                "pattern": "^[a-fA-F0-9]+$"  # Hexadecimal format
            }
        },
        "required": ["proposals", "commitSecret", "groupContext", "signature"],
        "additionalProperties": False
    }

    def __init__(self, proposals: List[Proposal], commitSecret: bytes, groupContext: bytes):
        self.proposals = proposals
        self.commitSecret = commitSecret
        self.groupContext = groupContext
        self.signature = None

    def serialize(self, include_signature: bool = True) -> bytes:
        """
        Serializes the Commit message for transmission or signing.
        """
        serialized_proposals = [proposal.to_dict() for proposal in self.proposals]
        data = {
            "proposals": serialized_proposals,
            "commitSecret": self.commitSecret.hex(),
            "groupContext": self.groupContext.hex(),
        }
        if include_signature and self.signature:
            data["signature"] = self.signature.hex()

        serialized = json.dumps(data, ensure_ascii=False)
        if DEBUG:
            print(f"Serialized Commit(debug): {serialized}")
        return serialized.encode("utf-8")

    def sign(self, privateKey: Ed25519PrivateKey):
        """
        Signs the serialized Commit message.
        """
        serializedCommit = self.serialize(include_signature=False)
        self.signature = privateKey.sign(serializedCommit)
        if DEBUG:
            print(f"Commit Signature: {self.signature.hex()}")

    def verify(self, publicKey: bytes) -> bool:
        """
        Verifies the Commit message signature.
        """
        if not self.signature:
            raise ValueError("Commit is not signed.")

        verifierKey = Ed25519PublicKey.from_public_bytes(publicKey)
        serializedCommit = self.serialize(include_signature=False)

        try:
            verifierKey.verify(self.signature, serializedCommit)
            return True
        except Exception as e:
            if DEBUG:
                print(f"Verification failed: {e}")
            return False

    def apply(self, ratchetTree, keySchedule, hashManager: TranscriptHashManager):
        """
        Applies the Commit message to update the group state and computes the new transcript hash.
        :param ratchetTree: The group's ratchet tree.
        :param keySchedule: The group's key schedule.
        :param hashManager: Centralized transcript hash manager.
        """
        # Validate proposal types
        for proposal in self.proposals:
            if not isinstance(proposal, (AddProposal, RemoveProposal, UpdateProposal)):
                raise TypeError("Invalid proposal type in Commit.")

        # Apply each proposal to the RatchetTree
        for proposal in self.proposals:
            if isinstance(proposal, AddProposal):
                ratchetTree.addMember(proposal.publicKey)
            elif isinstance(proposal, RemoveProposal):
                ratchetTree.removeMember(proposal.memberIndex)
            elif isinstance(proposal, UpdateProposal):
                ratchetTree.updateMemberKey(proposal.memberIndex, proposal.newPublicKey)

        # Generate new epoch secrets using the commitSecret and updated group context
        keySchedule.updateForCommit(self.commitSecret, self.groupContext, hashManager)

        # Update the transcript hash using the serialized Commit
        serializedCommit = self.serialize(include_signature=False)
        hashManager.updateHash(serializedCommit)

    @staticmethod
    def deserializeCommit(data: bytes, signerPublicKey: bytes) -> Optional["Commit"]:
        """
        Deserializes a Commit message and verifies its signature.
        """
        try:
            rawData = data.decode("utf-8").strip()
            if DEBUG:
                print(f"Raw Commit Data(debug): {rawData}")

            # Ensure proper JSON format
            while rawData and not rawData.endswith("}"):
                rawData = rawData[:-1]

            # Parse JSON
            commitData = json.loads(rawData)
            if DEBUG:
                print(f"Parsed Commit Data: {commitData}")

            # Validate JSON against schema
            validate(instance=commitData, schema=Commit._commit_schema)

            # Deserialize proposals
            proposals = [
                Proposal.deserialize(json.dumps(proposal).encode("utf-8"))
                for proposal in commitData["proposals"]
            ]
            commitSecret = bytes.fromhex(commitData["commitSecret"])
            groupContext = bytes.fromhex(commitData["groupContext"])
            signature = bytes.fromhex(commitData.get("signature", ""))

            commit = Commit(proposals, commitSecret, groupContext)
            commit.signature = signature

            # Verify signature
            if not commit.verify(signerPublicKey):
                raise ValueError("Commit signature verification failed.")
            
            return commit
        except json.JSONDecodeError as e:
            if DEBUG:
                print(f"JSON Decode Error: {e}")
            return None
        except ValidationError as ve:
            if DEBUG:
                print(f"JSON Schema validation error: {ve.message}")
            return None
        except ValueError as ve:
            if DEBUG:
                print(f"Validation error: {ve}")
            return None
        except Exception as e:
            if DEBUG:
                print(f"Unexpected error during Commit deserialization: {e}")
            return None
