from typing import List, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives import serialization
from jsonschema import validate, ValidationError
from .Proposals import Proposal
from .TranscriptHashManager import TranscriptHashManager
import json

DEBUG = False


class Commit:
    """
    Represents a Commit message in the MLS protocol.
    """
    _commit_schema = {
        "type": "object",
        "properties": {
            "proposals": {"type": "array", "items": {"type": "object"}},
            "commitSecret": {"type": "string", "pattern": "^[a-fA-F0-9]+$"},
            "groupContext": {"type": "string", "pattern": "^[a-fA-F0-9]+$"},
            "signature": {"type": "string", "pattern": "^[a-fA-F0-9]+$"},
        },
        "required": ["proposals", "commitSecret", "groupContext"],
        "additionalProperties": False,
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
            print(f"Serialized Commit: {serialized}")
        return serialized.encode("utf-8")

    def sign(self, privateKey: Ed25519PrivateKey, hashManager: TranscriptHashManager):
        """
        Signs the serialized Commit message and updates the transcript hash.
        """
        serialized_commit = self.serialize(include_signature=False)
        hashManager.updateHash(serialized_commit)  # Update the transcript hash
        self.signature = privateKey.sign(serialized_commit)
        if DEBUG:
            print(f"Commit Signature: {self.signature.hex()}")

    def verify(self, publicKey: bytes, hashManager: TranscriptHashManager) -> bool:
        """
        Verifies the Commit message signature and updates the transcript hash.
        """
        if not self.signature:
            raise ValueError("Commit is not signed.")

        verifier_key = Ed25519PublicKey.from_public_bytes(publicKey)
        serialized_commit = self.serialize(include_signature=False)
        hashManager.updateHash(serialized_commit)  # Update the transcript hash

        try:
            verifier_key.verify(self.signature, serialized_commit)
            return True
        except Exception as e:
            if DEBUG:
                print(f"Verification failed: {e}")
            return False

    def apply(self, ratchetTree, keySchedule, hashManager: TranscriptHashManager):
        """
        Applies the Commit message to update the group state and computes the new transcript hash.
        """
        try:
            # Apply proposals to the ratchet tree
            for proposal in self.proposals:
                ratchetTree.applyProposal(proposal)

            # Update the group state
            keySchedule.nextEpoch(
                commitSecret=self.commitSecret,
                context=self.groupContext,
                hashManager=hashManager,
            )

            # Update the transcript hash with the new group context
            hashManager.updateHash(self.groupContext)
            if DEBUG:
                print(f"Commit applied successfully. New groupContext: {self.groupContext.hex()}")

        except Exception as e:
            if DEBUG:
                print(f"Error applying Commit: {e}")
            raise

    @staticmethod
    def deserialize(data: bytes) -> "Commit":
        """
        Deserializes a Commit message from JSON.
        """
        try:
            commit_data = json.loads(data.decode("utf-8"))
            validate(instance=commit_data, schema=Commit._commit_schema)

            proposals = [Proposal.deserialize(json.dumps(p).encode('utf-8')) for p in commit_data["proposals"]]
            commit_secret = bytes.fromhex(commit_data["commitSecret"])
            group_context = bytes.fromhex(commit_data["groupContext"])

            commit = Commit(proposals, commit_secret, group_context)
            if "signature" in commit_data:
                commit.signature = bytes.fromhex(commit_data["signature"])

            return commit

        except (json.JSONDecodeError, ValidationError) as e:
            if DEBUG:
                print(f"Error deserializing Commit: {e}")
            raise
