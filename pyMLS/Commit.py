from typing import List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .HandshakeMessages import HandshakeMessage
from .TranscriptHashManager import TranscriptHashManager
from .SerializationUtils import SerializationUtils

DEBUG = True

class Commit:
    """
    Represents a Commit message in the MLS protocol.
    """

    def __init__(self, proposals: List[HandshakeMessage], commitSecret: bytes, groupContext: bytes, signature: bytes = None):
        if len(commitSecret) != 32:
            raise ValueError("Invalid commitSecret length. Expected 32 bytes.")
        if len(groupContext) == 0:
            raise ValueError("Invalid groupContext length. Must be non-empty.")

        self.proposals = proposals
        self.commitSecret = commitSecret
        self.groupContext = groupContext
        self.signature = signature

    def serializeBinary(self, include_signature: bool = True) -> bytes:
        """
        Serializes the Commit message for binary encoding.
        """
        serializedProposals = b"".join(
            [SerializationUtils.packLengthPrefixed(proposal.serializeBinary()) for proposal in self.proposals]
        )
        serializedData = (
            SerializationUtils.packLengthPrefixed(serializedProposals)
            + self.commitSecret
            + self.groupContext
        )

        if include_signature and self.signature:
            serializedData += SerializationUtils.packLengthPrefixed(self.signature)

        if DEBUG:
            print(f"Serializing Commit (binary): {serializedData.hex()}")
        return serializedData

    @staticmethod
    def deserializeBinary(data: bytes) -> "Commit":
        """
        Deserializes a Commit message from binary data.
        """
        offset = 0
        serializedProposals, offset = SerializationUtils.unpackLengthPrefixed(data, offset)

        proposals = []
        proposal_offset = 0
        while proposal_offset < len(serializedProposals):
            proposalData, proposal_offset = SerializationUtils.unpackLengthPrefixed(serializedProposals, proposal_offset)
            proposals.append(HandshakeMessage.deserializeBinary(proposalData))

        commitSecret = data[offset:offset + 32]
        offset += 32

        groupContext = data[offset:]

        commit = Commit(proposals, commitSecret, groupContext)

        if DEBUG:
            print(f"Deserialized Commit: proposals={proposals}, commitSecret={commitSecret.hex()}, groupContext={groupContext.hex()}")
        return commit
    
    def sign(self, privateKey: Ed25519PrivateKey, hashManager: TranscriptHashManager):
        """
        Signs the serialized Commit message and updates the transcript hash.
        """
        serializedCommit = self.serializeBinary(include_signature=False)
        hashManager.updateHash(serializedCommit)  # Update the transcript hash
        self.signature = privateKey.sign(serializedCommit)
        if DEBUG:
            print(f"Commit Signature: {self.signature.hex()}")

    def verify(self, publicKey: Ed25519PublicKey, hashManager: TranscriptHashManager) -> bool:
        """
        Verifies the Commit message signature and updates the transcript hash.
        """
        if not self.signature:
            raise ValueError("Commit is not signed.")

        serializedCommit = self.serializeBinary(include_signature=False)
        hashManager.updateHash(serializedCommit)

        try:
            publicKey.verify(self.signature, serializedCommit)
            if DEBUG:
                print("Commit signature verified successfully.")
            return True
        except Exception as e:
            if DEBUG:
                print(f"Commit signature verification failed: {e}")
            return False

    def apply(self, ratchetTree, keySchedule, hashManager: TranscriptHashManager):
        """
        Applies the Commit message to update the group state and computes the new transcript hash.
        """
        for proposal in self.proposals:
            ratchetTree.applyProposal(proposal)

        keySchedule.nextEpoch(
            commitSecret=self.commitSecret,
            context=self.groupContext,
            hashManager=hashManager,
        )
        hashManager.updateHash(self.groupContext)
        if DEBUG:
            print(f"Commit applied successfully. New groupContext: {self.groupContext.hex()}")
