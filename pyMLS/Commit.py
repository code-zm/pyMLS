from typing import List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .HandshakeMessages import HandshakeMessage
from .TranscriptHashManager import TranscriptHashManager
from . import serialize
DEBUG = True

class Commit:
    """
    Represents a Commit message in the MLS protocol.
    """

    def __init__(self, proposals: List[HandshakeMessage] = None, 
        commitSecret: bytes = None, 
        groupContext: bytes = None,
        signature: bytes = None):
        
        if commitSecret and len(commitSecret) != 32:
            raise ValueError("Invalid commitSecret length. Expected 32 bytes.")
        if groupContext and len(groupContext) == 0:
            raise ValueError("Invalid groupContext length. Must be non-empty.")

        self.proposals = proposals
        self.commitSecret = commitSecret
        self.groupContext = groupContext
        self.signature = signature

    def serialize(self, include_signature: bool = True) -> bytes:
        """
        Serializes the Commit message for binary encoding.
        """
        stream = serialize.io_wrapper()
        stream.write(serialize.ser_list(self.proposals))
        stream.write(serialize.ser_str(self.commitSecret))
        stream.write(serialize.ser_str(self.groupContext))
        if include_signature and self.signature:
            stream.write(serialize.ser_str(self.signature))
        if DEBUG:
            print(f"Serializing Commit (binary): {stream.getvalue().hex()}")
        return stream.getvalue()

    def deserialize(self, data: bytes) -> "Commit":
        """
        Deserializes a Commit message from binary data.
        """
        stream = serialize.io_wrapper(data)
        self.proposals = serialize.deser_list(stream, HandshakeMessage)
        self.commitSecret = serialize.deser_str(stream)
        self.groupContext = serialize.deser_str(stream)
        return self

    
    def sign(self, privateKey: Ed25519PrivateKey, hashManager: TranscriptHashManager):
        """
        Signs the serialized Commit message and updates the transcript hash.
        """
        serializedCommit = self.serialize(include_signature=False)
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

        serializedCommit = self.serialize(include_signature=False)
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
