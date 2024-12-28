import unittest
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyMLS.Commit import Commit
from pyMLS.Proposals import AddProposal, UpdateProposal, RemoveProposal
from pyMLS.KeyPackage import KeyPackage
from pyMLS.TranscriptHashManager import TranscriptHashManager
from pyMLS.KeySchedule import KeySchedule

class MockRatchetTree:
    def __init__(self):
        self.members = {}
    
    def addMember(self, publicKey):
        self.members[len(self.members)] = publicKey
    
    def removeMember(self, memberIndex):
        if memberIndex in self.members:
            del self.members[memberIndex]
        else:
            raise ValueError(f"Member index {memberIndex} does not exist.")
    
    def updateMemberKey(self, memberIndex, newPublicKey):
        if memberIndex in self.members:
            self.members[memberIndex] = newPublicKey
        else:
            raise ValueError(f"Member index {memberIndex} does not exist.")

    def applyProposal(self, proposal):
        """
        Apply a proposal to the ratchet tree.
        """
        if isinstance(proposal, AddProposal):
            self.addMember(proposal.keyPackage.initKey)
        elif isinstance(proposal, RemoveProposal):
            self.removeMember(proposal.memberIndex)
        elif isinstance(proposal, UpdateProposal):
            self.updateMemberKey(proposal.memberIndex, proposal.newPublicKey)
        else:
            raise ValueError(f"Unknown proposal type: {type(proposal).__name__}")

    def validateProposal(self, proposal):
        """
        Simulates validation of a proposal in the ratchet tree.
        """
        if isinstance(proposal, AddProposal):
            # Ensure no duplicate keys
            if proposal.keyPackage.initKey in self.members.values():
                return False
        elif isinstance(proposal, RemoveProposal):
            # Ensure member exists
            if proposal.memberIndex not in self.members:
                return False
        elif isinstance(proposal, UpdateProposal):
            # Ensure member exists
            if proposal.memberIndex not in self.members:
                return False
        return True

class TestCommit(unittest.TestCase):
    def setUp(self):
        self.privateKey = Ed25519PrivateKey.generate()
        self.publicKey = self.privateKey.public_key()
        self.publicKeyBytes = self.publicKey.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        self.commitSecret = os.urandom(32)
        self.groupContext = os.urandom(32)
        self.transcriptHashManager = TranscriptHashManager()

        self.mockKeyPackage = KeyPackage(
            version=1,
            cipherSuite=0x0001,
            initKey=self.publicKeyBytes,
            leafNode={
                "capabilities": {"versions": [1], "cipherSuites": [0x0001]},
                "encryptionKey": os.urandom(32).hex(),
                "signatureKey": self.publicKeyBytes.hex(),
                "leafNodeSource": "",
            },
            extensions=[],
            privateKey=self.privateKey,
        )

        self.proposals = [
            AddProposal(keyPackage=self.mockKeyPackage),
            UpdateProposal(memberIndex=1, newPublicKey=os.urandom(32)),
            RemoveProposal(memberIndex=2),
        ]

        self.commit = Commit(
            proposals=self.proposals,
            commitSecret=self.commitSecret,
            groupContext=self.groupContext,
        )

        self.ratchetTree = MockRatchetTree()

        # Add mock members for UpdateProposal and RemoveProposal
        self.ratchetTree.addMember(os.urandom(32))  # Member at index 0
        self.ratchetTree.addMember(os.urandom(32))  # Member at index 1
        self.ratchetTree.addMember(os.urandom(32))  # Member at index 2

        # Initialize KeySchedule
        self.keySchedule = KeySchedule(initialSecret=os.urandom(32))

    def testCommitSerialization(self):
        serialized = self.commit.serialize()
        self.assertIsInstance(serialized, bytes)

    def testCommitDeserialization(self):
        serialized = self.commit.serialize()
        deserialized = Commit.deserialize(serialized)
        self.assertIsNotNone(deserialized, "Commit deserialization returned None.")
        if deserialized is not None:
            self.assertEqual(deserialized.commitSecret, self.commit.commitSecret)
            self.assertEqual(deserialized.groupContext, self.commit.groupContext)

    def testCommitSigning(self):
        self.commit.sign(self.privateKey, self.transcriptHashManager)
        self.assertIsNotNone(self.commit.signature)

    def testCommitSignatureVerification(self):
        self.commit.sign(self.privateKey, self.transcriptHashManager)
        is_valid = self.commit.verify(self.publicKeyBytes, self.transcriptHashManager)
        self.assertTrue(is_valid)

    def testCommitSignatureVerificationFailure(self):
        self.commit.sign(self.privateKey, self.transcriptHashManager)
        self.commit.groupContext = os.urandom(32)  # Tamper the Commit
        is_valid = self.commit.verify(self.publicKeyBytes, self.transcriptHashManager)
        self.assertFalse(is_valid)

    def testCommitApplication(self):
        """Validate the application of Commit to update group state."""
        try:
            self.commit.apply(
                ratchetTree=self.ratchetTree,
                keySchedule=self.keySchedule,
                hashManager=self.transcriptHashManager
            )
            self.assertTrue(True)  # If no exception, pass the test
        except AttributeError as e:
            self.fail(f"Commit application raised unexpected AttributeError: {e}")

if __name__ == "__main__":
    unittest.main()
