import unittest
from unittest.mock import Mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from pyMLS.Commit import Commit
from pyMLS.HandshakeMessages import HandshakeMessage, HandshakeType
from pyMLS.KeyPackage import KeyPackage

class MockTranscriptHashManager:
    def updateHash(self, data: bytes):
        pass  # Mock method

class TestCommit(unittest.TestCase):
    def setUp(self):
        keyPackage = KeyPackage(
            version=1,
            cipherSuite=1,
            initKey=b'\x00' * 32,
            leafNode={"leafNodeSource": "test_leaf_node", "signatureKey": b'\x00' * 32},
            credential="test_credential".encode("utf-8"),
            extensions=[b"test_extension_1", b"test_extension_2"],
        )

        self.proposals = [
            HandshakeMessage(HandshakeType.ADD, keyPackage.serialize()),
            HandshakeMessage(HandshakeType.UPDATE, keyPackage.serialize()),
            HandshakeMessage(HandshakeType.REMOVE, b'\x00\x00\x00\x01'),  # Example payload
        ]
        self.commitSecret = b"\x00" * 32
        self.groupContext = b"group_context_data"
        self.commit = Commit(
            proposals=self.proposals,
            commitSecret=self.commitSecret,
            groupContext=self.groupContext
        )
        self.privateKey = Ed25519PrivateKey.generate()
        self.publicKey = self.privateKey.public_key()
        self.transcriptHashManager = MockTranscriptHashManager()

    def testCommitSerialization(self):
        serialized = self.commit.serialize()
        self.assertTrue(serialized, "Commit serialization should produce a non-empty result.")

    def testCommitDeserialization(self):
        serialized = self.commit.serialize()
        deserialized = Commit()
        deserialized.deserialize(serialized)
        self.assertEqual(len(deserialized.proposals), len(self.proposals))
        self.assertEqual(deserialized.commitSecret, self.commitSecret)
        self.assertEqual(deserialized.groupContext, self.groupContext)

    def testCommitSigning(self):
        self.commit.sign(self.privateKey, self.transcriptHashManager)
        self.assertIsNotNone(self.commit.signature)

    def testCommitSignatureVerification(self):
        self.commit.sign(self.privateKey, self.transcriptHashManager)

        # Ensure signature exists
        self.assertIsNotNone(self.commit.signature, "Commit signature should not be None.")

        # Verify signature
        is_valid = self.commit.verify(self.publicKey, self.transcriptHashManager)
        self.assertTrue(is_valid, "Signature verification should pass for a valid Commit.")

    def testCommitApplication(self):
        ratchetTree = Mock()
        ratchetTree.applyProposal = Mock()
        keySchedule = Mock()
        keySchedule.nextEpoch = Mock()

        try:
            self.commit.apply(ratchetTree, keySchedule, self.transcriptHashManager)
        except Exception as e:
            self.fail(f"Commit application raised unexpected exception: {e}")

if __name__ == "__main__":
    unittest.main()
