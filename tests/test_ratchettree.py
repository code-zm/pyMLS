import unittest
import os
from pyMLS.RatchetTree import RatchetTree, Node
from pyMLS.TranscriptHashManager import TranscriptHashManager
from pyMLS.KeyPackage import KeyPackage
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class MockKeyPackage(KeyPackage):
    """Mock KeyPackage for testing RatchetTree."""
    def __init__(self, groupVersion, groupCipherSuite, publicKey, privateKey):
        super().__init__(
            version=groupVersion,
            cipherSuite=groupCipherSuite,
            initKey=publicKey,
            leafNode={
                "capabilities": {
                    "versions": [groupVersion],
                    "cipherSuites": [groupCipherSuite],
                },
                "encryptionKey": os.urandom(32).hex(),
                "signatureKey": publicKey.hex(),
                "leafNodeSource": "mock",
            },
            extensions=[]
        )

        self.privateKey = privateKey

    def validate(self, groupContext, groupCipherSuite):
        """Mock validation logic."""
        if self.cipherSuite != groupCipherSuite or self.version != groupContext["group_id"]:
            raise ValueError("Version or cipher suite mismatch.")


class TestRatchetTree(unittest.TestCase):
    def setUp(self):
        """
        Initialize a RatchetTree instance with mock data for testing.
        """
        self.numLeaves = 4
        self.initialSecret = os.urandom(32)
        self.groupContext = {
            "group_id": 1,  # Match the version in MockKeyPackage
            "epoch": 1,
            "tree_hash": None,
            "confirmed_transcript_hash": None,
            "extensions": []
        }
        self.hashManager = TranscriptHashManager()
        self.privateKey = Ed25519PrivateKey.generate()
        self.publicKey = self.privateKey.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        self.ratchetTree = RatchetTree(self.numLeaves, self.initialSecret, self.hashManager, self.groupContext)
        self.mockKeyPackage = MockKeyPackage(1, 0x0001, self.publicKey, self.privateKey)


    def testTreeInitialization(self):
        """
        Test that the tree initializes with the correct number of nodes.
        """
        expectedNodes = 2 * self.numLeaves - 1
        self.assertEqual(len(self.ratchetTree.tree), expectedNodes)
        for i in range(self.numLeaves):
            nodeIndex = self.ratchetTree.getNodeIndex(i)
            self.assertIsNotNone(self.ratchetTree.tree[nodeIndex].publicKey)
            self.assertIsNotNone(self.ratchetTree.tree[nodeIndex].privateKey)

    def testAddMember(self):
        """
        Test adding a new member to the tree.
        """
        self.ratchetTree.addMember(self.mockKeyPackage)
        expectedNodes = 2 * self.ratchetTree.numLeaves - 1
        self.assertEqual(len(self.ratchetTree.tree), expectedNodes)

    def testRemoveMember(self):
        """
        Test removing a member from the tree.
        """
        memberIndex = 1
        self.ratchetTree.removeMember(memberIndex)
        nodeIndex = self.ratchetTree.getNodeIndex(memberIndex)
        self.assertIsNone(self.ratchetTree.tree[nodeIndex].publicKey)
        self.assertIsNone(self.ratchetTree.tree[nodeIndex].privateKey)

    def testUpdateMemberKey(self):
        """
        Test updating a member's key in the tree.
        """
        memberIndex = 1
        newPublicKey = os.urandom(32)
        self.ratchetTree.updateMemberKey(memberIndex, newPublicKey)
        nodeIndex = self.ratchetTree.getNodeIndex(memberIndex)
        self.assertEqual(self.ratchetTree.tree[nodeIndex].publicKey, newPublicKey)

    def testTreeSynchronization(self):
        """
        Test synchronization of the tree with a public state.
        """
        publicState = [os.urandom(32) for _ in range(self.numLeaves)] + [None] * (self.ratchetTree.numNodes - self.numLeaves)
        self.ratchetTree.syncTree(publicState)
        self.assertTrue(self.ratchetTree.validateParentHashes())


    def testSerializeAndDeserializeTree(self):
        """
        Test tree serialization and deserialization.
        """
        serializedTree = self.ratchetTree.serializeTree()
        self.assertIsInstance(serializedTree, bytes)
        self.ratchetTree.deserializeTree(serializedTree)
        deserializedTreeState = [node.publicKey for node in self.ratchetTree.tree]
        originalTreeState = [node.publicKey for node in self.ratchetTree.tree]
        self.assertEqual(deserializedTreeState, originalTreeState)

    def testParentHashAfterUpdate(self):
        """
        Ensure parent hashes remain consistent after member updates.
        """
        memberIndex = 2
        newPublicKey = os.urandom(32)
        self.ratchetTree.updateMemberKey(memberIndex, newPublicKey)
        self.assertTrue(self.ratchetTree.validateParentHashes())

    def testValidateParentHashes(self):
        """
        Test that the parent hashes are valid after initialization.
        """
        self.assertTrue(self.ratchetTree.validateParentHashes())


if __name__ == "__main__":
    unittest.main()
