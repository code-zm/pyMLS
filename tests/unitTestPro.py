import unittest
import os
from unittest.mock import Mock
from jsonschema import validate, ValidationError
from pyMLS.KeySchedule import KeySchedule
from pyMLS.RatchetTree import RatchetTree
from pyMLS.MessageFraming import MessageFraming
from pyMLS.WelcomeMessage import WelcomeMessage
from pyMLS.Proposals import AddProposal, RemoveProposal, UpdateProposal, ProposalSigner, ProposalList
from pyMLS.Commit import Commit
from pyMLS.HandshakeMessages import HandshakeMessage, HandshakeType, Add, Update, Remove
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives import serialization
from pyMLS.TranscriptHashManager import TranscriptHashManager
import json

DEBUG = False


class TestMLSComponents(unittest.TestCase):
    """
    Comprehensive test suite for MLS components.
    """

    def setUp(self):
        """
        Initialize shared resources for all tests.
        """
        self.initialSecret = os.urandom(32)
        self.commitSecret = os.urandom(32)
        self.groupContext = b"group_context_example"

        # Initialize TranscriptHashManager
        self.hashManager = TranscriptHashManager()

        # Initialize components
        self.ratchetTree = RatchetTree(numLeaves=4, initialSecret=self.initialSecret, hashManager=self.hashManager)
        self.keySchedule = self.ratchetTree.keySchedule
        self.keySchedule.nextEpoch(self.commitSecret, self.groupContext, self.hashManager)

        epochSecrets = self.keySchedule.getEpochSecrets()
        self.messageFraming = MessageFraming(
            encryptionSecret=epochSecrets["encryptionSecret"],
            authenticationSecret=epochSecrets["authenticationSecret"]
        )
        self.welcomeMessage = WelcomeMessage(
            groupContext=self.groupContext,
            ratchetTree=self.ratchetTree,
            keySchedule=self.keySchedule
        )

        # Generate signing keys
        self.privateKey = Ed25519PrivateKey.generate()
        self.publicKey = self.privateKey.public_key()

    # ---- Existing Tests ----
    def test_key_schedule_derivation(self):
        """Test key schedule derivation process."""
        secrets = self.keySchedule.getEpochSecrets()
        self.assertIn("epochSecret", secrets)
        self.assertIn("encryptionSecret", secrets)

    def test_welcome_message_serialization(self):
        serialized = self.welcomeMessage.serialize()
        deserialized = WelcomeMessage.deserialize(serialized)

        originalTreeSize = len(self.ratchetTree.getPublicState())
        deserializedTreeSize = len(deserialized.ratchetTree.getPublicState())

        self.assertEqual(
            originalTreeSize,
            deserializedTreeSize,
            "Serialized and deserialized tree sizes should match"
        )

    def test_handshake_message_serialization(self):
        """Test serialization and deserialization of HandshakeMessages."""
        # Create an Add handshake message
        senderId = os.urandom(16)
        publicKey = os.urandom(32)
        handshake = Add(senderId=senderId, publicKey=publicKey)

        # Serialize the handshake message
        serialized = handshake.serialize()
        self.assertIsInstance(serialized, bytes, "Serialized handshake message should be bytes")

        # Deserialize the handshake message
        deserialized = HandshakeMessage.deserialize(serialized)
        self.assertIsInstance(deserialized, Add, "Deserialized handshake should be an Add instance")

        # Verify the attributes
        self.assertEqual(deserialized.senderId, senderId, "SenderId should match after deserialization")
        self.assertEqual(deserialized.publicKey, publicKey, "PublicKey should match after deserialization")



    def test_handshake_message_validation(self):
        """Test validation of handshake messages."""
        senderId = os.urandom(16)
        newPublicKey = os.urandom(32)
        
        # Create an Update message
        handshake = Update(senderId=senderId, newPublicKey=newPublicKey)

        # Verify that serialization works
        serialized = handshake.serialize()
        self.assertIsInstance(serialized, bytes, "Serialized Update message should be bytes")

        # Deserialize the message and validate
        deserialized = HandshakeMessage.deserialize(serialized)
        self.assertIsInstance(deserialized, Update, "Deserialized handshake should be an Update instance")
        self.assertEqual(deserialized.senderId, senderId, "SenderId should match after deserialization")
        self.assertEqual(deserialized.newPublicKey, newPublicKey, "newPublicKey should match after deserialization")



    def test_commit_application(self):
        """Test commit message application."""
        addProposal = AddProposal(publicKey=os.urandom(32))
        removeProposal = RemoveProposal(memberIndex=1)
        commit = Commit([addProposal, removeProposal], commitSecret=self.commitSecret, groupContext=self.groupContext)
        commit.apply(self.ratchetTree, self.keySchedule, self.hashManager)
        self.assertEqual(self.keySchedule.epoch, 2)

    # ---- New Tests ----
    def test_large_tree(self):
        """Test creating and managing a large RatchetTree."""
        numLeaves = 1000  # Set the number of leaves
        largeTree = RatchetTree(numLeaves=numLeaves, initialSecret=os.urandom(32), hashManager=self.hashManager)

        # Verify the total number of nodes in the tree (2 * numLeaves - 1)
        self.assertEqual(len(largeTree.getPublicState()), 2 * numLeaves - 1)

        # Add a new member and verify consistency
        newPublicKey = os.urandom(32)
        largeTree.addMember(newPublicKey)
        self.assertEqual(len(largeTree.getPublicState()), 2 * (numLeaves + 1) - 1)

        # Remove a member and verify consistency
        largeTree.removeMember(0)
        self.assertIsNone(largeTree.tree[largeTree.getNodeIndex(0)].publicKey)

    def test_invalid_operations_on_tree(self):
        """Test invalid operations like removing non-existent members."""
        with self.assertRaises(ValueError):
            self.ratchetTree.removeMember(10)  # Invalid index

    def test_transcript_hash_manager(self):
        """Test transcript hash updates and retrieval."""
        initialHash = self.hashManager.getCurrentHash()

        # Expected initial hash: SHA-256 of empty input
        hasher = Hash(SHA256())
        hasher.update(b"")
        expectedInitialHash = hasher.finalize()

        self.assertEqual(initialHash, expectedInitialHash, "Initial hash should match SHA-256 of an empty input")

        # Update hash with dummy data
        self.hashManager.updateHash(b"test-data")
        updatedHash = self.hashManager.getCurrentHash()
        self.assertNotEqual(initialHash, updatedHash, "Transcript hash should update with new data")

    def test_batch_proposals(self):
        """Test signing and verifying a batch of proposals."""
        proposals = [AddProposal(publicKey=os.urandom(32)) for _ in range(10)]
        for proposal in proposals:
            signature = ProposalSigner.signProposal(proposal, self.privateKey, self.hashManager)
            self.assertTrue(
                ProposalSigner.verifyProposal(proposal, signature, self.publicKey.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ), self.hashManager)
            )

    def test_full_group_lifecycle(self):
        """Simulate full group lifecycle."""
        addProposal = AddProposal(publicKey=self.publicKey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))
        removeProposal = RemoveProposal(memberIndex=0)
        commit = Commit(
            proposals=[addProposal, removeProposal],
            commitSecret=self.commitSecret,
            groupContext=self.groupContext
        )
        commit.sign(self.privateKey)
        commit.apply(self.ratchetTree, self.keySchedule, self.hashManager)
        self.assertEqual(self.keySchedule.epoch, 2)


if __name__ == "__main__":
    unittest.main()
