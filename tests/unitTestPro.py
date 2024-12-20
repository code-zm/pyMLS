import unittest
import os
from unittest.mock import Mock
from jsonschema import validate, ValidationError
from ..KeySchedule import KeySchedule
from ..RatchetTree import RatchetTree
from ..MessageFraming import MessageFraming
from ..WelcomeMessage import WelcomeMessage
from ..Proposals import AddProposal, RemoveProposal, UpdateProposal, ProposalSigner, ProposalList
from ..Commit import Commit
from ..HandshakeMessages import HandshakeMessage, HandshakeType, Add, Update, Remove
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives import serialization
from TranscriptHashManager import TranscriptHashManager
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

    # ---- Ratchet Tree ----
    def test_large_tree(self):
        """Test creating and managing a large RatchetTree."""
        numLeaves = 1000
        largeTree = RatchetTree(numLeaves=numLeaves, initialSecret=os.urandom(32), hashManager=self.hashManager)

        self.assertEqual(len(largeTree.getPublicState()), 2 * numLeaves - 1)

        newPublicKey = os.urandom(32)
        largeTree.addMember(newPublicKey)
        self.assertEqual(len(largeTree.getPublicState()), 2 * (numLeaves + 1) - 1)

        largeTree.removeMember(0)
        self.assertIsNone(largeTree.tree[largeTree.getNodeIndex(0)].publicKey)

    def test_invalid_operations_on_tree(self):
        """Test invalid operations like removing non-existent members."""
        with self.assertRaises(ValueError):
            self.ratchetTree.removeMember(10)

    def test_public_state_consistency(self):
        """Verify syncTree restores consistent public state."""
        originalState = self.ratchetTree.getPublicState()
        self.ratchetTree.syncTree(originalState)
        self.assertEqual(self.ratchetTree.getPublicState(), originalState)

    # ---- Transcript Hash ----
    def test_transcript_hash_manager(self):
        """Test transcript hash updates and retrieval."""
        initialHash = self.hashManager.getCurrentHash()

        hasher = Hash(SHA256())
        hasher.update(b"")
        expectedInitialHash = hasher.finalize()

        self.assertEqual(initialHash, expectedInitialHash)

        self.hashManager.updateHash(b"test-data")
        updatedHash = self.hashManager.getCurrentHash()
        self.assertNotEqual(initialHash, updatedHash)

    # ---- Key Schedule ----
    def test_invalid_commit_secret(self):
        """Test handling of invalid commit secrets."""
        with self.assertRaises(ValueError):
            self.keySchedule.nextEpoch(None, self.groupContext, self.hashManager)

    def test_serialization_deserialization_key_schedule(self):
        """Test serializing and deserializing key schedule states."""
        serialized = json.dumps(self.keySchedule.getEpochSecrets())
        deserialized = json.loads(serialized)
        self.assertIn("epochSecret", deserialized)

    # ---- Proposals ----
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

    # ---- Commit ----
    def test_commit_application(self):
        """Test commit message application."""
        addProposal = AddProposal(publicKey=os.urandom(32))
        removeProposal = RemoveProposal(memberIndex=1)
        commit = Commit([addProposal, removeProposal], commitSecret=self.commitSecret, groupContext=self.groupContext)
        commit.apply(self.ratchetTree, self.keySchedule, self.hashManager)
        self.assertEqual(self.keySchedule.epoch, 2)

    def test_tampered_commit_data(self):
        """Verify detection of tampered commit data."""
        commit = Commit(
            proposals=[AddProposal(publicKey=self.publicKey.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ))],
            commitSecret=self.commitSecret,
            groupContext=self.groupContext
        )
        commit.sign(self.privateKey)
        serialized = commit.serialize()[:-1] + b"X"
        deserialized = Commit.deserializeCommit(serialized, self.publicKey)
        self.assertIsNone(deserialized)

    # ---- Handshake Messages ----
    def test_handshake_message_serialization(self):
        """Test serialization and deserialization of HandshakeMessages."""
        senderId = os.urandom(16)
        publicKey = os.urandom(32)
        handshake = Add(senderId=senderId, publicKey=publicKey)

        serialized = handshake.serialize()
        self.assertIsInstance(serialized, bytes)

        deserialized = HandshakeMessage.deserialize(serialized)
        self.assertIsInstance(deserialized, Add)
        self.assertEqual(deserialized.senderId, senderId)
        self.assertEqual(deserialized.publicKey, publicKey)

    # ---- Welcome Message ----
    def test_welcome_message_serialization(self):
        serialized = self.welcomeMessage.serialize()
        deserialized = WelcomeMessage.deserialize(serialized)

        originalTreeSize = len(self.ratchetTree.getPublicState())
        deserializedTreeSize = len(deserialized.ratchetTree.getPublicState())

        self.assertEqual(originalTreeSize, deserializedTreeSize)

    # ---- Integration ----
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
