import unittest
import os
from unittest.mock import Mock
from jsonschema import validate, ValidationError
from ..KeySchedule import KeySchedule
from ..RatchetTree import RatchetTree
from ..MessageFraming import MessageFraming
from ..WelcomeMessage import WelcomeMessage
from ..Proposals import AddProposal, RemoveProposal, UpdateProposal, ProposalSigner
from ..Commit import Commit
from ..HandshakeMessages import HandshakeMessage, HandshakeType, Add, Update, Remove
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import json

DEBUG = False

class TestMLSComponents(unittest.TestCase):
    """
    Comprehensive test suite for testing all MLS components.
    """

    def setUp(self):
        """
        Initialize shared resources for all tests.
        """
        self.initialSecret = os.urandom(32)
        self.commitSecret = os.urandom(32)
        self.groupContext = b"group_context_example"

        # Initialize components
        self.ratchetTree = RatchetTree(numLeaves=4, initialSecret=self.initialSecret)
        self.keySchedule = self.ratchetTree.keySchedule
        self.keySchedule.nextEpoch(self.commitSecret, self.groupContext)

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
        self.publicKey = self.privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    # ---- Ratchet Tree ----
    def test_large_tree(self):
        """Test creating and managing a large RatchetTree."""
        numLeaves = 1000  # Set the number of leaves
        largeTree = RatchetTree(numLeaves=numLeaves, initialSecret=os.urandom(32))

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
        with self.assertRaises(IndexError):
            self.ratchetTree.removeMember(10)  # Invalid index

    def test_public_state_consistency(self):
        """Verify syncTree restores consistent public state."""
        originalState = self.ratchetTree.getPublicState()
        self.ratchetTree.syncTree(originalState)
        self.assertEqual(self.ratchetTree.getPublicState(), originalState)

    # ---- Key Schedule ----
    def test_invalid_commit_secret(self):
        """Test handling of invalid commit secrets."""
        with self.assertRaises(ValueError):
            self.keySchedule.nextEpoch(None, self.groupContext)

    def test_serialization_deserialization_key_schedule(self):
        """Test serializing and deserializing key schedule states."""
        serialized = json.dumps(self.keySchedule.getEpochSecrets())
        deserialized = json.loads(serialized)
        self.assertIn("epochSecret", deserialized)

    # ---- Message Framing ----
    def test_tampered_ciphertext(self):
        """Verify tampered ciphertext detection."""
        plaintext = b"Test tampered ciphertext"
        groupId = b"group_id_example"
        epoch = 0

        # Encrypt a message
        encrypted = self.messageFraming.encryptMessage(plaintext, groupId, epoch)

        # Tamper with the ciphertext
        tampered = encrypted[:-1] + b"\x00"  # Change the last byte

        # Ensure decryption raises ValueError
        with self.assertRaises(ValueError) as context:
            self.messageFraming.decryptMessage(tampered, groupId, epoch)

        self.assertEqual(str(context.exception), "Tampered ciphertext detected")

    # ---- Proposals ----
    def test_batch_proposals(self):
        """Test signing and verifying a batch of proposals."""
        proposals = [AddProposal(publicKey=os.urandom(32)) for _ in range(10)]
        for proposal in proposals:
            signature = ProposalSigner.signProposal(proposal, self.privateKey)
            self.assertTrue(
                ProposalSigner.verifyProposal(proposal, signature, self.publicKey)
            )

    # ---- Commit ----
    def test_partial_application_commit(self):
        """Test partial application of proposals in Commit."""
        commit = Commit(
            proposals=[AddProposal(publicKey=self.publicKey), "InvalidProposal"],
            commitSecret=self.commitSecret,
            groupContext=self.groupContext
        )
        with self.assertRaises(TypeError):
            commit.apply(self.ratchetTree, self.keySchedule)
            
    
    def test_tampered_commit_data(self):
        """Verify detection of tampered commit data."""
        commit = Commit(
            proposals=[AddProposal(publicKey=self.publicKey)],
            commitSecret=self.commitSecret,
            groupContext=self.groupContext
        )
        commit.sign(self.privateKey)
        serialized = commit.serialize()[:-1] + b"X"  # Tamper with data
        deserialized = Commit.deserializeCommit(serialized, self.publicKey)
        self.assertIsNone(deserialized)

    # ---- Handshake Messages ----
    def test_handshake_invalid_types(self):
        """Verify detection of invalid handshake types."""
        with self.assertRaises(ValueError):
            HandshakeMessage.deserialize(b'{"proposalType": "invalid"}')

    def test_handshake_message_performance(self):
        """Test serialization/deserialization performance of handshake messages."""
        handshakeMessages = [Add(senderId=os.urandom(16), publicKey=os.urandom(32)) for _ in range(1000)]
        serialized = [message.serialize() for message in handshakeMessages]
        deserialized = [Add.deserialize(data) for data in serialized]
        self.assertEqual(len(handshakeMessages), len(deserialized))

    # ---- Welcome Message ----
    def test_welcome_invalid_secrets(self):
        invalidKey = "not_a_key"
        with self.assertRaises(ValueError):
            self.welcomeMessage.createWelcome(invalidKey)

    def test_welcome_partial_members(self):
        """Test creating WelcomeMessage for subset of members."""
        partialWelcome = self.welcomeMessage.createWelcome(os.urandom(32))
        self.assertIn("groupContext", partialWelcome)

    # ---- Integration ----
    def test_full_group_lifecycle(self):
        """Simulate full group lifecycle."""
        addProposal = AddProposal(publicKey=self.publicKey)
        removeProposal = RemoveProposal(memberIndex=0)
        commit = Commit(
            proposals=[addProposal, removeProposal],
            commitSecret=self.commitSecret,
            groupContext=self.groupContext
        )
        commit.sign(self.privateKey)
        commit.apply(self.ratchetTree, self.keySchedule)
        self.assertEqual(self.keySchedule.epoch, 2)

if __name__ == "__main__":
    unittest.main()
