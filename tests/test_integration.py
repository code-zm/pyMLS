import unittest
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyMLS.Commit import Commit
from pyMLS.HandshakeMessages import Add, Update, Remove
from pyMLS.KeyPackage import KeyPackage
from pyMLS.KeySchedule import KeySchedule
from pyMLS.MessageFraming import MessageFraming
from pyMLS.Proposals import AddProposal, UpdateProposal, RemoveProposal
from pyMLS.RatchetTree import RatchetTree
from pyMLS.TranscriptHashManager import TranscriptHashManager
from pyMLS.WelcomeMessage import WelcomeMessage


class TestMLSIntegration(unittest.TestCase):
    def setUp(self):
        # Setup common elements
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        self.commit_secret = os.urandom(32)
        self.group_context = os.urandom(32)

        # Initialize key schedule and transcript hash manager
        self.key_schedule = KeySchedule(initialSecret=self.commit_secret)
        self.transcript_hash_manager = TranscriptHashManager()

        # Initialize a RatchetTree with two members
        self.ratchet_tree = RatchetTree(numLeaves=2, initialSecret=os.urandom(32), hashManager=self.transcript_hash_manager)

        # Mock KeyPackage
        self.mock_key_package = KeyPackage(
            version=1,
            cipher_suite=0x0001,
            init_key=self.public_key_bytes,
            leaf_node={
                "capabilities": {"versions": [1], "ciphersuites": [0x0001]},
                "encryption_key": os.urandom(32).hex(),
                "signature_key": self.public_key_bytes.hex(),
                "leaf_node_source": "key_package",
            },
            extensions=[],
            private_key=self.private_key,
        )

    def test_commit_integration(self):
        """Test Commit creation, serialization, signing, and application."""
        # Serialize the Commit
        serialized_commit = self.commit.serialize()
        self.assertIsInstance(serialized_commit, bytes)

        # Deserialize the Commit
        deserialized_commit = Commit.deserialize(serialized_commit)
        self.assertIsNotNone(deserialized_commit, "Commit deserialization failed.")
        self.assertEqual(deserialized_commit.commitSecret, self.commit.commitSecret)
        self.assertEqual(deserialized_commit.groupContext, self.commit.groupContext)

        # Apply the Commit
        try:
            deserialized_commit.apply(
                ratchetTree=self.ratchet_tree,
                keySchedule=self.key_schedule,
                hashManager=self.transcript_hash_manager
            )
            self.assertTrue(True, "Commit applied successfully.")
        except Exception as e:
            self.fail(f"Commit application failed with exception: {e}")

    def test_handshake_messages_integration(self):
        """Test Add, Update, and Remove handshake messages."""
        add_msg = Add(senderId=os.urandom(16), keyPackage=self.mock_key_package)
        serialized_add = add_msg.serialize()
        deserialized_add = Add.deserialize(serialized_add)
        self.assertEqual(deserialized_add.keyPackage.version, add_msg.keyPackage.version)

        update_msg = Update(senderId=os.urandom(16), newPublicKey=os.urandom(32))
        serialized_update = update_msg.serialize()
        deserialized_update = Update.deserialize(serialized_update)
        self.assertEqual(deserialized_update.newPublicKey, update_msg.newPublicKey)

        remove_msg = Remove(senderId=os.urandom(16), memberIndex=1)
        serialized_remove = remove_msg.serialize()
        deserialized_remove = Remove.deserialize(serialized_remove)
        self.assertEqual(deserialized_remove.memberIndex, remove_msg.memberIndex)

    def test_welcome_message_integration(self):
        """Test WelcomeMessage creation, serialization, and processing."""
        welcome = WelcomeMessage(self.group_context, self.ratchet_tree, self.key_schedule)
        welcome_message = welcome.createWelcome(self.mock_key_package)

        self.assertIn("groupContext", welcome_message)
        self.assertIn("encryptedGroupSecrets", welcome_message)
        self.assertIn("encryptedEpochSecret", welcome_message)

        serialized_welcome = welcome.serialize()
        deserialized_welcome = WelcomeMessage.deserialize(serialized_welcome)
        self.assertIsNotNone(deserialized_welcome, "WelcomeMessage deserialization returned None.")

    def test_message_framing(self):
        """Test encryption and decryption of MLS messages."""
        framer = MessageFramer(epoch=1, groupId=self.group_context, senderId=os.urandom(16))
        plaintext_message = b"Hello, MLS!"
        encrypted_message = framer.encrypt(plaintext_message, self.key_schedule.getEpochSecrets()["encryptionKey"])
        decrypted_message = framer.decrypt(encrypted_message, self.key_schedule.getEpochSecrets()["encryptionKey"])

        self.assertEqual(plaintext_message, decrypted_message)

if __name__ == "__main__":
    unittest.main()

