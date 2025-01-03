import unittest
from cryptography.hazmat.primitives.hashes import SHA256
from pyMLS.KeySchedule import KeySchedule
from unittest.mock import Mock


class TestKeySchedule(unittest.TestCase):
    def setUp(self):
        # Setup initial conditions for tests
        self.initial_secret = b"initial_secret"
        self.commit_secret = b"commit_secret"
        self.context = b"group_context"
        self.psk = b"pre_shared_key"
        self.transcript_hash = b"transcript_hash"
        
        # Mock TranscriptHashManager
        self.hash_manager = Mock()
        self.hash_manager.getCurrentHash.return_value = self.transcript_hash
        
        # Initialize KeySchedule
        self.key_schedule = KeySchedule(self.initial_secret)

    def test_derive_secret(self):
        # Test deriveSecret with a simple context
        label = "test_label"
        context = b"test_context"
        secret = self.key_schedule.deriveSecret(self.initial_secret, label, context)
        self.assertEqual(len(secret), 32)

    def test_inject_pre_shared_key(self):
        # Test injecting a pre-shared key
        self.key_schedule.currentEpochSecret = b"current_secret"
        self.key_schedule.injectPreSharedKey(self.psk)
        derived_secret = self.key_schedule.deriveSecret(b"current_secret", "psk_secret", self.psk)
        self.assertEqual(self.key_schedule.currentEpochSecret, derived_secret)

    def test_export_secret(self):
        label = "export_test"
        context = b"export_context"

        # Initialize secrets for the epoch
        self.key_schedule.nextEpoch(self.commit_secret, self.context, self.hash_manager, numLeaves=4)

        exported_secret = self.key_schedule.exportSecret(label, context)
        expected_secret = self.key_schedule.deriveSecret(self.key_schedule.exporterSecret, f"exporter_{label}", context)
        self.assertEqual(exported_secret, expected_secret)


    def test_derive_epoch_authenticator(self):
        # Test deriving an epoch authenticator
        confirmation_key = b"confirmation_key"
        epoch_authenticator = self.key_schedule.deriveEpochAuthenticator(confirmation_key)
        expected_authenticator = self.key_schedule.deriveSecret(confirmation_key, "epoch_authenticator", b"")
        self.assertEqual(epoch_authenticator, expected_authenticator)

    def test_next_epoch(self):
        # Call nextEpoch with PSK
        self.key_schedule.nextEpoch(self.commit_secret, self.context, self.hash_manager, self.psk, numLeaves=4)

        # Compute expected values step-by-step
        combined_context = self.commit_secret + self.context + self.transcript_hash
        expected_epoch_secret = self.key_schedule.deriveSecret(
            self.initial_secret, "epoch_secret", combined_context
        )
        if self.psk:
            expected_epoch_secret = self.key_schedule.deriveSecret(
                expected_epoch_secret, "psk_secret", self.psk
            )

        # Validate the epoch secret
        self.assertEqual(self.key_schedule.currentEpochSecret, expected_epoch_secret)

        # Check SecretTree initialization
        self.assertIsNotNone(self.key_schedule.secretTree)

    def test_get_epoch_secrets(self):
        # Test retrieving epoch secrets
        self.key_schedule.nextEpoch(self.commit_secret, self.context, self.hash_manager, self.psk, numLeaves=4)
        secrets = self.key_schedule.getEpochSecrets()
        self.assertIn("epochSecret", secrets)
        self.assertIn("encryptionSecret", secrets)
        self.assertIn("authenticationSecret", secrets)
        self.assertIn("exporterSecret", secrets)
        self.assertIn("resumptionSecret", secrets)
        self.assertIn("confirmationKey", secrets)
        self.assertIn("epochAuthenticator", secrets)

    def test_update_for_commit(self):
        # Test updateForCommit functionality
        self.key_schedule.updateForCommit(self.commit_secret, self.context, self.hash_manager, self.psk)
        self.assertEqual(self.key_schedule.epoch, 1)

    def test_get_leaf_secrets(self):
        # Test retrieving per-leaf secrets
        numLeaves = 4
        self.key_schedule.nextEpoch(self.commit_secret, self.context, self.hash_manager, numLeaves=numLeaves)

        # Test handshake and application keys for the first leaf
        leaf_index = 0
        secrets = self.key_schedule.getLeafSecrets(leaf_index, self.key_schedule.epoch)

        self.assertIn("handshakeKey", secrets)
        self.assertIn("handshakeNonce", secrets)
        self.assertIn("applicationKey", secrets)
        self.assertIn("applicationNonce", secrets)

        # Ensure keys and nonces are non-empty
        self.assertTrue(secrets["handshakeKey"])
        self.assertTrue(secrets["handshakeNonce"])
        self.assertTrue(secrets["applicationKey"])
        self.assertTrue(secrets["applicationNonce"])


if __name__ == "__main__":
    unittest.main()
