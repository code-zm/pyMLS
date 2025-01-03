import unittest
import os
from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption, Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pyMLS.WelcomeMessage import WelcomeMessage
from pyMLS.RatchetTree import RatchetTree
from pyMLS.KeySchedule import KeySchedule
from pyMLS.KeyPackage import KeyPackage


class TestWelcomeMessage(unittest.TestCase):
    def setUp(self):
        # Generate X25519 keys for HPKE
        self.privateKey = X25519PrivateKey.generate()
        self.publicKey = self.privateKey.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

        # Mock dependencies
        self.groupContext = os.urandom(32)  # Mock group context
        self.groupVersion = 1  # Example version
        self.groupCipherSuite = 0x1301  # TLS_AES_128_GCM_SHA256

        # Mock RatchetTree
        self.mockRatchetTree = RatchetTree(numLeaves=4, initialSecret=os.urandom(32), hashManager=None)
        self.mockRatchetTree.getPublicState = lambda: [os.urandom(32) for _ in range(7)]

        # Mock KeySchedule
        self.mockKeySchedule = KeySchedule(initialSecret=os.urandom(32))
        self.mockKeySchedule.getEpochSecrets = lambda: {"epochSecret": os.urandom(32)}

        # Create a valid KeyPackage
        self.keyPackage = KeyPackage(
            version=self.groupVersion,
            cipherSuite=self.groupCipherSuite,
            initKey=self.publicKey,
            credential=os.urandom(16),
            leafNode={
                "leafNodeSource": "test_leaf_node",
                "signatureKey": os.urandom(32),
            },
            extensions=[os.urandom(8), os.urandom(8)],
        )
        self.keyPackage.sign(Ed25519PrivateKey.generate())  # Use Ed25519 key for signing

        # Initialize WelcomeMessage handler
        self.welcomeMessageHandler = WelcomeMessage(
            groupContext=self.groupContext,
            ratchetTree=self.mockRatchetTree,
            keySchedule=self.mockKeySchedule,
            groupVersion=self.groupVersion,
            groupCipherSuite=self.groupCipherSuite,
        )

    def testCreateWelcomeMessage(self):
        """Test creation of a WelcomeMessage."""
        welcomeMessage = self.welcomeMessageHandler.createWelcome(self.keyPackage)
        self.assertIn("groupContext", welcomeMessage)
        self.assertIn("encryptedGroupSecrets", welcomeMessage)
        self.assertIn("encryptedEpochSecret", welcomeMessage)
        self.assertIn("publicRatchetTree", welcomeMessage)
        self.assertIn("keyPackage", welcomeMessage)

    def testSerializeBinary(self):
        """Test binary serialization of a WelcomeMessage."""
        welcomeMessage = self.welcomeMessageHandler.createWelcome(self.keyPackage)
        serialized = self.welcomeMessageHandler.serializeBinary(welcomeMessage)
        self.assertIsInstance(serialized, bytes)
        self.assertGreater(len(serialized), 0)

    def testDeserializeBinary(self):
        """Test binary deserialization of a WelcomeMessage."""
        welcomeMessage = self.welcomeMessageHandler.createWelcome(self.keyPackage)
        serialized = self.welcomeMessageHandler.serializeBinary(welcomeMessage)
        deserialized = self.welcomeMessageHandler.deserializeBinary(serialized)
        self.assertIn("groupContext", deserialized)
        self.assertIn("encryptedGroupSecrets", deserialized)
        self.assertIn("encryptedEpochSecret", deserialized)
        self.assertIn("publicRatchetTree", deserialized)
        self.assertIn("keyPackage", deserialized)

    def testProcessWelcomeMessage(self):
        """Test processing a WelcomeMessage to initialize state."""
        welcomeMessage = self.welcomeMessageHandler.createWelcome(self.keyPackage)
        serialized = self.welcomeMessageHandler.serializeBinary(welcomeMessage)
        deserialized = self.welcomeMessageHandler.deserializeBinary(serialized)

        # Mock syncTree
        self.mockRatchetTree.syncTree = lambda x: None

        # Process the welcome message
        self.welcomeMessageHandler.processWelcome(
            welcomeMessage=deserialized,
            privateKey=self.privateKey,  # Pass the private key object directly
        )
        self.assertIsNotNone(self.mockKeySchedule.currentEpochSecret)


if __name__ == "__main__":
    unittest.main()
