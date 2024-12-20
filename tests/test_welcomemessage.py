import unittest
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from pyMLS.WelcomeMessage import WelcomeMessage
from pyMLS.RatchetTree import RatchetTree
from pyMLS.KeySchedule import KeySchedule
from pyMLS.KeyPackage import KeyPackage
from pyMLS.TranscriptHashManager import TranscriptHashManager

DEBUG = False

class Node:
    """
    Represents a node in the RatchetTree with a public key and optional parent hash.
    """
    def __init__(self, publicKey=None):
        self.publicKey = publicKey  # Bytes-like object for the node's public key
        self.parentHash = None  # Bytes-like object for the parent hash


class MockRatchetTree(RatchetTree):
    def __init__(self, numLeaves, initialSecret, hashManager):
        super().__init__(numLeaves, initialSecret, hashManager)
        self.numLeaves = numLeaves
        self.tree = self.generateCompleteBinaryTree(numLeaves)

    def generateCompleteBinaryTree(self, numLeaves):
        """
        Generate a complete binary tree structure with `Node` objects.
        """
        totalNodes = 2 * numLeaves - 1  # Total nodes in a complete binary tree
        return [Node(publicKey=os.urandom(32)) for _ in range(totalNodes)]

    def getPublicState(self):
        """
        Return the public state of the tree (all nodes).
        """
        return [{"publicKey": node.publicKey} for node in self.tree]

    def syncTree(self, publicState):
        """
        Sync the tree state with the provided public state.
        Ensure all nodes are reconstructed as `Node` objects.
        """
        if len(publicState) != len(self.tree):
            if DEBUG:
                print(f"Expected tree size: {len(self.tree)}, but got: {len(publicState)}")
            raise ValueError("Public tree state size does not match the tree.")
        
        # Reconstruct the tree with proper `Node` objects
        self.tree = [
            Node(publicKey=state["publicKey"] if isinstance(state["publicKey"], bytes) 
                 else bytes.fromhex(state["publicKey"])) for state in publicState
        ]
        if DEBUG:
            print("Tree successfully synced with public state.")
            print("Tree nodes after sync:", [node.publicKey for node in self.tree])







class TestWelcomeMessage(unittest.TestCase):
    def setUp(self):
        # Generate keys and mock data
        self.privateKey = Ed25519PrivateKey.generate()
        self.publicKey = self.privateKey.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        self.groupContext = os.urandom(32)  # Mock group context
        self.groupVersion = 1  # Example version
        self.groupCipherSuite = 0x1301  # TLS_AES_128_GCM_SHA256
        self.transcriptHashManager = TranscriptHashManager()
        self.commitSecret = os.urandom(32)  # Mock commit secret

        # Mock RatchetTree with complete binary tree structure
        self.ratchetTree = MockRatchetTree(
            numLeaves=4,  # Number of leaves
            initialSecret=os.urandom(32),
            hashManager=self.transcriptHashManager,
        )

        # Mock KeySchedule
        self.keySchedule = KeySchedule(initialSecret=os.urandom(32))
        self.keySchedule.nextEpoch(self.commitSecret, self.groupContext, self.transcriptHashManager)  # Initialize epoch secrets

        # Mock KeyPackage using format from KeyPackage.py
        self.mockKeyPackage = KeyPackage(
            version=self.groupVersion,
            cipherSuite=self.groupCipherSuite,  # Updated for lower camel case
            initKey=self.publicKey,  # Updated for lower camel case
            leafNode={
                "capabilities": {
                    "versions": [self.groupVersion],
                    "cipherSuites": [self.groupCipherSuite],
                },
                "encryptionKey": os.urandom(32).hex(),
                "signatureKey": self.publicKey.hex(),
                "leafNodeSource": "key_package",
            },
            extensions=[],
            privateKey=self.privateKey,  # Updated for lower camel case
        )

        # Initialize WelcomeMessage handler
        self.welcomeMessageHandler = WelcomeMessage(
            groupContext=self.groupContext,
            ratchetTree=self.ratchetTree,
            keySchedule=self.keySchedule,
            groupVersion=self.groupVersion,
            groupCipherSuite=self.groupCipherSuite,
            keyPackage=self.mockKeyPackage,  # Pass KeyPackage instance
        )

    def testCreateWelcomeMessage(self):
        """Test creation of a WelcomeMessage."""
        welcomeMessage = self.welcomeMessageHandler.createWelcome(self.mockKeyPackage)
        self.assertIn("groupContext", welcomeMessage)
        self.assertIn("encryptedGroupSecrets", welcomeMessage)
        self.assertIn("publicRatchetTree", welcomeMessage)

    def testSerializeWelcomeMessage(self):
        """Test serialization of a WelcomeMessage."""
        welcomeMessage = self.welcomeMessageHandler.createWelcome(self.mockKeyPackage)
        serialized = self.welcomeMessageHandler.serialize()
        self.assertIsInstance(serialized, bytes)

    def testDeserializeWelcomeMessage(self):
        """Test deserialization of a WelcomeMessage."""
        welcomeMessage = self.welcomeMessageHandler.createWelcome(self.mockKeyPackage)
        serialized = self.welcomeMessageHandler.serialize()
        if DEBUG:
            print(f"Serialized data: {serialized}")
        deserialized = WelcomeMessage.deserialize(serialized)
        self.assertIsInstance(deserialized, WelcomeMessage)

    def testProcessWelcomeMessage(self):
        """Test processing a WelcomeMessage to initialize state."""
        welcomeMessage = self.welcomeMessageHandler.createWelcome(self.mockKeyPackage)
        self.welcomeMessageHandler.processWelcome(
            welcomeMessage=welcomeMessage,
            privateKey=self.privateKey.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            ),
        )


if __name__ == "__main__":
    unittest.main()
