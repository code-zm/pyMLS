import unittest
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pyMLS.KeyPackage import KeyPackage


class TestKeyPackage(unittest.TestCase):
    def setUp(self):
        # Generate keys
        self.privateKey = Ed25519PrivateKey.generate()
        self.publicKey = self.privateKey.public_key()
        
        # Use bytes for credential and extensions
        self.credential = "test_credential".encode("utf-8")
        self.extensions = ["test_extension_1".encode("utf-8"), "test_extension_2".encode("utf-8")]
        
        # Initialize the KeyPackage
        self.keyPackage = KeyPackage(
            version=1,
            cipherSuite=1,
            initKey=os.urandom(32),
            leafNode={
                "leafNodeSource": "test_leaf_node",
                "signatureKey": os.urandom(32),
            },
            extensions=self.extensions,
            credential=self.credential,
            signature=None,
        )
    
    def test_serializeTbs(self):
        """Test serialization of the 'to-be-signed' portion of the KeyPackage."""
        serialized = self.keyPackage.serializeTbs()
        self.assertIsInstance(serialized, bytes)
        self.assertGreater(len(serialized), 0)
        print(f"Serialized TBS: {serialized.hex()}")

    def test_sign(self):
        """Test signing the KeyPackage and ensure signature is generated."""
        self.keyPackage.sign(self.privateKey)
        self.assertIsNotNone(self.keyPackage.signature)
        print(f"KeyPackage signed. Signature: {self.keyPackage.signature.hex()}")

    def test_validateSignature(self):
        """Test signature validation for the KeyPackage."""
        self.keyPackage.sign(self.privateKey)
        is_valid = self.keyPackage.validateSignature(self.publicKey)
        self.assertTrue(is_valid)

    def test_invalid_signature(self):
        """Test signature validation with an invalid signature."""
        self.keyPackage.sign(self.privateKey)
        invalid_key = Ed25519PrivateKey.generate().public_key()
        is_valid = self.keyPackage.validateSignature(invalid_key)
        self.assertFalse(is_valid)

    def test_serialize(self):
        """Test full serialization of the KeyPackage, including the signature."""
        self.keyPackage.sign(self.privateKey)
        serialized = self.keyPackage.serialize()
        self.assertIsInstance(serialized, bytes)
        self.assertGreater(len(serialized), 0)
        print(f"Serialized KeyPackage: {serialized.hex()}")

    def test_deserialize(self):
        """Test deserialization of the KeyPackage from binary data."""
        self.keyPackage.sign(self.privateKey)
        serialized = self.keyPackage.serialize()
        print(f"Serialized for deserialization test: {serialized.hex()}")
        deserialized = KeyPackage.deserialize(serialized)
        self.assertEqual(deserialized.version, self.keyPackage.version)
        self.assertEqual(deserialized.cipherSuite, self.keyPackage.cipherSuite)
        self.assertEqual(deserialized.initKey, self.keyPackage.initKey)
        self.assertEqual(deserialized.leafNode["leafNodeSource"], self.keyPackage.leafNode["leafNodeSource"])
        self.assertEqual(deserialized.extensions, self.keyPackage.extensions)

    def test_signature_generation(self):
        """Test signature generation and ensure it matches the expected output."""
        self.keyPackage.sign(self.privateKey)
        serialized_tbs = self.keyPackage.serializeTbs()
        expected_signature = self.privateKey.sign(serialized_tbs)
        print(f"Generated Signature: {expected_signature.hex()}")
        self.assertEqual(self.keyPackage.signature, expected_signature)


if __name__ == "__main__":
    unittest.main()
