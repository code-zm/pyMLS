import unittest
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pyMLS.HandshakeMessages import HandshakeMessage, HandshakeType
from pyMLS.KeyPackage import KeyPackage

class TestHandshakeMessages(unittest.TestCase):

    def setUp(self):
        # Generate keys
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # Use bytes for credentials and extensions
        credential = b"test_credential"
        extensions = [b"test_extension_1", b"test_extension_2"]

        # Initialize KeyPackage
        self.key_package = KeyPackage(
            version=1,
            cipherSuite=1,
            initKey=os.urandom(32),
            leafNode={
                "leafNodeSource": "test_leaf_node",
                "signatureKey": os.urandom(32),
            },
            extensions=extensions,
            credential=credential,
            signature=None,
        )


    def test_handshake_serialize_deserialize(self):
        # Test for ADD
        add_msg = HandshakeMessage(HandshakeType.ADD, b"payload_add")
        serialized = add_msg.serializeBinary()
        deserialized = HandshakeMessage.deserializeBinary(serialized)
        self.assertEqual(add_msg.messageType, deserialized.messageType)
        self.assertEqual(add_msg.payload, deserialized.payload)

        # Test for UPDATE
        update_msg = HandshakeMessage(HandshakeType.UPDATE, b"payload_update")
        serialized = update_msg.serializeBinary()
        deserialized = HandshakeMessage.deserializeBinary(serialized)
        self.assertEqual(update_msg.messageType, deserialized.messageType)
        self.assertEqual(update_msg.payload, deserialized.payload)

        # Test for REMOVE
        remove_msg = HandshakeMessage(HandshakeType.REMOVE, b"payload_remove")
        serialized = remove_msg.serializeBinary()
        deserialized = HandshakeMessage.deserializeBinary(serialized)
        self.assertEqual(remove_msg.messageType, deserialized.messageType)
        self.assertEqual(remove_msg.payload, deserialized.payload)

    def test_signature_validation(self):
        # Create and sign a message
        msg = HandshakeMessage(HandshakeType.COMMIT, b"commit_payload")
        signature = self.private_key.sign(msg.serializeBinary())
        
        # Validate signature
        self.public_key.verify(signature, msg.serializeBinary())

        # Test invalid signature
        with self.assertRaises(Exception):
            self.public_key.verify(b"invalid_signature", msg.serializeBinary())

    def test_invalid_deserialization(self):
        # Test malformed input
        with self.assertRaises(Exception):
            HandshakeMessage.deserializeBinary(b"malformed_input")

if __name__ == "__main__":
    unittest.main()
