import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pyMLS.HandshakeMessages import Add, Update, Remove, Commit, HandshakeMessage
from pyMLS.KeyPackage import KeyPackage
from pyMLS.HandshakeTypes import HandshakeType

class TestHandshakeMessages(unittest.TestCase):

    def setUp(self):
        self.key_package = KeyPackage(
            version=1,
            cipherSuite=1,
            initKey=b'\x01' * 32,
            leafNode={"public_key": "dummy"},
            extensions=[],
        )
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.proposals = [Add(self.key_package)]
        self.commit_msg = Commit(
            proposals=self.proposals,
            commitSecret=b'\x02' * 32
        )

    def test_add_serialize_deserialize(self):
        add_msg = Add(self.key_package)
        serialized = add_msg.serializeBinary()
        deserialized = Add.deserializeBinary(serialized)
        self.assertEqual(self.key_package.serialize(), deserialized.keyPackage.serialize())

    def test_update_serialize_deserialize(self):
        update_msg = Update(self.key_package)
        serialized = update_msg.serializeBinary()
        deserialized = Update.deserializeBinary(serialized)
        self.assertEqual(self.key_package.serialize(), deserialized.keyPackage.serialize())

    def test_remove_serialize_deserialize(self):
        remove_msg = Remove(42)
        serialized = remove_msg.serializeBinary()
        deserialized = Remove.deserializeBinary(serialized)
        self.assertEqual(remove_msg.removedIndex, deserialized.removedIndex)

    def test_commit_serialize_deserialize(self):
        serialized = self.commit_msg.serializeBinary()
        deserialized = Commit.deserializeBinary(serialized)
        self.assertEqual(self.commit_msg.commitSecret, deserialized.commitSecret)
        self.assertEqual(len(self.commit_msg.proposals), len(deserialized.proposals))

    def test_commit_sign_verify(self):
        self.commit_msg.sign(self.private_key)
        self.assertTrue(self.commit_msg.signature is not None)
        self.assertTrue(self.commit_msg.verify(self.public_key))

if __name__ == "__main__":
    unittest.main()
