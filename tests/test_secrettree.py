import unittest
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from pyMLS.SecretTree import SecretTree


class TestSecretTree(unittest.TestCase):
    def setUp(self):
        # Fixed root secret for testing
        self.root_secret = b'\x00' * 32  # 32-byte root secret
        self.num_leaves = 4  # Number of leaves in the tree
        self.epoch = 1  # Epoch for key derivation
        self.secret_tree = SecretTree(self.num_leaves, self.root_secret)

    def test_tree_structure(self):
        # Verify the structure of the tree
        expected_tree_size = 2 * self.num_leaves - 1
        self.assertEqual(len(self.secret_tree.tree), expected_tree_size)
        self.assertIsNotNone(self.secret_tree.tree[0])  # Root node
        for i in range(1, expected_tree_size):
            if i >= self.num_leaves - 1:
                # Leaf nodes
                self.assertIsNotNone(self.secret_tree.tree[i])
            else:
                # Internal nodes
                self.assertIsNotNone(self.secret_tree.tree[i])

    def test_derive_tree(self):
        # Verify the tree is derived correctly
        for i in range(len(self.secret_tree.tree)):
            if i == 0:
                # Root node should match the root secret
                self.assertEqual(self.secret_tree.tree[i], self.root_secret)
            elif i < len(self.secret_tree.tree):
                # Derived nodes should not be None
                self.assertIsNotNone(self.secret_tree.tree[i])

    def test_expand_function(self):
        # Test the expand function
        label = b"test_label"
        secret = self.secret_tree.expand(self.root_secret, label)
        self.assertEqual(len(secret), 32)  # Derived key should be 32 bytes

    def test_get_leaf_secret(self):
        # Verify leaf secrets
        for leaf_index in range(self.num_leaves):
            leaf_secret = self.secret_tree.getLeafSecret(leaf_index)
            self.assertIsNotNone(leaf_secret)

    def test_get_handshake_keys(self):
        # Verify handshake keys
        for leaf_index in range(self.num_leaves):
            handshake_key, handshake_nonce = self.secret_tree.getHandshakeKeys(leaf_index, self.epoch)
            self.assertEqual(len(handshake_key), 32)  # Handshake key should be 32 bytes
            self.assertEqual(len(handshake_nonce), 32)  # Handshake nonce should be 32 bytes

    def test_get_application_keys(self):
        # Verify application keys
        for leaf_index in range(self.num_leaves):
            application_key, application_nonce = self.secret_tree.getApplicationKeys(leaf_index, self.epoch)
            self.assertEqual(len(application_key), 32)  # Application key should be 32 bytes
            self.assertEqual(len(application_nonce), 32)  # Application nonce should be 32 bytes


if __name__ == "__main__":
    unittest.main()
