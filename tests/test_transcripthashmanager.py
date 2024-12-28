import unittest
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from pyMLS.TranscriptHashManager import TranscriptHashManager


class TestTranscriptHashManager(unittest.TestCase):
    def setUp(self):
        """
        Initialize the TranscriptHashManager before each test.
        """
        self.hashManager = TranscriptHashManager()
        self.sampleState1 = {"group_id": 1, "epoch": 1}
        self.sampleState2 = {"group_id": 1, "epoch": 2}

    def test_initialization(self):
        """
        Test the initial state of the transcript hash.
        """
        initialHash = self.hashManager.getCurrentHash()
        self.assertIsInstance(initialHash, bytes)
        # Compare with manually computed empty SHA256 hash
        emptyHash = Hash(SHA256())
        emptyHash.update(b"")
        self.assertEqual(initialHash, emptyHash.finalize())

    def test_update_hash(self):
        """
        Test updating the transcript hash with a serialized state.
        """
        serializedState = self.hashManager.serializeState(self.sampleState1)
        updatedHash = self.hashManager.updateHash(serializedState)
        currentHash = self.hashManager.getCurrentHash()
        self.assertEqual(updatedHash, currentHash)  # Verify that the updated hash matches the current hash
        self.assertNotEqual(currentHash, Hash(SHA256()).finalize())  # Ensure it’s not the initial empty hash


    def test_validate_state_consistency(self):
        """
        Test validating state consistency with an expected hash.
        """
        serializedState = self.hashManager.serializeState(self.sampleState1)
        baseHash = self.hashManager.getCurrentHash()  # Get the initial hash
        expectedHash = self.hashManager.updateHash(serializedState)

        # Validate state consistency using the base hash
        isValid = self.hashManager.validateStateConsistency(serializedState, expectedHash, baseHash)
        self.assertTrue(isValid, "State consistency validation failed with correct hash.")

        # Validate incorrect hash
        wrongHash = b"\x00" * 32
        isValid = self.hashManager.validateStateConsistency(serializedState, wrongHash, baseHash)
        self.assertFalse(isValid, "State consistency validation passed with incorrect hash.")


    def test_serialize_state(self):
        """
        Test serializing a state dictionary.
        """
        serializedState = self.hashManager.serializeState(self.sampleState1)
        self.assertIsInstance(serializedState, bytes)
        self.assertEqual(serializedState, b'{"group_id":1,"epoch":1}')

        # Test with another state
        serializedState2 = self.hashManager.serializeState(self.sampleState2)
        self.assertEqual(serializedState2, b'{"group_id":1,"epoch":2}')


if __name__ == "__main__":
    unittest.main()
