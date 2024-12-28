from cryptography.hazmat.primitives.hashes import Hash, SHA256
import json

DEBUG = False

class TranscriptHashManager:
    """
    Manages the transcript hash for the group state, ensuring consistency across components.
    """

    def __init__(self):
        """
        Initialize the hash manager with a zeroed hash.
        """
        hasher = Hash(SHA256())
        hasher.update(b"")
        self.currentHash = hasher.finalize()
        if DEBUG:
            print(f"Initialized currentHash: {self.currentHash.hex()}")

    def updateHash(self, serializedState: bytes) -> bytes:
        """
        Updates the transcript hash by hashing the current hash and the provided state.

        :param serializedState: Serialized representation of the updated group state.
        :return: The new transcript hash.
        """
        hasher = Hash(SHA256())
        hasher.update(self.currentHash)
        hasher.update(serializedState)
        newHash = hasher.finalize()
        
        if DEBUG:
            print(f"[updateHash] Current Hash Before: {self.currentHash.hex()}")
            print(f"[updateHash] Serialized State: {serializedState}")
            print(f"[updateHash] New Hash: {newHash.hex()}")

        self.currentHash = newHash
        return self.currentHash


    def getCurrentHash(self) -> bytes:
        """
        Returns the current transcript hash.

        :return: The current transcript hash.
        """
        return self.currentHash

    def validateStateConsistency(self, serializedState: bytes, expectedHash: bytes, baseHash: bytes) -> bool:
        """
        Validates the provided state against the expected hash value.

        :param serializedState: Serialized representation of the state to validate.
        :param expectedHash: The expected transcript hash to compare against.
        :param baseHash: The base hash to use for validation (before the update).
        :return: True if the hash matches, False otherwise.
        """
        tempHasher = Hash(SHA256())
        tempHasher.update(baseHash)
        tempHasher.update(serializedState)
        calculatedHash = tempHasher.finalize()

        if DEBUG:
            print(f"[validateStateConsistency] Base Hash: {baseHash.hex()}")
            print(f"[validateStateConsistency] Serialized State: {serializedState}")
            print(f"[validateStateConsistency] Calculated Hash: {calculatedHash.hex()}")
            print(f"[validateStateConsistency] Expected Hash: {expectedHash.hex()}")

        return calculatedHash == expectedHash


    def serializeState(self, state: dict) -> bytes:
        """
        Serializes a dictionary state into JSON format for hashing purposes.

        :param state: The dictionary representing the group state.
        :return: A JSON-formatted byte string.
        """
        try:
            serialized = json.dumps(state, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if DEBUG:
                print(f"Serialized state: {serialized}")
            return serialized
        except Exception as e:
            if DEBUG:
                print(f"Error during state serialization: {e}")
            raise
