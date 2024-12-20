from cryptography.hazmat.primitives.hashes import Hash, SHA256

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
        self.currentHash = hasher.finalize()
        return self.currentHash

    def getCurrentHash(self) -> bytes:
        """
        Returns the current transcript hash.
        :return: The current transcript hash.
        """
        return self.currentHash


