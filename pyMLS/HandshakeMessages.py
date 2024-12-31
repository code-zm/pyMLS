import struct
from typing import List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .KeyPackage import KeyPackage
from .HandshakeTypes import HandshakeType

DEBUG = True

class SerializationUtils:
    @staticmethod
    def packLengthPrefixed(data: bytes) -> bytes:
        return struct.pack(f"!H{len(data)}s", len(data), data)

    @staticmethod
    def unpackLengthPrefixed(data: bytes, offset: int):
        length = struct.unpack("!H", data[offset:offset + 2])[0]
        start = offset + 2
        value = data[start:start + length]
        return value, start + length

class HandshakeMessage:
    def __init__(self, messageType: HandshakeType, payload: bytes):
        self.messageType = messageType
        self.payload = payload

    def serializeBinary(self) -> bytes:
        payloadLength = len(self.payload)
        return struct.pack(f"!B{payloadLength}s", self.messageType.value, self.payload)

    @staticmethod
    def deserializeBinary(data: bytes) -> "HandshakeMessage":
        messageType = HandshakeType(struct.unpack("!B", data[:1])[0])
        payload = data[1:]
        return HandshakeMessage(messageType, payload)

class Add:
    def __init__(self, keyPackage: KeyPackage):
        self.keyPackage = keyPackage

    def serializeBinary(self) -> bytes:
        serialized = self.keyPackage.serialize()
        if DEBUG:
            print(f"Serializing Add: keyPackage={self.keyPackage}")
            print(f"[SERIALIZEDDATA]{serialized}")
        return serialized

    @staticmethod
    def deserializeBinary(data: bytes) -> "Add":
        keyPackage = KeyPackage.deserialize(data)
        if DEBUG:
            print(f"Deserializing Add: keyPackage={keyPackage}")
        return Add(keyPackage)

class Update:
    def __init__(self, keyPackage: KeyPackage):
        self.keyPackage = keyPackage

    def serializeBinary(self) -> bytes:
        serialized = self.keyPackage.serialize()
        if DEBUG:
            print(f"Serializing Update: keyPackage={self.keyPackage}")
            print(f"[SERIALIZEDDATA]{serialized}")
        return serialized

    @staticmethod
    def deserializeBinary(data: bytes) -> "Update":
        keyPackage = KeyPackage.deserialize(data)
        if DEBUG:
            print(f"Deserializing Update: keyPackage={keyPackage}")
        return Update(keyPackage)

class Remove:
    def __init__(self, removedIndex: int):
        self.removedIndex = removedIndex

    def serializeBinary(self) -> bytes:
        serialized = struct.pack("!I", self.removedIndex)
        if DEBUG:
            print(f"Serializing Remove: removedIndex={self.removedIndex}")
            print(f"[SERIALIZEDDATA]{serialized}")
        return serialized

    @staticmethod
    def deserializeBinary(data: bytes) -> "Remove":
        removedIndex = struct.unpack("!I", data[:4])[0]
        if DEBUG:
            print(f"Deserializing Remove: removedIndex={removedIndex}")
        return Remove(removedIndex)

class Commit:
    def __init__(self, proposals: List[HandshakeMessage], commitSecret: bytes, signature: bytes = None):
        self.proposals = proposals  # Keep as HandshakeMessage objects
        self.commitSecret = commitSecret
        self.signature = signature  # Optional

    def serializeBinary(self) -> bytes:
        serializedProposals = b"".join([SerializationUtils.packLengthPrefixed(p.serializeBinary()) for p in self.proposals])
        proposalsLength = len(serializedProposals)
        serializedData = struct.pack(f"!H{proposalsLength}s32s", proposalsLength, serializedProposals, self.commitSecret)
        if DEBUG:
            print(f"Serializing Commit: proposals={self.proposals}, commitSecret={self.commitSecret}")
            print(f"[SERIALIZEDDATA]{serializedData}")
        return serializedData

    @staticmethod
    def deserializeBinary(data: bytes) -> "Commit":
        proposalsLength = struct.unpack("!H", data[:2])[0]
        proposalsData = data[2:2 + proposalsLength]
        commitSecret = data[2 + proposalsLength:2 + proposalsLength + 32]

        proposals = []
        offset = 0
        while offset < proposalsLength:
            proposal, next_offset = SerializationUtils.unpackLengthPrefixed(proposalsData, offset)
            proposals.append(Add.deserializeBinary(proposal))  # Adjust for other message types if needed
            offset = next_offset

        if DEBUG:
            print(f"Deserializing Commit: proposals={proposals}, commitSecret={commitSecret}")
        return Commit(proposals, commitSecret)

    def sign(self, privateKey: Ed25519PrivateKey):
        """Signs the serialized Commit data using the provided Ed25519 private key."""
        serializedCommit = self.serializeBinary()
        self.signature = privateKey.sign(serializedCommit)
        if DEBUG:
            print(f"Commit signed successfully. Signature: {self.signature}")

    def verify(self, publicKey: Ed25519PublicKey) -> bool:
        """Verifies the Commit signature using the provided Ed25519 public key."""
        if not self.signature:
            raise ValueError("No signature available to verify.")
        serializedCommit = self.serializeBinary()
        try:
            publicKey.verify(self.signature, serializedCommit)
            if DEBUG:
                print("Commit signature verified successfully.")
            return True
        except Exception as e:
            if DEBUG:
                print(f"Commit signature verification failed: {e}")
            return False
