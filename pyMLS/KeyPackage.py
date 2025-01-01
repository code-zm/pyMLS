import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import hashes
from typing import List, Optional

class KeyPackage:
    def __init__(
        self,
        version: int,
        cipherSuite: int,
        initKey: bytes,
        credential: bytes,
        leafNode: dict,
        extensions: List[bytes],
        signature: Optional[bytes] = None,
    ):
        self.version = version
        self.cipherSuite = cipherSuite
        self.initKey = initKey
        self.credential = credential
        self.leafNode = leafNode
        self.extensions = extensions
        self.signature = signature

    def serialize(self) -> bytes:
        """
        Serialize the KeyPackage into binary format.
        """
        leafNodeSource = self.leafNode.get("leafNodeSource", "").encode("utf-8")
        signatureKey = self.leafNode.get("signatureKey", b"")

        serialized = struct.pack(
            f"!HB{len(self.initKey)}sH{len(self.credential)}sH{len(leafNodeSource)}sH{len(signatureKey)}sH",
            self.version,
            self.cipherSuite,
            self.initKey,
            len(self.credential),
            self.credential,
            len(leafNodeSource),
            leafNodeSource,
            len(signatureKey),
            signatureKey,
            len(self.extensions),
        )

        for ext in self.extensions:
            serialized += struct.pack(f"!H{len(ext)}s", len(ext), ext)

        if self.signature:
            serialized += struct.pack(f"!H{len(self.signature)}s", len(self.signature), self.signature)
        else:
            serialized += struct.pack("!H", 0)

        return serialized

    @staticmethod
    def deserialize(data: bytes) -> "KeyPackage":
        """
        Deserialize binary data into a KeyPackage object.
        """
        offset = 0

        try:
            version, cipherSuite = struct.unpack_from("!HB", data, offset)
            offset += 3

            initKeyLength = 32  # Assuming fixed size for initKey
            if len(data) < offset + initKeyLength:
                raise ValueError("Input data is too short for initKey.")

            initKey = struct.unpack_from(f"!{initKeyLength}s", data, offset)[0]
            offset += initKeyLength

            # Deserialize credential
            credentialLength = struct.unpack_from("!H", data, offset)[0]
            offset += 2
            if len(data) < offset + credentialLength:
                raise ValueError("Input data is too short for credential.")

            credential = data[offset:offset + credentialLength]
            offset += credentialLength

            # Deserialize leafNode
            leafNodeSourceLength = struct.unpack_from("!H", data, offset)[0]
            offset += 2
            if len(data) < offset + leafNodeSourceLength:
                raise ValueError("Input data is too short for leafNodeSource.")

            leafNodeSource = data[offset:offset + leafNodeSourceLength].decode("utf-8")
            offset += leafNodeSourceLength

            signatureKeyLength = struct.unpack_from("!H", data, offset)[0]
            offset += 2
            if len(data) < offset + signatureKeyLength:
                raise ValueError("Input data is too short for signatureKey.")

            signatureKey = data[offset:offset + signatureKeyLength]
            offset += signatureKeyLength

            # Deserialize extensions
            extensions = []
            extensionsLength = struct.unpack_from("!H", data, offset)[0]
            offset += 2
            for _ in range(extensionsLength):
                extLength = struct.unpack_from("!H", data, offset)[0]
                offset += 2
                if len(data) < offset + extLength:
                    raise ValueError("Input data is too short for extensions.")
                ext = data[offset:offset + extLength]
                offset += extLength
                extensions.append(ext)

            # Deserialize signature
            signatureLength = struct.unpack_from("!H", data, offset)[0]
            offset += 2
            signature = data[offset:offset + signatureLength] if signatureLength > 0 else None

            leafNode = {"leafNodeSource": leafNodeSource, "signatureKey": signatureKey}

            return KeyPackage(version, cipherSuite, initKey, credential, leafNode, extensions, signature)

        except struct.error as e:
            raise ValueError(f"Error deserializing KeyPackage: {e}")

    def serializeTbs(self) -> bytes:
        """
        Serialize the "to-be-signed" portion of the KeyPackage.
        """
        leafNodeSource = self.leafNode.get("leafNodeSource", "").encode("utf-8")
        signatureKey = self.leafNode.get("signatureKey", b"")

        # Ensure credential is in bytes
        if not isinstance(self.credential, bytes):
            raise TypeError(f"Credential must be bytes, got {type(self.credential)} instead.")

        serialized = struct.pack(
            f"!HB{len(self.initKey)}sH{len(self.credential)}sH{len(leafNodeSource)}sH{len(signatureKey)}sH",
            self.version,
            self.cipherSuite,
            self.initKey,
            len(self.credential),
            self.credential,
            len(leafNodeSource),
            leafNodeSource,
            len(signatureKey),
            signatureKey,
            len(self.extensions),
        )

        for ext in self.extensions:
            if not isinstance(ext, bytes):
                raise TypeError(f"Extension must be bytes, got {type(ext)} instead.")
            serialized += struct.pack(f"!H{len(ext)}s", len(ext), ext)

        return serialized

    def sign(self, privateKey: Ed25519PrivateKey):
        """
        Sign the serialized "to-be-signed" portion of the KeyPackage.
        """
        serializedTBS = self.serializeTbs()  # Serialized data to be signed
        self.signature = privateKey.sign(serializedTBS)

    def validateSignature(self, publicKey: Ed25519PublicKey) -> bool:
        """
        Validate the signature of the KeyPackage.
        """
        if not self.signature:
            raise ValueError("KeyPackage has no signature to validate.")

        serializedTBS = self.serializeTbs()
        try:
            publicKey.verify(self.signature, serializedTBS)
            return True
        except Exception:
            return False
