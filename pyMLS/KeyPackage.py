import json
from typing import Dict, Any, List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives import serialization

DEBUG = False

class KeyPackage:
    def __init__(self, version: int, cipherSuite: int, initKey: bytes, leafNode: Dict[str, Any], extensions: List[Any], privateKey: Ed25519PrivateKey = None):
        self.version = version
        self.cipherSuite = cipherSuite
        self.initKey = initKey
        self.leafNode = leafNode
        self.extensions = extensions
        self.signature = None

        if DEBUG:
            print(f"Initializing KeyPackage: version={self.version}, cipherSuite={self.cipherSuite}, initKey={self.initKey.hex()}")

        # Automatically sign if privateKey is provided
        if privateKey:
            if DEBUG:
                print("Signing KeyPackage with provided privateKey.")
            self.sign(privateKey)

    def serializeTbs(self) -> bytes:
        """
        Serialize the KeyPackageTBS (to-be-signed portion of the KeyPackage).
        """
        tbs = {
            "version": self.version,
            "cipherSuite": self.cipherSuite,
            "initKey": self.initKey.hex(),
            "leafNode": self.leafNode,
            "extensions": self.extensions,
        }
        if DEBUG:
            print(f"Serialized TBS: {tbs}")
        return json.dumps(tbs, ensure_ascii=False).encode("utf-8")

    def serialize(self) -> bytes:
        """
        Serialize the complete KeyPackage, including the signature.
        """
        data = {
            "version": self.version,
            "cipherSuite": self.cipherSuite,
            "initKey": self.initKey.hex(),
            "leafNode": self.leafNode,
            "extensions": self.extensions,
            "signature": self.signature.hex() if self.signature else None,
        }
        if DEBUG:
            print(f"Serialized KeyPackage: {data}")
        return json.dumps(data, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def deserialize(data: bytes) -> "KeyPackage":
        """
        Deserialize a KeyPackage from its serialized form.
        """
        obj = json.loads(data.decode("utf-8"))
        signature = bytes.fromhex(obj["signature"]) if obj["signature"] else None
        if DEBUG:
            print(f"Deserializing KeyPackage: {obj}")
        return KeyPackage(
            version=obj["version"],
            cipherSuite=obj["cipherSuite"],
            initKey=bytes.fromhex(obj["initKey"]),
            leafNode=obj["leafNode"],
            extensions=obj["extensions"],
            privateKey=None
        )

    def sign(self, privateKey: Ed25519PrivateKey):
        """
        Sign the KeyPackageTBS structure.
        """
        tbs = self.serializeTbs()
        self.signature = privateKey.sign(tbs)
        if DEBUG:
            print(f"Signed KeyPackage. Signature: {self.signature.hex()}")

    def validateSignature(self) -> bool:
        """
        Validate the KeyPackage signature using the public key from the credential.
        """
        if not self.signature:
            raise ValueError("KeyPackage is not signed.")
        publicKeyBytes = bytes.fromhex(self.leafNode["signatureKey"])
        publicKey = Ed25519PublicKey.from_public_bytes(publicKeyBytes)
        tbs = self.serializeTbs()
        if DEBUG:
            print(f"Validating signature. Public key: {publicKeyBytes.hex()}, TBS: {tbs}")
        try:
            publicKey.verify(self.signature, tbs)
            if DEBUG:
                print("Signature validation succeeded.")
            return True
        except Exception as e:
            if DEBUG:
                print(f"Signature validation failed: {e}")
            return False

    def validate(self, groupVersion: int, groupCipherSuite: int) -> bool:
        """
        Validate the KeyPackage according to RFC 9420.
        """
        if DEBUG:
            print(f"Validating KeyPackage. Group version: {groupVersion}, Group cipherSuite: {groupCipherSuite}")

        # Check protocol version and cipher suite
        if self.version != groupVersion or self.cipherSuite != groupCipherSuite:
            errorMessage = "Version or cipher suite mismatch."
            if DEBUG:
                print(errorMessage)
            raise ValueError(errorMessage)

        # Check that leafNode is valid
        if self.leafNode["leafNodeSource"] != "key_package":
            errorMessage = "Invalid leafNodeSource in KeyPackage."
            if DEBUG:
                print(errorMessage)
            raise ValueError(errorMessage)

        # Ensure encryptionKey differs from initKey
        if self.leafNode["encryptionKey"] == self.initKey.hex():
            errorMessage = "encryptionKey must differ from initKey."
            if DEBUG:
                print(errorMessage)
            raise ValueError(errorMessage)

        # Validate signature
        if not self.validateSignature():
            errorMessage = "Invalid KeyPackage signature."
            if DEBUG:
                print(errorMessage)
            raise ValueError(errorMessage)

        if DEBUG:
            print("KeyPackage validation succeeded.")
        return True
