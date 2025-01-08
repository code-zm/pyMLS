import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import hashes
from typing import List, Optional
from . import serialize

class KeyPackage:
    def __init__(
        self,
        version: int = None,
        cipherSuite: int = None,
        initKey: bytes = None,
        credential: bytes = None,
        leafNode: dict = None,
        extensions: List[bytes] = None,
        signature: Optional[bytes] = bytes(),
    ):
        self.version = version
        self.cipherSuite = cipherSuite
        self.initKey = initKey
        self.credential = credential
        self.leafNode = leafNode
        self.extensions = extensions
        self.signature = signature

    def serialize(self, nType=0) -> bytes:
        """
        Serialize the KeyPackage into binary format.
        """
        leafNodeSource = self.leafNode.get("leafNodeSource", "").encode("utf-8")
        signatureKey = self.leafNode.get("signatureKey", b"")

        stream = serialize.io_wrapper()
        stream.write(serialize.ser_int(self.version))
        stream.write(serialize.ser_int(self.cipherSuite))
        stream.write(serialize.ser_str(self.initKey))
        stream.write(serialize.ser_str(self.credential))
        stream.write(serialize.ser_str(leafNodeSource))
        stream.write(serialize.ser_str(signatureKey))
        stream.write(serialize.ser_str_list(self.extensions))
        if not(nType & serialize.SerType.SER_TBS):
            stream.write(serialize.ser_str(self.signature))
        return stream.getvalue()



    def deserialize(self, data: bytes, nType=0) -> "KeyPackage":
        """
        Deserialize binary data into a KeyPackage object.
        """
        stream = serialize.io_wrapper(data)
        self.version = serialize.deser_int(stream)
        self.cipherSuite = serialize.deser_int(stream)
        self.initKey = serialize.deser_str(stream)
        self.credential = serialize.deser_str(stream)
        leafNodeSource = serialize.deser_str(stream)
        signatureKey = serialize.deser_str(stream)
        self.extensions = serialize.deser_str_list(stream)
        if not(nType & serialize.SerType.SER_TBS):
            self.signature = serialize.deser_str(stream)
        self.leafNode = {"leafNodeSource": leafNodeSource.decode()}
        if signatureKey:
            self.leafNode["signatureKey"] = signatureKey
        return self


    def sign(self, privateKey: Ed25519PrivateKey):
        """
        Sign the serialized "to-be-signed" portion of the KeyPackage.
        """
        serializedTBS = self.serialize(serialize.SerType.SER_TBS)  # Serialized data to be signed
        self.signature = privateKey.sign(serializedTBS)

    def validateSignature(self, publicKey: Ed25519PublicKey) -> bool:
        """
        Validate the signature of the KeyPackage.
        """
        if not self.signature:
            raise ValueError("KeyPackage has no signature to validate.")

        serializedTBS = self.serialize(serialize.SerType.SER_TBS)
        try:
            publicKey.verify(self.signature, serializedTBS)
            return True
        except Exception:
            return False

    def __eq__(self, other):
        return (
            self.version == other.version and
            self.cipherSuite == other.cipherSuite and
            self.initKey == other.initKey and
            self.credential == other.credential and
            self.leafNode == other.leafNode and
            self.extensions == other.extensions and
            self.signature == other.signature
        )

    def __ne__(self, other):
        return not self.__eq__(other)