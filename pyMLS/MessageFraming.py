import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
from cryptography.exceptions import InvalidSignature
from .KeySchedule import KeySchedule
from . import serialize

DEBUG = False

class PublicMessage:
    def __init__(self, content: bytes = None, signature: bytes = None, groupId: bytes = None, epoch: int = None):
        self.content = content
        self.signature = signature
        self.groupId = groupId
        self.epoch = epoch

    def encode(self) -> bytes:
        stream = serialize.io_wrapper()
        stream.write(serialize.ser_str(self.content))
        stream.write(serialize.ser_str(self.signature))
        stream.write(serialize.ser_str(self.groupId))
        stream.write(serialize.ser_int(self.epoch))
        return stream.getvalue()

    def decode(self, encodedMessage: bytes):
        stream = serialize.io_wrapper(encodedMessage)
        self.content = serialize.deser_str(stream)
        self.signature = serialize.deser_str(stream)
        self.groupId = serialize.deser_str(stream)
        self.epoch = serialize.deser_int(stream)
        return self

    def __eq__(self, other):
        return (self.content == other.content and 
            self.signature == other.signature and
            self.groupId == other.groupId and
            self.epoch == other.epoch
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class PrivateMessage:
    def __init__(self, senderData: bytes = None, ciphertext: bytes = None, authTag: bytes = None):
        self.senderData = senderData
        self.ciphertext = ciphertext
        self.authTag = authTag

    def encode(self) -> bytes:
        stream = serialize.io_wrapper()
        stream.write(serialize.ser_str(self.senderData))
        stream.write(serialize.ser_str(self.ciphertext))
        stream.write(serialize.ser_str(self.authTag))
        return stream.getvalue()

    def decode(self, encodedMessage: bytes):
        stream = serialize.io_wrapper(encodedMessage)
        self.senderData = serialize.deser_str(stream)
        self.ciphertext = serialize.deser_str(stream)
        self.authTag = serialize.deser_str(stream)
        return self

    def __eq__(self, other):
        return (self.senderData == other.senderData and 
            self.ciphertext == other.ciphertext and
            self.authTag == other.authTag
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class MessageFraming:
    def __init__(self, keySchedule: KeySchedule, epoch: int, leafIndex: int):
        self.keySchedule = keySchedule
        self.epoch = epoch
        self.leafIndex = leafIndex

    def encryptSenderData(self, senderData: bytes, groupId: bytes) -> bytes:
        secrets = self.keySchedule.getLeafSecrets(self.leafIndex, self.epoch)
        key = secrets["handshakeKey"]
        nonce = secrets["handshakeNonce"]

        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        ciphertext = encryptor.update(senderData) + encryptor.finalize()
        return nonce + ciphertext + encryptor.tag

    def encryptMessage(self, plaintext: bytes, groupId: bytes) -> PrivateMessage:
        secrets = self.keySchedule.getLeafSecrets(self.leafIndex, self.epoch)
        key = secrets["applicationKey"]
        nonce = secrets["applicationNonce"]

        if DEBUG:
            print(f"[DEBUG] Encryption key: {key.hex()}, nonce: {nonce.hex()}")  # Debug

        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        authTag = encryptor.tag
        senderData = groupId + self.epoch.to_bytes(4, 'big') + nonce

        return PrivateMessage(senderData, ciphertext, authTag)

    def decryptMessage(self, privateMessage: PrivateMessage, groupId: bytes) -> bytes:
        # Extract sender data and metadata
        senderData = privateMessage.senderData
        parsedGroupId = senderData[:16]
        parsedEpoch = int.from_bytes(senderData[16:20], 'big')
        rawNonce = senderData[20:]

        if parsedGroupId != groupId or parsedEpoch != self.epoch:
            raise ValueError("Group ID or epoch mismatch during decryption")

        secrets = self.keySchedule.getLeafSecrets(self.leafIndex, self.epoch)
        key = secrets["applicationKey"]
        nonce = secrets["applicationNonce"]
        if DEBUG:
            print(f"[DEBUG] Decryption key: {key.hex()}, nonce: {nonce.hex()}")  # Debug

        ciphertext = privateMessage.ciphertext
        authTag = privateMessage.authTag

        try:
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, authTag)).decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag as e:
            raise ValueError(f"Decryption failed: {e}")


    def signMessage(self, plaintext: bytes, groupId: bytes) -> bytes:
        secrets = self.keySchedule.getLeafSecrets(self.leafIndex, self.epoch)
        signingKey = Ed25519PrivateKey.from_private_bytes(secrets["handshakeKey"])

        if DEBUG:
            print(f"[DEBUG] Signing key: {secrets['handshakeKey'].hex()}")  # Debug

        signed_data = groupId + self.epoch.to_bytes(4, 'big') + plaintext
        return signingKey.sign(signed_data)


    def verifySignature(self, publicMessage: PublicMessage, publicKey: bytes) -> bool:
        try:
            verifierKey = Ed25519PublicKey.from_public_bytes(publicKey)
            signed_data = publicMessage.groupId + publicMessage.epoch.to_bytes(4, 'big') + publicMessage.content

            if DEBUG:
                print(f"[DEBUG] Public key: {publicKey.hex()}")  # Debug

            verifierKey.verify(publicMessage.signature, signed_data)
            return True
        except InvalidSignature as e:
            raise ValueError(f"Signature verification failed: {e}")

    
    def createPublicMessage(self, content: bytes, groupId: bytes) -> PublicMessage:
        signature = self.signMessage(content, groupId)
        return PublicMessage(content, signature, groupId, self.epoch)

    def processPublicMessage(self, encodedMessage: bytes, publicKey: bytes) -> bool:
        publicMessage = PublicMessage()
        publicMessage.decode(encodedMessage)
        return self.verifySignature(publicMessage, publicKey)
