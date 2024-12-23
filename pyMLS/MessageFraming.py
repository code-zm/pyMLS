import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag

class PublicMessage:
    def __init__(self, content: bytes, signature: bytes, group_id: bytes, epoch: int):
        self.content = content
        self.signature = signature
        self.group_id = group_id
        self.epoch = epoch

    def encode(self) -> bytes:
        return self.group_id + self.epoch.to_bytes(4, 'big') + self.signature + self.content

    @staticmethod
    def decode(encoded_message: bytes):
        group_id = encoded_message[:16]  # Assuming group_id is 16 bytes
        epoch = int.from_bytes(encoded_message[16:20], 'big')
        signature = encoded_message[20:84]  # Assuming Ed25519 signature is 64 bytes
        content = encoded_message[84:]
        return PublicMessage(content, signature, group_id, epoch)

class PrivateMessage:
    def __init__(self, sender_data: bytes, ciphertext: bytes, auth_tag: bytes):
        self.sender_data = sender_data
        self.ciphertext = ciphertext
        self.auth_tag = auth_tag

    def encode(self) -> bytes:
        sender_data_len = len(self.sender_data).to_bytes(4, 'big')  # Add sender_data length
        ciphertext_len = len(self.ciphertext).to_bytes(4, 'big')   # Add ciphertext length
        return sender_data_len + ciphertext_len + self.sender_data + self.ciphertext + self.auth_tag


    @staticmethod
    def decode(encoded_message: bytes):
        sender_data_len = int.from_bytes(encoded_message[:4], 'big')  # Extract sender_data length
        ciphertext_len = int.from_bytes(encoded_message[4:8], 'big')  # Extract ciphertext length

        sender_data_start = 8
        sender_data_end = sender_data_start + sender_data_len
        ciphertext_start = sender_data_end
        ciphertext_end = ciphertext_start + ciphertext_len

        sender_data = encoded_message[sender_data_start:sender_data_end]
        ciphertext = encoded_message[ciphertext_start:ciphertext_end]
        auth_tag = encoded_message[ciphertext_end:]  # Remaining is auth_tag

        return PrivateMessage(sender_data, ciphertext, auth_tag)

class MessageFraming:
    def __init__(self, encryption_secret: bytes, authentication_secret: bytes):
        self.encryption_secret = bytes.fromhex(encryption_secret)
        self.authentication_secret = bytes.fromhex(authentication_secret)

    def encrypt_sender_data(self, sender_data: bytes, group_id: bytes, epoch: int) -> bytes:
        key = HKDF(
            algorithm=SHA256(),
            length=16,
            salt=None,
            info=f"sender_data_{epoch}".encode()
        ).derive(self.encryption_secret)

        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        ciphertext = encryptor.update(sender_data) + encryptor.finalize()
        return nonce + ciphertext + encryptor.tag  # Concatenate components

    def encrypt_message(self, plaintext: bytes, group_id: bytes, epoch: int) -> PrivateMessage:
        key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=f"key_{epoch}".encode()
        ).derive(self.encryption_secret)

        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        auth_tag = encryptor.tag

        # Construct sender_data with metadata (e.g., group_id and epoch)
        sender_data = group_id + epoch.to_bytes(4, 'big') + nonce

        return PrivateMessage(sender_data, ciphertext, auth_tag)

    def decrypt_message(self, private_message: PrivateMessage, group_id: bytes, epoch: int) -> bytes:
        key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=f"key_{epoch}".encode()
        ).derive(self.encryption_secret)

        # Parse sender_data to extract metadata and nonce
        sender_data = private_message.sender_data
        parsed_group_id = sender_data[:16]  # Assuming group_id is 16 bytes
        parsed_epoch = int.from_bytes(sender_data[16:20], 'big')  # 4 bytes for epoch
        nonce = sender_data[20:]  # Remaining is nonce

        # Validate group_id and epoch
        if parsed_group_id != group_id or parsed_epoch != epoch:
            raise ValueError("Group ID or epoch mismatch during decryption")

        ciphertext = private_message.ciphertext
        auth_tag = private_message.auth_tag

        # Decrypt using extracted nonce and tag
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, auth_tag)).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()



    def sign_message(self, plaintext: bytes, group_id: bytes, epoch: int) -> bytes:
        signing_key = Ed25519PrivateKey.from_private_bytes(self.authentication_secret)
        return signing_key.sign(group_id + epoch.to_bytes(4, 'big') + plaintext)

    def verify_signature(self, public_message: PublicMessage, public_key: bytes, expected_group_id: bytes, expected_epoch: int) -> bool:
        try:
            # Validate group_id and epoch
            if public_message.group_id != expected_group_id or public_message.epoch != expected_epoch:
                raise ValueError("Group ID or epoch mismatch in public message")

            verifier_key = Ed25519PublicKey.from_public_bytes(public_key)
            verifier_key.verify(
                public_message.signature,
                public_message.group_id + public_message.epoch.to_bytes(4, 'big') + public_message.content
            )
            return True
        except Exception as e:
            raise ValueError(f"Public message verification failed: {e}")


    def create_public_message(self, content: bytes, group_id: bytes, epoch: int) -> PublicMessage:
        signature = self.sign_message(content, group_id, epoch)
        return PublicMessage(content, signature, group_id, epoch)

    def process_public_message(self, encoded_message: bytes, public_key: bytes) -> bool:
        public_message = PublicMessage.decode(encoded_message)
        return self.verify_signature(public_message, public_key)
