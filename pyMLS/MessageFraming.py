import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag


class MessageFraming:
    """
    Implements message framing, encryption, and authentication for the MLS protocol.
    """

    def __init__(self, encryptionSecret: bytes, authenticationSecret: bytes):
        """
        Initializes the message framing component.
        :param encryptionSecret: Secret used for message encryption.
        :param authenticationSecret: Secret used for signing messages.
        """
        self.encryptionSecret = bytes.fromhex(encryptionSecret)
        self.authenticationSecret = bytes.fromhex(authenticationSecret)

    def encryptMessage(self, plaintext: bytes, groupId: bytes, epoch: int) -> bytes:
        """
        Encrypts a message using the encryption secret and AES-GCM.
        :param plaintext: The message to encrypt.
        :param groupId: The group ID for context binding.
        :param epoch: The epoch number for key derivation.
        :return: The encrypted message (nonce + ciphertext + authTag).
        """
        if not isinstance(self.encryptionSecret, bytes):
            raise TypeError("encryptionSecret must be bytes-like")

        # Generate a random nonce
        nonce = os.urandom(12)

        # Derive the key
        key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=f"key_{epoch}".encode(),  # Ensure info is bytes
        ).derive(self.encryptionSecret)

        # AES-GCM encryption
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Concatenate nonce, ciphertext, and authTag
        encryptedMessage = nonce + ciphertext + encryptor.tag
        return encryptedMessage


    def decryptMessage(self, ciphertext: bytes, groupId: bytes, epoch: int) -> bytes:
        """
        Decrypts a message using the encryption secret and AES-GCM.
        :param ciphertext: The encrypted message (nonce + ciphertext + authTag).
        :param groupId: The group ID for context binding.
        :param epoch: The epoch number for key derivation.
        :return: Decrypted plaintext.
        """
        # Extract nonce, ciphertext, and authTag
        nonce = ciphertext[:12]
        authTag = ciphertext[-16:]
        encryptedMessage = ciphertext[12:-16]

        # Derive the key
        key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=f"key_{epoch}".encode(),
        ).derive(self.encryptionSecret)

        # AES-GCM decryption with error handling
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, authTag)).decryptor()
        try:
            plaintext = decryptor.update(encryptedMessage) + decryptor.finalize()
            return plaintext
        except InvalidTag:
            raise ValueError("Tampered ciphertext detected")

    def signMessage(self, plaintext: bytes) -> bytes:
        """
        Signs a message using the authentication secret.
        :param plaintext: The message to sign.
        :return: Signature.
        """
        signingKey = Ed25519PrivateKey.from_private_bytes(self.authenticationSecret)
        return signingKey.sign(plaintext)

    def verifySignature(self, plaintext: bytes, signature: bytes, publicKey: bytes) -> bool:
        """
        Verifies a message's signature.
        :param plaintext: The message whose signature is verified.
        :param signature: The signature to verify.
        :param publicKey: The public key used for verification (raw Ed25519 key).
        :return: True if valid, False otherwise.
        """
        try:
            verifierKey = Ed25519PublicKey.from_public_bytes(publicKey)
            verifierKey.verify(signature, plaintext)
            return True
        except Exception:
            return False

    def encryptProposal(self, proposal: object, groupId: bytes, epoch: int) -> bytes:
        """
        Encrypts a proposal for secure transmission.
        :param proposal: The proposal to encrypt.
        :param groupId: The group ID for context binding.
        :param epoch: The current epoch.
        :return: Encrypted proposal as bytes.
        """
        serializedProposal = proposal.serialize()
        return self.encryptMessage(serializedProposal, groupId, epoch)

    def decryptProposal(self, encryptedProposal: bytes, groupId: bytes, epoch: int) -> object:
        """
        Decrypts a received proposal.
        :param encryptedProposal: The encrypted proposal.
        :param groupId: The group ID for context binding.
        :param epoch: The current epoch.
        :return: Decrypted Proposal object.
        """
        decryptedProposal = self.decryptMessage(encryptedProposal, groupId, epoch)
        return eval(decryptedProposal.decode())  # Deserialize proposal

    def encryptCommit(self, commit: object, groupId: bytes, epoch: int) -> bytes:
        """
        Encrypts a commit for secure transmission.
        :param commit: The commit to encrypt.
        :param groupId: The group ID for context binding.
        :param epoch: The current epoch.
        :return: Encrypted commit as bytes.
        """
        serializedCommit = commit.serialize()
        return self.encryptMessage(serializedCommit, groupId, epoch)

    def decryptCommit(self, encryptedCommit: bytes, groupId: bytes, epoch: int) -> object:
        """
        Decrypts a received commit.
        :param encryptedCommit: The encrypted commit.
        :param groupId: The group ID for context binding.
        :param epoch: The current epoch.
        :return: Decrypted Commit object.
        """
        decryptedCommit = self.decryptMessage(encryptedCommit, groupId, epoch)
        return eval(decryptedCommit.decode())  # Deserialize commit

