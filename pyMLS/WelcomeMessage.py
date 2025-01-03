import os
import struct
from typing import Dict, Any
from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption, Encoding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from .KeyPackage import KeyPackage


class WelcomeMessage:
    """
    Handles Welcome messages for new members in the MLS protocol.
    """

    def __init__(self, groupContext: bytes, ratchetTree, keySchedule, groupVersion: int, groupCipherSuite: int):
        self.groupContext = groupContext
        self.ratchetTree = ratchetTree
        self.keySchedule = keySchedule
        self.groupVersion = groupVersion
        self.groupCipherSuite = groupCipherSuite

    def hpke_encrypt(self, recipient_public_key_bytes: bytes, plaintext: bytes, aad: bytes = b"") -> (bytes, bytes):
        """
        Encrypt a plaintext using HPKE.
        :param recipient_public_key_bytes: Recipient's public key in raw format.
        :param plaintext: The plaintext to encrypt.
        :param aad: Additional authenticated data.
        :return: (ephemeral_public_key, ciphertext)
        """
        # Generate ephemeral key pair
        ephemeral_private_key = X25519PrivateKey.generate()
        ephemeral_public_key = ephemeral_private_key.public_key()

        # Load recipient's public key
        recipient_public_key = X25519PublicKey.from_public_bytes(recipient_public_key_bytes)

        # Perform Diffie-Hellman key exchange
        shared_secret = ephemeral_private_key.exchange(recipient_public_key)

        # Derive key and nonce
        hkdf = HKDF(algorithm=SHA256(), length=32 + 12, salt=None, info=b"hpke-context")
        key_and_nonce = hkdf.derive(shared_secret)
        encryption_key = key_and_nonce[:32]
        nonce = key_and_nonce[32:]

        # Encrypt plaintext
        aesgcm = AESGCM(encryption_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Return ephemeral public key and ciphertext
        return ephemeral_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw), ciphertext

    def hpke_decrypt(self, recipient_private_key: X25519PrivateKey, ephemeral_public_key_bytes: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt a ciphertext using HPKE.
        :param recipient_private_key: Recipient's private key object.
        :param ephemeral_public_key_bytes: Ephemeral public key sent by the sender.
        :param ciphertext: The ciphertext to decrypt.
        :param aad: Additional authenticated data.
        :return: The decrypted plaintext.
        """
        # Load ephemeral public key
        ephemeral_public_key = X25519PublicKey.from_public_bytes(ephemeral_public_key_bytes)

        # Perform Diffie-Hellman key exchange
        shared_secret = recipient_private_key.exchange(ephemeral_public_key)

        # Derive key and nonce
        hkdf = HKDF(algorithm=SHA256(), length=32 + 12, salt=None, info=b"hpke-context")
        key_and_nonce = hkdf.derive(shared_secret)
        encryption_key = key_and_nonce[:32]
        nonce = key_and_nonce[32:]

        # Decrypt ciphertext
        aesgcm = AESGCM(encryption_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

        return plaintext

    def createWelcome(self, keyPackage: KeyPackage) -> Dict[str, Any]:
        """
        Creates a Welcome message for a new member using their KeyPackage.
        """
        if not isinstance(keyPackage, KeyPackage):
            raise ValueError("createWelcome requires a valid KeyPackage.")

        if keyPackage.version != self.groupVersion or keyPackage.cipherSuite != self.groupCipherSuite:
            raise ValueError("KeyPackage version or cipher suite mismatch.")

        publicRatchetTree = self.ratchetTree.getPublicState()

        # Derive group secret (randomly generated)
        groupSecret = os.urandom(32)

        # Encrypt groupSecret using HPKE
        ephemeral_public_key, encryptedGroupSecrets = self.hpke_encrypt(
            recipient_public_key_bytes=keyPackage.initKey,
            plaintext=groupSecret
        )

        # Use groupSecret to derive joinerSecret
        joinerSecret = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"mls-joiner-secret"
        ).derive(groupSecret)

        # Derive symmetric encryption key and nonce for epochSecret
        epochSecret = self.keySchedule.getEpochSecrets()["epochSecret"]
        aesgcm = AESGCM(joinerSecret[:16])
        nonce = joinerSecret[16:28]
        encryptedEpochSecret = aesgcm.encrypt(nonce, epochSecret, self.groupContext)

        welcomeMessage = {
            "groupContext": self.groupContext,
            "encryptedGroupSecrets": ephemeral_public_key + encryptedGroupSecrets,
            "encryptedEpochSecret": nonce + encryptedEpochSecret,
            "publicRatchetTree": publicRatchetTree,
            "keyPackage": keyPackage.serialize(),
        }
        return welcomeMessage

    def processWelcome(self, welcomeMessage: Dict[str, Any], privateKey: X25519PrivateKey):
        """
        Processes a Welcome message to initialize the new member's state.
        """
        encryptedGroupSecrets = welcomeMessage["encryptedGroupSecrets"]
        ephemeral_public_key = encryptedGroupSecrets[:32]
        ciphertext = encryptedGroupSecrets[32:]

        # Decrypt groupSecret using HPKE
        groupSecret = self.hpke_decrypt(
            recipient_private_key=privateKey,
            ephemeral_public_key_bytes=ephemeral_public_key,
            ciphertext=ciphertext,
        )

        # Derive joinerSecret from groupSecret
        joinerSecret = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"mls-joiner-secret"
        ).derive(groupSecret)

        # Derive symmetric decryption key and nonce from joinerSecret
        aesgcm = AESGCM(joinerSecret[:16])
        nonce = joinerSecret[16:28]

        # Decrypt epochSecret
        encryptedEpochSecret = welcomeMessage["encryptedEpochSecret"]
        extractedNonce = encryptedEpochSecret[:12]
        ciphertext = encryptedEpochSecret[12:]

        if extractedNonce != nonce:
            raise ValueError("Nonce mismatch during decryption.")

        epochSecret = aesgcm.decrypt(nonce, ciphertext, self.groupContext)

        # Update the key schedule with the decrypted epochSecret
        self.keySchedule.currentEpochSecret = epochSecret

        # Sync the ratchet tree with the provided public state
        self.ratchetTree.syncTree(welcomeMessage["publicRatchetTree"])

    def serializeBinary(self, welcomeMessage: Dict[str, Any]) -> bytes:
        """
        Serialize the WelcomeMessage to binary format.
        """
        groupContextLen = len(welcomeMessage["groupContext"])
        secretsLen = len(welcomeMessage["encryptedGroupSecrets"])
        epochSecretLen = len(welcomeMessage["encryptedEpochSecret"])
        publicTreeBytes = b''.join(welcomeMessage["publicRatchetTree"])
        keyPackageBytes = welcomeMessage["keyPackage"]

        return struct.pack(
            f"!I{groupContextLen}sI{secretsLen}sI{epochSecretLen}sI{len(publicTreeBytes)}s{len(keyPackageBytes)}s",
            groupContextLen,
            welcomeMessage["groupContext"],
            secretsLen,
            welcomeMessage["encryptedGroupSecrets"],
            epochSecretLen,
            welcomeMessage["encryptedEpochSecret"],
            len(publicTreeBytes),
            publicTreeBytes,
            keyPackageBytes,
        )

    @staticmethod
    def deserializeBinary(data: bytes) -> Dict[str, Any]:
        """
        Deserialize binary data into a WelcomeMessage dictionary.
        """
        offset = 0

        groupContextLen = struct.unpack("!I", data[offset:offset + 4])[0]
        offset += 4
        groupContext = data[offset:offset + groupContextLen]
        offset += groupContextLen

        secretsLen = struct.unpack("!I", data[offset:offset + 4])[0]
        offset += 4
        encryptedGroupSecrets = data[offset:offset + secretsLen]
        offset += secretsLen

        epochSecretLen = struct.unpack("!I", data[offset:offset + 4])[0]
        offset += 4
        encryptedEpochSecret = data[offset:offset + epochSecretLen]
        offset += epochSecretLen

        publicTreeLen = struct.unpack("!I", data[offset:offset + 4])[0]
        offset += 4
        publicRatchetTree = [
            data[offset + i:offset + i + 32]
            for i in range(0, publicTreeLen, 32)
        ]
        offset += publicTreeLen

        keyPackageBytes = data[offset:]
        keyPackage = KeyPackage.deserialize(keyPackageBytes)

        return {
            "groupContext": groupContext,
            "encryptedGroupSecrets": encryptedGroupSecrets,
            "encryptedEpochSecret": encryptedEpochSecret,
            "publicRatchetTree": publicRatchetTree,
            "keyPackage": keyPackage,
        }


