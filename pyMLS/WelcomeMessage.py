import os
import struct
from typing import Dict, Any
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from .KeyPackage import KeyPackage
from . import serialize

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

    def hpkeEncrypt(self, recipientPublicKeyBytes: bytes, plaintext: bytes, aad: bytes = b"") -> (bytes, bytes):
        """
        Encrypt a plaintext using HPKE.
        :param recipientPublicKeyBytes: Recipient's public key in raw format.
        :param plaintext: The plaintext to encrypt.
        :param aad: Additional authenticated data.
        :return: (ephemeralPublicKey, ciphertext)
        """
        # Generate ephemeral key pair
        ephemeralPrivateKey = X25519PrivateKey.generate()
        ephemeralPublicKey = ephemeralPrivateKey.public_key()

        # Load recipient's public key
        recipientPublicKey = X25519PublicKey.from_public_bytes(recipientPublicKeyBytes)

        # Perform Diffie-Hellman key exchange
        sharedSecret = ephemeralPrivateKey.exchange(recipientPublicKey)

        # Derive key and nonce
        hkdf = HKDF(algorithm=SHA256(), length=32 + 12, salt=None, info=b"hpke-context")
        keyAndNonce = hkdf.derive(sharedSecret)
        encryptionKey = keyAndNonce[:32]
        nonce = keyAndNonce[32:]

        # Encrypt plaintext
        aesgcm = AESGCM(encryptionKey)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Return ephemeral public key and ciphertext
        return ephemeralPublicKey.public_bytes(Encoding.Raw, PublicFormat.Raw), ciphertext

    def hpkeDecrypt(self, recipientPrivateKey: X25519PrivateKey, ephemeralPublicKeyBytes: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt a ciphertext using HPKE.
        :param recipientPrivateKey: Recipient's private key object.
        :param ephemeralPublicKeyBytes: Ephemeral public key sent by the sender.
        :param ciphertext: The ciphertext to decrypt.
        :param aad: Additional authenticated data.
        :return: The decrypted plaintext.
        """
        # Load ephemeral public key
        ephemeralPublicKey = X25519PublicKey.from_public_bytes(ephemeralPublicKeyBytes)

        # Perform Diffie-Hellman key exchange
        sharedSecret = recipientPrivateKey.exchange(ephemeralPublicKey)

        # Derive key and nonce
        hkdf = HKDF(algorithm=SHA256(), length=32 + 12, salt=None, info=b"hpke-context")
        keyAndNonce = hkdf.derive(sharedSecret)
        encryptionKey = keyAndNonce[:32]
        nonce = keyAndNonce[32:]

        # Decrypt ciphertext
        aesgcm = AESGCM(encryptionKey)
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
        ephemeralPublicKey, encryptedGroupSecrets = self.hpkeEncrypt(
            recipientPublicKeyBytes=keyPackage.initKey,
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
            "encryptedGroupSecrets": ephemeralPublicKey + encryptedGroupSecrets,
            "encryptedEpochSecret": nonce + encryptedEpochSecret,
            "publicRatchetTree": publicRatchetTree,
            "keyPackage": keyPackage.serialize(),
        }
        return welcomeMessage

    def serialize(self, welcomeMessage: Dict[str, Any]) -> bytes:
        """
        Serialize the WelcomeMessage to binary format.
        """
        stream = serialize.io_wrapper()
        stream.write(serialize.ser_str(welcomeMessage["groupContext"]))
        stream.write(serialize.ser_str(welcomeMessage["encryptedGroupSecrets"]))
        stream.write(serialize.ser_str(welcomeMessage["encryptedEpochSecret"]))
        stream.write(serialize.ser_str_list(welcomeMessage["publicRatchetTree"]))
        stream.write(serialize.ser_str(welcomeMessage["keyPackage"]))
        return stream.getvalue()


    @staticmethod
    def deserialize(data: bytes) -> Dict[str, Any]:
        """
        Deserialize binary data into a WelcomeMessage dictionary.
        """
        stream = serialize.io_wrapper(data)
        groupContext = serialize.deser_str(stream)
        encryptedGroupSecrets = serialize.deser_str(stream)
        encryptedEpochSecret = serialize.deser_str(stream)
        publicRatchetTree = serialize.deser_str_list(stream)
        keyPackageBytes = serialize.deser_str(stream)
        keyPackage = KeyPackage()
        keyPackage.deserialize(keyPackageBytes)

        return {
            "groupContext": groupContext,
            "encryptedGroupSecrets": encryptedGroupSecrets,
            "encryptedEpochSecret": encryptedEpochSecret,
            "publicRatchetTree": publicRatchetTree,
            "keyPackage": keyPackage,
        }

    def processWelcome(self, welcomeMessage: Dict[str, Any], privateKey: X25519PrivateKey):
        """
        Processes a Welcome message to initialize the new member's state.
        """
        encryptedGroupSecrets = welcomeMessage["encryptedGroupSecrets"]
        ephemeralPublicKey = encryptedGroupSecrets[:32]
        ciphertext = encryptedGroupSecrets[32:]

        # Decrypt groupSecret using HPKE
        groupSecret = self.hpkeDecrypt(
            recipientPrivateKey=privateKey,
            ephemeralPublicKeyBytes=ephemeralPublicKey,
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
