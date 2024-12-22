from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from typing import Optional
from .TranscriptHashManager import TranscriptHashManager  # Centralized manager

DEBUG = False
class KeySchedule:
    """
    Implements the key schedule for the Messaging Layer Security (MLS) protocol.
    This handles the derivation of secrets and keys for each epoch.
    """

    def __init__(self, initialSecret: bytes):
        """
        Initialize the key schedule with an initial secret.
        :param initialSecret: A byte string used as the initial input to the key schedule.
        """
        self.initSecret = initialSecret
        self.currentEpochSecret = None
        self.epoch = 0

    def deriveSecret(self, inputSecret: bytes, label: str, context: bytes, length: int = 32) -> bytes:
        hkdf_info = f"MLS 1.0 {label}".encode() + context
        if DEBUG:
            print(f"HKDF Info: {hkdf_info}")
            print(f"Input Secret: {inputSecret.hex()}")
        
        hkdf = HKDF(
            algorithm=SHA256(),
            length=length,
            salt=None,
            info=hkdf_info,
        )
        return hkdf.derive(inputSecret)


    def injectPreSharedKey(self, psk: bytes):
        """
        Inject a Pre-Shared Key (PSK) into the current key schedule.
        :param psk: The pre-shared key to inject.
        """
        if not isinstance(psk, bytes) or not psk:
            raise ValueError("PSK must be a non-empty bytes object")
        self.currentEpochSecret = self.deriveSecret(self.currentEpochSecret, "psk_secret", psk)

    def exportSecret(self, label: str, context: bytes, length: int = 32) -> bytes:
        """
        Export a derived secret for external protocols.
        :param label: Label for the derivation.
        :param context: Contextual information to bind the derivation.
        :param length: Length of the exported secret in bytes.
        :return: A byte string of the exported secret.
        """
        if not self.currentEpochSecret:
            raise ValueError("Key schedule is not initialized. Call `nextEpoch` first.")
        return self.deriveSecret(self.currentEpochSecret, f"exporter_{label}", context, length)

    def deriveEpochAuthenticator(self, confirmationKey: bytes) -> bytes:
        """
        Derive an epoch authenticator to bind the epoch state.
        :param confirmationKey: The confirmation key from the key schedule.
        :return: The epoch authenticator as bytes.
        """
        return self.deriveSecret(confirmationKey, "epoch_authenticator", b"")

    def nextEpoch(self, commitSecret: bytes, context: bytes, hashManager: TranscriptHashManager, psk: Optional[bytes] = None):
        """
        Derives the secrets for the next epoch using the commitSecret, context, and transcript hash.
        :param commitSecret: Fresh entropy introduced during the Commit phase.
        :param context: The group context (e.g., group ID, epoch, etc.).
        :param hashManager: The centralized transcript hash manager.
        :param psk: Optional pre-shared key to inject.
        """
        if commitSecret is None or not isinstance(commitSecret, bytes):
            raise ValueError("Invalid commitSecret: must be a non-empty bytes object")

        if self.currentEpochSecret is None:
            self.currentEpochSecret = self.initSecret

        # Retrieve the current transcript hash from the hash manager
        transcriptHash = hashManager.getCurrentHash()

        # Combine commitSecret, context, and transcriptHash for secret derivation
        combinedContext = commitSecret + context + transcriptHash

        # Derive new secrets for the next epoch
        self.currentEpochSecret = self.deriveSecret(
            self.currentEpochSecret, "epoch_secret", combinedContext
        )
        if psk:
            self.injectPreSharedKey(psk)

        self.encryptionSecret = self.deriveSecret(self.currentEpochSecret, "encryption_secret", context)
        self.authenticationSecret = self.deriveSecret(self.currentEpochSecret, "authentication_secret", context)
        self.exporterSecret = self.deriveSecret(self.currentEpochSecret, "exporter_secret", context)
        self.resumptionSecret = self.deriveSecret(self.currentEpochSecret, "resumption_secret", context)
        self.confirmationKey = self.deriveSecret(self.currentEpochSecret, "confirmation_key", context)

        # Derive the epoch authenticator
        self.epochAuthenticator = self.deriveEpochAuthenticator(self.confirmationKey)

        self.epoch += 1

    def updateForCommit(self, commitSecret: bytes, context: bytes, hashManager: TranscriptHashManager, psk: Optional[bytes] = None):
        """
        Updates the key schedule for a new epoch after a commit.
        :param commitSecret: Secret derived from the Commit message.
        :param context: The updated group context.
        :param hashManager: The centralized transcript hash manager.
        :param psk: Optional pre-shared key to inject.
        """
        self.nextEpoch(commitSecret, context, hashManager, psk)

    def getEpochSecrets(self) -> dict:
        """
        Returns the secrets for the current epoch.
        :return: A dictionary of derived secrets.
        """
        if not self.currentEpochSecret:
            raise ValueError("Key schedule is not initialized. Call `nextEpoch` to initialize.")

        return {
            "epochSecret": self.currentEpochSecret.hex(),
            "encryptionSecret": self.encryptionSecret.hex(),
            "authenticationSecret": self.authenticationSecret.hex(),
            "exporterSecret": self.exporterSecret.hex(),
            "resumptionSecret": self.resumptionSecret.hex(),
            "confirmationKey": self.confirmationKey.hex(),
            "epochAuthenticator": self.epochAuthenticator.hex(),
        }
