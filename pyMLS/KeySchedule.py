from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from typing import Optional
from .TranscriptHashManager import TranscriptHashManager
from .SecretTree import SecretTree


class KeySchedule:
    """
    Implements the MLS Key Schedule as per RFC 9420.
    Manages secret derivations for epoch transitions and integrates SecretTree for encryption secrets.
    """

    def __init__(self, initialSecret: bytes):
        """
        Initialize the KeySchedule with an initial secret.
        :param initialSecret: The initial secret for the group.
        """
        self.initSecret = initialSecret
        self.currentEpochSecret = None
        self.encryptionSecret = None
        self.authenticationSecret = None
        self.exporterSecret = None
        self.resumptionSecret = None
        self.confirmationKey = None
        self.epochAuthenticator = None
        self.secretTree = None  # SecretTree instance
        self.epoch = 0  # Current epoch

    def deriveSecret(self, secret: bytes, label: str, context: Optional[bytes] = b"") -> bytes:
        """
        Derive a new secret using HKDF-Expand-Label as per RFC 9420.
        :param secret: The input secret for derivation.
        :param label: The label to include in the HKDF info field.
        :param context: Optional context for derivation.
        :return: The derived secret.
        """
        info = f"MLS 1.0 {label}".encode() + context
        hkdf = HKDF(
            algorithm=SHA256(),
            length=32,  # Default length for secrets in MLS
            salt=None,
            info=info,
        )
        return hkdf.derive(secret)

    def deriveEpochAuthenticator(self, confirmationKey: bytes) -> bytes:
        """
        Derive the epoch authenticator using the confirmation key.
        :param confirmationKey: The confirmation key for the epoch.
        :return: The epoch authenticator.
        """
        return self.deriveSecret(confirmationKey, "epoch_authenticator")

    def injectPreSharedKey(self, psk: bytes):
        """
        Inject a pre-shared key into the current epoch secret.
        :param psk: The pre-shared key to be injected.
        """
        if self.currentEpochSecret is None:
            raise ValueError("Current epoch secret is not set.")
        self.currentEpochSecret = self.deriveSecret(self.currentEpochSecret, "psk_secret", psk)

    def initializeSecretTree(self, numLeaves: int):
        """
        Initialize the SecretTree for the current epoch.
        :param numLeaves: Number of leaves in the group.
        """
        if not self.encryptionSecret:
            raise ValueError("Encryption secret must be derived before initializing the SecretTree.")
        self.secretTree = SecretTree(numLeaves, self.encryptionSecret)

    def getLeafSecrets(self, leafIndex: int, epoch: int):
        """
        Retrieve the handshake and application secrets for a specific leaf.
        :param leafIndex: Leaf index of the member.
        :param epoch: Current epoch.
        :return: A dictionary of derived secrets.
        """
        if not self.secretTree:
            raise ValueError("SecretTree is not initialized.")
        
        handshakeKey, handshakeNonce = self.secretTree.getHandshakeKeys(leafIndex, epoch)
        applicationKey, applicationNonce = self.secretTree.getApplicationKeys(leafIndex, epoch)
        return {
            "handshakeKey": handshakeKey,
            "handshakeNonce": handshakeNonce,
            "applicationKey": applicationKey,
            "applicationNonce": applicationNonce,
        }

    def exportSecret(self, label: str, context: bytes) -> bytes:
        """
        Derive an exportable secret using the exporterSecret.
        :param label: A label for the export operation.
        :param context: Additional context for derivation.
        :return: An exported secret.
        """
        if self.exporterSecret is None:
            raise ValueError("exporterSecret is not initialized.")
        return self.deriveSecret(self.exporterSecret, f"exporter_{label}", context)

    def getEpochSecrets(self) -> dict:
        """
        Return a dictionary containing all secrets for the current epoch.
        :return: A dictionary of secrets.
        """
        return {
            "epochSecret": self.currentEpochSecret,
            "encryptionSecret": self.encryptionSecret,
            "authenticationSecret": self.authenticationSecret,
            "exporterSecret": self.exporterSecret,
            "resumptionSecret": self.resumptionSecret,
            "confirmationKey": self.confirmationKey,
            "epochAuthenticator": self.epochAuthenticator,
        }

    def updateForCommit(self, commitSecret: bytes, context: bytes, hashManager: TranscriptHashManager, psk: Optional[bytes] = None, numLeaves: int = 1):
        """
        Update the key schedule for a commit.
        :param commitSecret: Fresh entropy from the Commit.
        :param context: The group context.
        :param hashManager: Transcript hash manager.
        :param psk: Optional pre-shared key.
        :param numLeaves: Number of leaves in the group.
        """
        if numLeaves <= 0:
            raise ValueError("numLeaves must be greater than 0.")
        self.nextEpoch(commitSecret, context, hashManager, psk, numLeaves)


    def nextEpoch(self, commitSecret: bytes, context: bytes, hashManager: TranscriptHashManager, psk: Optional[bytes] = None, numLeaves: int = 1):
        """
        Derives the secrets for the next epoch using the commitSecret, context, and transcript hash.
        Initializes the SecretTree for message encryption.
        :param commitSecret: Fresh entropy introduced during the Commit phase.
        :param context: The group context (e.g., group ID, epoch, etc.).
        :param hashManager: The centralized transcript hash manager.
        :param psk: Optional pre-shared key to inject.
        :param numLeaves: Number of leaves in the group (used for SecretTree initialization).
        """
        if numLeaves <= 0:
            raise ValueError("numLeaves must be greater than 0.")

        if commitSecret is None or not isinstance(commitSecret, bytes):
            raise ValueError("Invalid commitSecret: must be a non-empty bytes object.")

        if self.currentEpochSecret is None:
            self.currentEpochSecret = self.initSecret

        transcriptHash = hashManager.getCurrentHash()
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

        self.epochAuthenticator = self.deriveEpochAuthenticator(self.confirmationKey)

        # Initialize the SecretTree for this epoch
        self.initializeSecretTree(numLeaves)

        self.epoch += 1
