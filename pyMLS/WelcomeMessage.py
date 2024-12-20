import os
from typing import Dict, Any
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Proposals import AddProposal
from RatchetTree import RatchetTree
from KeySchedule import KeySchedule
from TranscriptHashManager import TranscriptHashManager
import json

DEBUG = False
class WelcomeMessage:
    """
    Handles Welcome messages for new members in the MLS protocol.
    """

    def __init__(self, groupContext: bytes, ratchetTree, keySchedule):
        """
        Initialize the WelcomeMessage handler.
        :param groupContext: Current group context (e.g., group ID, epoch, root hash).
        :param ratchetTree: RatchetTree instance to access group state.
        :param keySchedule: KeySchedule instance for deriving secrets.
        """
        self.groupContext = groupContext
        self.ratchetTree = ratchetTree
        self.keySchedule = keySchedule

    def createWelcome(self, newMemberPublicKey: bytes) -> Dict[str, Any]:
        """
        Creates a Welcome message for a new member.
        :param newMemberPublicKey: Public key of the new member (from their KeyPackage).
        :return: A dictionary representing the Welcome message.
        """
        # Validate the new member's public key
        if not isinstance(newMemberPublicKey, bytes) or len(newMemberPublicKey) != 32:
            raise ValueError("Invalid public key provided for new member.")

        # Serialize the full ratchet tree
        publicRatchetTree = self.ratchetTree.getPublicState()
        if DEBUG:
            print(f"Serialized full tree structure: {publicRatchetTree}")
            print(f"Serialized full tree size: {len(publicRatchetTree)} (Expected: {len(self.ratchetTree.tree)})")

        # Verify the serialized tree matches the expected size
        if len(publicRatchetTree) != len(self.ratchetTree.tree):
            raise ValueError("Serialized tree does not include all nodes in the binary tree.")

        # Derive a joiner_secret (simulated as random here for testing purposes)
        joinerSecret = os.urandom(32)

        # Derive the symmetric encryption key and nonce from the joiner_secret
        encryptionKey = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"welcome_encryption_key"
        ).derive(joinerSecret)

        nonce = HKDF(
            algorithm=SHA256(),
            length=12,
            salt=None,
            info=b"welcome_nonce"
        ).derive(joinerSecret)

        # Ensure the epochSecret and groupContext are bytes-like
        epochSecret = self.keySchedule.getEpochSecrets()["epochSecret"]
        groupContext = self.groupContext

        if not isinstance(epochSecret, bytes):
            epochSecret = bytes.fromhex(epochSecret)

        if not isinstance(groupContext, bytes):
            groupContext = groupContext.encode('utf-8')

        # Encrypt the epoch secret using the symmetric key
        aesGcm = AESGCM(encryptionKey)
        encryptedEpochSecret = aesGcm.encrypt(
            nonce,
            epochSecret,
            groupContext
        )

        # Simulate encrypted_group_secrets (would normally involve HPKE encryption)
        encryptedGroupSecrets = joinerSecret  # Placeholder for demonstration

        # Prepare and return the Welcome message
        welcomeMessage = {
            "groupContext": groupContext.hex(),
            "encryptedGroupSecrets": encryptedGroupSecrets.hex(),
            "encryptedEpochSecret": (nonce + encryptedEpochSecret).hex(),
            "publicRatchetTree": publicRatchetTree,
        }
        return welcomeMessage


    def processWelcome(self, welcomeMessage: Dict[str, bytes], privateKey: bytes) -> None:
        """
        Processes a Welcome message to initialize the new member's state.
        :param welcomeMessage: The received Welcome message.
        :param privateKey: Private key of the new member for decrypting the group secrets.
        """
        # Decrypt the joiner_secret from encrypted_group_secrets using private key
        encryptedGroupSecrets = welcomeMessage["encryptedGroupSecrets"]

        # Placeholder: Assume joiner_secret is simply the encryptedGroupSecrets for testing
        joinerSecret = encryptedGroupSecrets

        # Derive the symmetric decryption key and nonce from the joiner_secret
        encryptionKey = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"welcome_encryption_key"
        ).derive(joinerSecret)

        nonce = HKDF(
            algorithm=SHA256(),
            length=12,
            salt=None,
            info=b"welcome_nonce"
        ).derive(joinerSecret)

        # Extract the encrypted epoch secret
        encryptedData = welcomeMessage["encryptedEpochSecret"]
        extractedNonce = encryptedData[:12]
        ciphertext = encryptedData[12:]

        if extractedNonce != nonce:
            raise ValueError("Nonce mismatch between encryption and decryption.")

        # Decrypt the epoch secret
        aesGcm = AESGCM(encryptionKey)
        epochSecret = aesGcm.decrypt(nonce, ciphertext, welcomeMessage["groupContext"])

        # Update KeySchedule with the decrypted epoch secret
        self.keySchedule.currentEpochSecret = epochSecret

        # Sync the ratchet tree
        self.ratchetTree.syncTree(welcomeMessage["publicRatchetTree"])

        # Deserialize and process the AddProposal
        addProposalData = json.loads(welcomeMessage["addProposal"].decode())
        addProposal = AddProposal(publicKey=bytes.fromhex(addProposalData["publicKey"]))
        self.ratchetTree.addMember(addProposal.publicKey)

    def serialize(self) -> bytes:
        """
        Serializes the WelcomeMessage into JSON format.
        Recursively converts bytes to hex for JSON compatibility.
        """
        def convert_bytes(obj):
            if isinstance(obj, bytes):
                return obj.hex()
            elif isinstance(obj, list):
                return [convert_bytes(item) for item in obj]
            elif isinstance(obj, dict):
                return {key: convert_bytes(value) for key, value in obj.items()}
            else:
                return obj

        try:
            welcomeMessage = self.createWelcome(os.urandom(32))  # Generate a sample for serialization
            if DEBUG:
                print(f"Serialized publicRatchetTree size: {len(welcomeMessage['publicRatchetTree'])}")            
            serializedMessage = convert_bytes(welcomeMessage)
            return json.dumps(serializedMessage, ensure_ascii=False).encode("utf-8")
        except Exception as e:
            print(f"Error serializing WelcomeMessage: {e}")
            raise



    @staticmethod
    def deserialize(data: bytes) -> "WelcomeMessage":
        """
        Deserializes a WelcomeMessage from JSON format.
        """
        def convert_hex(obj):
            if isinstance(obj, str):
                try:
                    return bytes.fromhex(obj)
                except ValueError:
                    return obj
            elif isinstance(obj, list):
                return [convert_hex(item) for item in obj]
            elif isinstance(obj, dict):
                return {key: convert_hex(value) for key, value in obj.items()}
            else:
                return obj

        try:
            parsed = json.loads(data.decode("utf-8"))
            parsed = convert_hex(parsed)
            if DEBUG:
                print(f"Deserialized publicRatchetTree size: {len(parsed['publicRatchetTree'])}")

            groupContext = parsed["groupContext"]
            publicRatchetTree = parsed["publicRatchetTree"]
            encryptedGroupSecrets = parsed["encryptedGroupSecrets"]
            encryptedEpochSecret = parsed["encryptedEpochSecret"]

            # Correctly calculate numLeaves based on publicRatchetTree size
            totalNodes = len(publicRatchetTree)
            numLeaves = (totalNodes + 1) // 2  # For a complete binary tree, leaves = (nodes + 1) / 2

            # Initialize a valid hashManager
            hashManager = TranscriptHashManager()

            ratchetTree = RatchetTree(numLeaves=numLeaves, initialSecret=b"", hashManager=hashManager)
            ratchetTree.syncTree(publicRatchetTree)

            keySchedule = KeySchedule(initialSecret=b"")
            keySchedule.currentEpochSecret = encryptedGroupSecrets

            return WelcomeMessage(groupContext, ratchetTree, keySchedule)
        except Exception as e:
            print(f"Error deserializing WelcomeMessage: {e}")
            raise


