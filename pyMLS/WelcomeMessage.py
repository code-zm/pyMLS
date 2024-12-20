import os
from typing import Dict, Any
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .Proposals import AddProposal
from .RatchetTree import RatchetTree, Node
from .KeySchedule import KeySchedule
from .KeyPackage import KeyPackage
from .TranscriptHashManager import TranscriptHashManager
import json

DEBUG = False

class WelcomeMessage:
    """
    Handles Welcome messages for new members in the MLS protocol.
    """

    def __init__(self, groupContext: bytes, ratchetTree, keySchedule, groupVersion: int, groupCipherSuite: int, keyPackage: KeyPackage):
        """
        Initialize the WelcomeMessage handler.
        :param groupContext: Current group context (e.g., group ID, epoch, root hash).
        :param ratchetTree: RatchetTree instance to access group state.
        :param keySchedule: KeySchedule instance for deriving secrets.
        """
        self.groupContext = groupContext
        self.ratchetTree = ratchetTree
        self.keySchedule = keySchedule
        self.groupVersion = groupVersion
        self.groupCipherSuite = groupCipherSuite
        self.keyPackage = keyPackage
        

    def createWelcome(self, keyPackage: KeyPackage) -> Dict[str, Any]:
        """
        Creates a Welcome message for a new member using their KeyPackage.
        :param keyPackage: KeyPackage object for the new member.
        :return: A dictionary representing the Welcome message.
        """
        if not isinstance(keyPackage, KeyPackage):
            raise ValueError("createWelcome requires a valid KeyPackage.")

        # Use the group_version and group_cipher_suite from the WelcomeMessage instance
        keyPackage.validate(self.groupVersion, self.groupCipherSuite)

        # Serialize the full ratchet tree
        publicRatchetTree = self.ratchetTree.getPublicState()
        if DEBUG:
            print(f"Generated publicRatchetTree: {publicRatchetTree}")

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
            "keyPackage": keyPackage.serialize().decode("utf-8"),
        }
        return welcomeMessage


    def processWelcome(self, welcomeMessage: Dict[str, Any], privateKey: bytes):
        """
        Processes a Welcome message to initialize the new member's state.
        :param welcomeMessage: The received Welcome message as a dictionary.
        :param privateKey: Private key of the new member for decrypting the group secrets.
        """
        # Deserialize fields from the WelcomeMessage
        encryptedGroupSecrets = bytes.fromhex(welcomeMessage["encryptedGroupSecrets"])
        encryptedEpochSecret = bytes.fromhex(welcomeMessage["encryptedEpochSecret"])
        groupContext = bytes.fromhex(welcomeMessage["groupContext"])
        publicRatchetTree = welcomeMessage["publicRatchetTree"]

        # Placeholder: Simulate joinerSecret derivation for testing
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

        # Extract the actual nonce and ciphertext from the encrypted epoch secret
        extractedNonce = encryptedEpochSecret[:12]
        ciphertext = encryptedEpochSecret[12:]

        if extractedNonce != nonce:
            raise ValueError("Nonce mismatch between encryption and decryption.")

        # Decrypt the epoch secret
        aesGcm = AESGCM(encryptionKey)
        epochSecret = aesGcm.decrypt(nonce, ciphertext, groupContext)

        # Update the key schedule with the decrypted epoch secret
        self.keySchedule.currentEpochSecret = epochSecret

        # Sync the ratchet tree with the provided public state
        self.ratchetTree.syncTree(publicRatchetTree)

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
            if DEBUG:
                print("Serializing WelcomeMessage...")
            # Ensure that a valid KeyPackage is available
            if not isinstance(self.keyPackage, KeyPackage):
                raise ValueError("serialize requires a valid KeyPackage.")
            
            # Generate the WelcomeMessage using a properly initialized KeyPackage
            welcomeMessage = self.createWelcome(self.keyPackage)
            if DEBUG:
                print(f"Serialized publicRatchetTree: {welcomeMessage['publicRatchetTree']}")
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

            groupContext = parsed["groupContext"]
            encryptedGroupSecrets = parsed["encryptedGroupSecrets"]
            encryptedEpochSecret = parsed["encryptedEpochSecret"]

            # Correctly calculate numLeaves based on publicRatchetTree size
            publicRatchetTreeData = parsed["publicRatchetTree"]
            totalNodes = len(publicRatchetTreeData)
            numLeaves = (totalNodes + 1) // 2  # For a complete binary tree, leaves = (nodes + 1) / 2

            # Initialize a valid hashManager
            hashManager = TranscriptHashManager()

            # Create a new RatchetTree and reconstruct it from publicRatchetTreeData
            ratchetTree = RatchetTree(numLeaves=numLeaves, initialSecret=b"", hashManager=hashManager)
            ratchetTree.tree = [
                Node(publicKey=node["publicKey"]) if isinstance(node["publicKey"], bytes)
                else Node(publicKey=bytes.fromhex(node["publicKey"])) for node in publicRatchetTreeData
            ]

            keySchedule = KeySchedule(initialSecret=b"")
            keySchedule.currentEpochSecret = encryptedGroupSecrets

            return WelcomeMessage(
                groupContext=groupContext,
                ratchetTree=ratchetTree,
                keySchedule=keySchedule,
                groupVersion=parsed.get("groupVersion"),
                groupCipherSuite=parsed.get("groupCipherSuite"),
                keyPackage=None  # Placeholder: Adjust if keyPackage needs to be reconstructed
            )
        except Exception as e:
            print(f"Error deserializing WelcomeMessage: {e}")
            raise


