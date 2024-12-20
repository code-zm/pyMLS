from typing import List, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives import serialization
from pyMLS.KeySchedule import KeySchedule
from pyMLS.TranscriptHashManager import TranscriptHashManager  # New centralized manager

DEBUG = False
@dataclass
class Node:
    """Represents a node in the ratchet tree."""
    publicKey: Optional[bytes] = None
    privateKey: Optional[X25519PrivateKey] = None
    parentHash: Optional[bytes] = None


class RatchetTree:
    """
    Implements a binary ratchet tree for the MLS protocol.
    """

    def __init__(self, numLeaves: int, initialSecret: bytes, hashManager: TranscriptHashManager):
        """
        Initializes a ratchet tree with the specified number of leaves.
        :param numLeaves: Number of leaves (members) in the tree.
        :param initialSecret: Initial secret for the key schedule.
        :param hashManager: Centralized transcript hash manager.
        """
        if numLeaves < 1:
            raise ValueError("The tree must have at least one leaf.")
        self.numLeaves = numLeaves
        self.numNodes = 2 * numLeaves - 1
        self.tree: List[Node] = [Node() for _ in range(self.numNodes)]
        if DEBUG:
            print(f"Initialized RatchetTree with {len(self.tree)} nodes (numLeaves={numLeaves}, numNodes={self.numNodes})")
        self.keySchedule = KeySchedule(initialSecret)
        self.hashManager = hashManager
        self.initializeLeaves()
        self.computeParentHashes()

    def initializeLeaves(self):
        """Initializes the leaf nodes with private-public key pairs deterministically."""
        for i in range(self.numLeaves):
            self.createLeaf(i)
        # Do not call updateTranscriptHash here to avoid premature hash updates

    def createLeaf(self, leafIndex: int):
        """Creates a new leaf with a private-public key pair at the specified index."""
        privateKey = X25519PrivateKey.generate()
        publicKey = privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        nodeIndex = self.getNodeIndex(leafIndex)
        self.tree[nodeIndex].privateKey = privateKey
        self.tree[nodeIndex].publicKey = publicKey

    def getNodeIndex(self, leafIndex: int) -> int:
        """Maps a leaf index to the corresponding node index in the array representation."""
        return self.numLeaves - 1 + leafIndex

    def computeParentHashes(self):
        """Computes the parent hashes for all parent nodes in the tree."""
        for nodeIndex in range(self.numNodes - 1, 0, -2):
            parentIndex = (nodeIndex - 1) // 2
            leftChild = self.tree[nodeIndex - 1]
            rightChild = self.tree[nodeIndex]
            parent = self.tree[parentIndex]

            if leftChild.publicKey and rightChild.publicKey:
                hasher = Hash(SHA256())
                hasher.update(leftChild.publicKey)
                hasher.update(rightChild.publicKey)
                parent.parentHash = hasher.finalize()
            else:
                parent.parentHash = None

    def syncTree(self, publicTree: List[Optional[bytes]]):
        """
        Synchronizes the tree with a received public tree state.
        Ensures compatibility between publicTree and the full binary tree.
        """
        if DEBUG:
            print(f"Expected tree size: {len(self.tree)}, Received tree size: {len(publicTree)}")
        if len(publicTree) != len(self.tree):
            if DEBUG:
                print(f"Expected full tree structure: {self.getPublicState()}")
                print(f"Received partial tree structure: {publicTree}")
            raise ValueError("Public tree state size does not match the tree.")

        for i, publicKey in enumerate(publicTree):
            if DEBUG:
                print(f"Syncing node {i}: Received publicKey={publicKey}")
            self.tree[i].publicKey = publicKey

        # Ensure parent nodes are consistent
        self.computeParentHashes()
        self.updateTranscriptHash()

    def getPublicState(self) -> List[Optional[bytes]]:
        """
        Returns the public state of the tree for distribution to group members.
        Includes all nodes in the binary tree, even if they are None.
        """
        publicState = []
        for node in self.tree:
            if node.publicKey is not None:
                publicState.append(node.publicKey)
            else:
                publicState.append(None)  # Include placeholders for missing nodes
        return publicState

    def addMember(self, publicKey: Optional[bytes] = None):
        """
        Adds a new member to the ratchet tree.
        :param publicKey: Public key of the new member. If None, generates a new key.
        """
        if publicKey in [node.publicKey for node in self.tree if node.publicKey]:
            raise ValueError("The public key already exists in the tree.")

        newLeafIndex = self.numLeaves
        self.numLeaves += 1
        self.numNodes = 2 * self.numLeaves - 1

        # Extend the tree to accommodate new nodes
        while len(self.tree) < self.numNodes:
            self.tree.append(Node())

        # Add the new member as a leaf node
        newLeafNodeIndex = self.getNodeIndex(newLeafIndex)
        if publicKey is None:
            privateKey = X25519PrivateKey.generate()
            publicKey = privateKey.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            self.tree[newLeafNodeIndex].privateKey = privateKey
        self.tree[newLeafNodeIndex].publicKey = publicKey

        # Ensure parent hashes are consistent
        self.computeParentHashes()
        self.updateTranscriptHash()

    def removeMember(self, memberIndex: int):
        """Removes a member from the ratchet tree."""
        if memberIndex >= self.numLeaves or memberIndex < 0:
            raise ValueError("Member index out of range.")
        nodeIndex = self.getNodeIndex(memberIndex)
        if self.tree[nodeIndex].publicKey is None:
            raise ValueError("Cannot remove a non-existent member.")
        self.tree[nodeIndex].publicKey = None
        self.tree[nodeIndex].privateKey = None
        self.computeParentHashes()
        self.updateTranscriptHash()


    def updateMemberKey(self, memberIndex: int, newPublicKey: bytes):
        """
        Updates a member's public key in the ratchet tree.
        :param memberIndex: Index of the member to update.
        :param newPublicKey: New public key for the member.
        """
        nodeIndex = self.getNodeIndex(memberIndex)
        if self.tree[nodeIndex].publicKey is None:
            raise ValueError("Cannot update key for a non-existent member.")
        self.tree[nodeIndex].publicKey = newPublicKey
        self.computeParentHashes()
        self.updateTranscriptHash()

    def updateTranscriptHash(self):
        """
        Updates the transcript hash of the tree using the centralized manager.
        """
        serializedTree = self.serializeTree()
        self.hashManager.updateHash(serializedTree)

    def serializeTree(self) -> bytes:
        """
        Serializes the current state of the tree.
        :return: Serialized tree as bytes.
        """
        state = [node.publicKey.hex() if node.publicKey else None for node in self.tree]
        return str(state).encode("utf-8")

    def deserializeTree(self, serializedTree: bytes):
        """
        Deserializes a tree state from bytes.
        :param serializedTree: Serialized tree data.
        """
        state = eval(serializedTree.decode("utf-8"))
        for i, publicKey in enumerate(state):
            self.tree[i].publicKey = bytes.fromhex(publicKey) if publicKey else None
