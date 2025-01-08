import os
from typing import List, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives import serialization
from .KeySchedule import KeySchedule
from .TranscriptHashManager import TranscriptHashManager
from .KeyPackage import KeyPackage
from . import serialize

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

    def __init__(self, numLeaves: int, initialSecret: bytes, hashManager: TranscriptHashManager, groupContext: Optional[dict] = None):
        """
        Initializes a ratchet tree with the specified number of leaves.
        :param numLeaves: Number of leaves (members) in the tree.
        :param initialSecret: Initial secret for the key schedule.
        :param hashManager: Centralized transcript hash manager.
        :param groupContext: Group context for validating KeyPackages.
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
        self.groupContext = groupContext or {
            "group_id": os.urandom(16),
            "epoch": 1,
            "tree_hash": None,
            "confirmed_transcript_hash": None,
            "extensions": [],
        }
        self.initializeLeaves()
        self.computeParentHashes()

    def initializeLeaves(self):
        """Initializes the leaf nodes with private-public key pairs deterministically."""
        for i in range(self.numLeaves):
            self.createLeaf(i)

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


    def computeTreeHash(self, nodeIndex: int) -> Optional[bytes]:
        """Computes the tree hash for a given node."""
        node = self.tree[nodeIndex]
        if not node:
            return None

        # Leaf node: Return public key directly
        if nodeIndex >= self.numLeaves - 1:
            hashValue = node.publicKey or b""
            print(f"Leaf Node {nodeIndex}: Hash={hashValue.hex() if hashValue else 'None'}")
            return hashValue

        # Parent node: Hash the left and right children
        leftChildIndex = 2 * nodeIndex + 1
        rightChildIndex = 2 * nodeIndex + 2

        leftHash = self.computeTreeHash(leftChildIndex) if leftChildIndex < self.numNodes else b""
        rightHash = self.computeTreeHash(rightChildIndex) if rightChildIndex < self.numNodes else b""

        hasher = Hash(SHA256())
        hasher.update(leftHash)
        hasher.update(rightHash)
        computedHash = hasher.finalize()

        print(f"Parent Node {nodeIndex}: LeftHash={leftHash.hex() if leftHash else 'None'}, RightHash={rightHash.hex() if rightHash else 'None'}, ComputedHash={computedHash.hex()}")
        return computedHash



    def computeParentHashes(self):
        """Computes the parent hashes for all parent nodes in the tree."""
        for nodeIndex in range(self.numNodes - 1, 0, -2):
            parentIndex = (nodeIndex - 1) // 2
            leftChild = self.tree[nodeIndex - 1]
            rightChild = self.tree[nodeIndex]
            parent = self.tree[parentIndex]

            leftKey = leftChild.publicKey or b""
            rightKey = rightChild.publicKey or b""

            if leftKey or rightKey:  # Only compute hash if at least one child has a key
                hasher = Hash(SHA256())
                hasher.update(leftKey)
                hasher.update(rightKey)
                parent.parentHash = hasher.finalize()
            else:
                parent.parentHash = None

            # Debugging information
            if DEBUG:
                debugLeftKey = leftKey.hex() if leftKey else 'None'
                debugRightKey = rightKey.hex() if rightKey else 'None'
                debugParentHash = parent.parentHash.hex() if parent.parentHash else 'None'
                print(f"Node {parentIndex}: LeftKey={debugLeftKey}, RightKey={debugRightKey}, ParentHash={debugParentHash}")


    def validateParentHashes(self) -> bool:
        """Validates the parent hashes for the entire tree."""
        for nodeIndex in range(self.numNodes - 1, 0, -2):  # Validate from leaves to root
            parentIndex = (nodeIndex - 1) // 2
            leftChild = self.tree[nodeIndex - 1]
            rightChild = self.tree[nodeIndex]
            parent = self.tree[parentIndex]

            leftKey = leftChild.publicKey or b""
            rightKey = rightChild.publicKey or b""

            # Compute expected hash
            if leftKey or rightKey:
                hasher = Hash(SHA256())
                hasher.update(leftKey)
                hasher.update(rightKey)
                expectedParentHash = hasher.finalize()
            else:
                expectedParentHash = None

            if parent.parentHash != expectedParentHash:
                print(f"Validation failed at node {parentIndex}: "
                      f"Expected {expectedParentHash.hex() if expectedParentHash else 'None'}, "
                      f"Got {parent.parentHash.hex() if parent.parentHash else 'None'}")
                return False
        return True



    def syncTree(self, publicTree: List[Optional[bytes]]):
        """Synchronizes the tree with a received public tree state."""
        if len(publicTree) != len(self.tree):
            raise ValueError("Public tree state size does not match the tree.")

        for i, publicKey in enumerate(publicTree):
            if DEBUG:
                print(f"Syncing node {i}: Received publicKey={publicKey.hex() if publicKey else 'None'}")
            self.tree[i].publicKey = publicKey  # Allow `None` for missing public keys

        # Recompute hashes after synchronization
        self.computeParentHashes()

        if not self.validateParentHashes():
            raise ValueError("Parent hash validation failed after synchronization.")

        # self.updateGroupContext()

    def updateGroupContext(self):
        """Updates the group context to reflect the current tree state."""
        self.groupContext["tree_hash"] = self.computeTreeHash(0)
        self.groupContext["epoch"] += 1
        self.groupContext["confirmed_transcript_hash"] = self.hashManager.getCurrentHash()

    def addMember(self, keyPackage: KeyPackage):
        """Adds a new member to the ratchet tree."""
        keyPackage.validate(self.groupContext, groupCipherSuite=0x0001)
        newLeafIndex = self.numLeaves
        self.numLeaves += 1
        self.numNodes = 2 * self.numLeaves - 1

        while len(self.tree) < self.numNodes:
            self.tree.append(Node())

        newLeafNodeIndex = self.getNodeIndex(newLeafIndex)
        self.tree[newLeafNodeIndex].publicKey = keyPackage.initKey
        self.computeParentHashes()
        self.updateGroupContext()

    def removeMember(self, memberIndex: int):
        """Removes a member from the tree."""
        nodeIndex = self.getNodeIndex(memberIndex)
        self.tree[nodeIndex].publicKey = None
        self.tree[nodeIndex].privateKey = None
        self.computeParentHashes()

    def updateMemberKey(self, memberIndex: int, newPublicKey: bytes):
        """Updates a member's key in the tree."""
        nodeIndex = self.getNodeIndex(memberIndex)
        self.tree[nodeIndex].publicKey = newPublicKey
        self.computeParentHashes()

    def serializeTree(self) -> bytes:
        """Serializes the tree's public keys."""
        pubkeys = [node.publicKey or b'' for node in self.tree]
        stream = serialize.io_wrapper()
        stream.write(serialize.ser_str_list(pubkeys))
        return stream.getvalue()

    def deserializeTree(self, serialized: bytes):
        """Deserializes the tree's public keys."""
        stream = serialize.io_wrapper(serialized)
        pubkeys = serialize.deser_str_list(stream)
        for i, node in enumerate(self.tree):
            node.publicKey = pubkeys[i]

    def getPublicState(self) -> List[Optional[bytes]]:
        """Returns the public state of the tree."""
        return [node.publicKey for node in self.tree]
