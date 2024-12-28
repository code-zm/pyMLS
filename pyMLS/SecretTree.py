from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256


class SecretTree:
    def __init__(self, numLeaves, rootSecret):
        self.numLeaves = numLeaves
        self.tree = [None] * (2 * numLeaves - 1)
        self.tree[0] = rootSecret
        self.deriveTree()

    def deriveTree(self):
        for i in range(len(self.tree)):
            if self.tree[i] is not None:
                leftIndex = 2 * i + 1
                rightIndex = 2 * i + 2
                if leftIndex < len(self.tree):
                    self.tree[leftIndex] = self.expand(self.tree[i], b"left")
                if rightIndex < len(self.tree):
                    self.tree[rightIndex] = self.expand(self.tree[i], b"right")

    def expand(self, secret, label, length=32):
        info = f"MLS 1.0 {label}".encode()
        hkdf = HKDF(
            algorithm=SHA256(),
            length=length,
            salt=None,
            info=info,
        )
        return hkdf.derive(secret)

    def getLeafSecret(self, leafIndex):
        nodeIndex = len(self.tree) // 2 + leafIndex
        return self.tree[nodeIndex]

    def getHandshakeKeys(self, leafIndex, epoch):
        leafSecret = self.getLeafSecret(leafIndex)
        handshakeKey = self.expand(leafSecret, f"handshake_key_{epoch}")
        handshakeNonce = self.expand(leafSecret, f"handshake_nonce_{epoch}")
        return handshakeKey, handshakeNonce

    def getApplicationKeys(self, leafIndex, epoch):
        leafSecret = self.getLeafSecret(leafIndex)
        applicationKey = self.expand(leafSecret, f"application_key_{epoch}")
        applicationNonce = self.expand(leafSecret, f"application_nonce_{epoch}")
        return applicationKey, applicationNonce
