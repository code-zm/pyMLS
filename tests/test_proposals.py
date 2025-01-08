import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyMLS.HandshakeMessages import HandshakeMessage, HandshakeType
from pyMLS.KeyPackage import KeyPackage
from pyMLS.TranscriptHashManager import TranscriptHashManager
from pyMLS.Proposals import AddProposal, RemoveProposal, UpdateProposal, ProposalSigner, ProposalList

class TestProposals(unittest.TestCase):
    def setUp(self):
        # Generate key pairs for testing
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.hash_manager = TranscriptHashManager()

        # Dummy key package for AddProposal and UpdateProposal
        self.key_package = KeyPackage(
            version=1,
            cipherSuite=0x0001,
            initKey=b'\x01' * 32,
            leafNode={"leafNodeSource": "test_leaf_node"},
            extensions=[],
            credential="test_credential".encode("utf-8"),
            signature=bytes()
        )

    def test_add_proposal_serialization(self):
        proposal = AddProposal(self.key_package)
        serialized = proposal.serialize()
        deserialized = AddProposal()
        deserialized.deserialize(serialized)
        self.assertEqual(proposal.keyPackage, deserialized.keyPackage)

    def test_remove_proposal_serialization(self):
        proposal = RemoveProposal(memberIndex=5)
        serialized = proposal.serialize()
        deserialized = RemoveProposal()
        deserialized.deserialize(serialized)
        self.assertEqual(proposal.memberIndex, deserialized.memberIndex)

    def test_update_proposal_serialization(self):
        proposal = UpdateProposal(self.key_package)
        serialized = proposal.serialize()
        deserialized = UpdateProposal()
        deserialized.deserialize(serialized)
        self.assertEqual(proposal.keyPackage, deserialized.keyPackage)

    def test_proposal_signing(self):
        proposal = AddProposal(self.key_package)
        signature = ProposalSigner.signProposal(proposal, self.private_key, self.hash_manager)
        is_verified = ProposalSigner.verifyProposal(
            proposal,
            signature,
            self.public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw),
            self.hash_manager
        )
        self.assertTrue(is_verified)

    def test_proposal_list(self):
        proposals = [
            AddProposal(self.key_package),
            RemoveProposal(memberIndex=3),
            UpdateProposal(self.key_package),
        ]
        proposal_list = ProposalList(proposals, self.hash_manager)
        
        # Test serialization
        serialized = proposal_list.serialize()
        self.assertIsInstance(serialized, bytes)

        # Test adding a proposal
        new_proposal = RemoveProposal(memberIndex=6)
        proposal_list.addProposal(new_proposal)
        self.assertEqual(len(proposal_list.proposals), 4)

        # Test signing and verifying the list
        signature = proposal_list.signList(self.private_key)
        is_verified = proposal_list.verifyList(signature, self.public_key)
        self.assertTrue(is_verified)


    

 

if __name__ == '__main__':
    unittest.main()
