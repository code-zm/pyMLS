import struct
from .HandshakeTypes import HandshakeType

class SerializationUtils:
    @staticmethod
    def packLengthPrefixed(data: bytes) -> bytes:
        return struct.pack(f"!H{len(data)}s", len(data), data)

    @staticmethod
    def unpackLengthPrefixed(data: bytes, offset: int):
        length = struct.unpack("!H", data[offset:offset + 2])[0]
        start = offset + 2
        value = data[start:start + length]
        return value, start + length
    
    @staticmethod
    def unpackProposalWithType(data: bytes, offset: int) -> (HandshakeType, bytes, int):
        """
        Unpacks a proposal with its type from binary data.
        """
        proposalType = HandshakeType(struct.unpack("!B", data[offset:offset + 1])[0])
        offset += 1
        proposalData, next_offset = SerializationUtils.unpackLengthPrefixed(data, offset)
        return proposalType, proposalData, next_offset

