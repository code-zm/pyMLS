import struct
from enum import Enum

DEBUG = False

class HandshakeType(Enum):
    ADD = 1
    UPDATE = 2
    REMOVE = 3
    COMMIT = 4

class HandshakeMessage:
    def __init__(self, messageType: HandshakeType, payload: bytes):
        """
        Initialize a HandshakeMessage.
        
        :param messageType: The type of handshake message (e.g., ADD, UPDATE).
        :param payload: The binary payload of the message.
        """
        self.messageType = messageType
        self.payload = payload

    def serializeBinary(self) -> bytes:
        """
        Serialize the HandshakeMessage to binary format.

        :return: Binary serialization of the handshake message.
        """
        payloadLength = len(self.payload)
        return struct.pack(f"!B{payloadLength}s", self.messageType.value, self.payload)

    @staticmethod
    def deserializeBinary(data: bytes) -> "HandshakeMessage":
        """
        Deserialize binary data into a HandshakeMessage.

        :param data: Binary data to deserialize.
        :return: A HandshakeMessage instance.
        """
        try:
            if DEBUG:
                print(f"Raw data for HandshakeMessage deserialization: {data}")
            messageTypeValue = struct.unpack("!B", data[:1])[0]
            messageType = HandshakeType(messageTypeValue)
            payload = data[1:]
            return HandshakeMessage(messageType, payload)
        except Exception as e:
            if DEBUG:
                print(f"Error during HandshakeMessage deserialization: {e}")
            raise
