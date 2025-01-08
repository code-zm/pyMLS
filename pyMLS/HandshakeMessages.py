import struct
from enum import Enum
from . import serialize

DEBUG = False

class HandshakeType(Enum):
    ADD = 1
    UPDATE = 2
    REMOVE = 3
    COMMIT = 4

class HandshakeMessage:
    def __init__(self, messageType: HandshakeType = None, payload: bytes = None):
        """
        Initialize a HandshakeMessage.
        
        :param messageType: The type of handshake message (e.g., ADD, UPDATE).
        :param payload: The binary payload of the message.
        """
        self.messageType = messageType
        self.payload = payload

    def serialize(self) -> bytes:
        """
        Serialize the HandshakeMessage to binary format.

        :return: Binary serialization of the handshake message.
        """
        stream = serialize.io_wrapper()
        stream.write(serialize.ser_int(self.messageType.value))
        stream.write(serialize.ser_str(self.payload))
        return stream.getvalue()

    def deserialize(self, data: bytes) -> "HandshakeMessage":
        """
        Deserialize binary data into a HandshakeMessage.

        :param data: Binary data to deserialize.
        :return: A HandshakeMessage instance.
        """

        if DEBUG:
            print(f"Raw data for HandshakeMessage deserialization: {data}")

        stream = serialize.io_wrapper(data)
        messageTypeValue = serialize.deser_int(stream)
        self.messageType = HandshakeType(messageTypeValue)
        self.payload = serialize.deser_str(stream)
        return self

    def __eq__(self, other):
        return (self.messageType == other.messageType and self.payload == other.payload)

    def __ne__(self, other):
        return not self.__eq__(other)