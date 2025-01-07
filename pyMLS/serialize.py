import io
import types
import struct

from enum import IntEnum


class SerType(IntEnum):
    SER_MAIN = (1 << 0)
    SER_TBS = (1 << 1)


def io_wrapper(data=None):
    if not data:
        return io.BytesIO()
        
    if isinstance(data, io.BytesIO):
        return data
    elif isinstance(data, bytes):
        return io.BytesIO(data)
    else:
        raise ValueError("io_wrapper(): Error: Input must be of type 'bytes' or 'io.BytesIO'")


def ser_str(s):
    s = s.encode() if isinstance(s, str) else s  
    length = len(s)
    if length < 253:
        return struct.pack("<B", length) + s
    elif length <= 0xFFFF:  
        return struct.pack("<B", 253) + struct.pack("<H", length) + s
    elif length <= 0xFFFFFFFF:  
        return struct.pack("<B", 254) + struct.pack("<I", length) + s
    else:  
        return struct.pack("<B", 255) + struct.pack("<Q", length) + s


def deser_str(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return f.read(nit)



def ser_list(l, ser_func=None, cls=None):
    s = io.BytesIO()
    length = len(l)
    if length < 253:
        s.write(bytes([length]))
    elif length < 2**16:  
        s.write(bytes([253]) + struct.pack("<H", length))
    elif length < 2**32:  
        s.write(bytes([254]) + struct.pack("<I", length))
    else:
        s.write(bytes([255]) + struct.pack("<Q", length))
    for i in l:
        if cls is not None:
            s.write(cls.serialize(i))
        else:
            s.write(i.serialize() if ser_func is None else ser_func(i))
    return s.getvalue()


def deser_list(f, cls, arg1=None):
    f = io_wrapper(f)
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        if isinstance(cls, types.FunctionType):
            t = cls(f)
        else:
            t = cls(arg1) if arg1 is not None else cls()
            t.deserialize(f)
        r.append(t)
    return r

# INT 
def ser_int(i):
    return struct.pack(b"<i", i)

def deser_int(f):
    return struct.unpack(b"<i", f.read(4))[0]

# UINT 
def ser_uint(i):
    return struct.pack(b"<I", i)

def deser_uint(f):
    return struct.unpack(b"<I", f.read(4))[0]

# INT64
def ser_int64(u):
    return struct.pack(b"<q", u)

def deser_int64(f):
    return struct.unpack(b"<q", f.read(8))[0]

# STR LIST
def ser_str_list(l):
    return ser_list(l, ser_func=ser_str)

def deser_str_list(f):
    return deser_list(f, deser_str)