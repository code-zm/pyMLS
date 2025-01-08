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


def ser_dict(d, key_ser_func=None, value_ser_func=None):
    r = b""
    dict_size = len(d)
    if dict_size < 253:
        r = bytes([dict_size])
    elif dict_size < 2**16:
        r = bytes([253]) + struct.pack("<H", dict_size)
    elif dict_size < 2**32:
        r = bytes([254]) + struct.pack("<I", dict_size)
    else:
        r = bytes([255]) + struct.pack("<Q", dict_size)
    for k, v in d.items():
        r += key_ser_func(k) if key_ser_func else k.serialize()
        r += value_ser_func(v) if value_ser_func else v.serialize()
    return r


def deser_dict(f, key_cls, value_cls, arg1=None, arg2=None):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    r = {}
    for _ in range(nit):
        if isinstance(key_cls, types.FunctionType):
            k = key_cls(f)
        else:
            k = key_cls(arg1) if arg1 is not None else key_cls()
            k.deserialize(f)
        if isinstance(value_cls, types.FunctionType):
            v = value_cls(f)
        else:
            v = value_cls(arg2) if arg2 is not None else value_cls()
            v.deserialize(f)
        r[k] = v
    return r



# STR KEY, INT VALUE
def ser_str_dict(d):
    return ser_dict(d, ser_str, ser_int)

# INT 
def ser_int(i):
    return struct.pack(b"<i", i)

def deser_int(f, skip=-1):
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