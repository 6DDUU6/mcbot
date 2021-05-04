# -*- coding: utf-8 -*-
"""
操作字节流的
"""
import struct
import random
from .pack import Pack
import pytea

def int2bytes(num: int, outlen: int = 0) -> bytes:
    if outlen == 0:
        if num > 281474976710655:
            outlen = 7
        elif num > 1099511627775:
            outlen = 6
        elif num > 4294967295:
            outlen = 5
        elif num > 16777215:
            outlen = 4
        elif num > 65535:
            outlen = 3
        elif num > 255:
            outlen = 2
        else:
            outlen = 1
    return num.to_bytes(length=outlen, byteorder='big')

def bytes2int(bin_) -> int:
    return int.from_bytes(bin_,byteorder='big')

def hex2bytes(hexstr: str) -> bytes:
    str_bytes = hexstr.strip().replace("\n", "")
    pkt = bytes.fromhex(str_bytes)
    return pkt

def bytes2hex(bin_: bytes) -> str:
    return ''.join(['%02X ' % b for b in bin_])

def _bytes2hex(bin_: bytes) -> str:
    return bin_.hex().upper()

def str2bytes(text: str):
    return text.encode('utf-8')

def bytes2str(bin_:bytes):
    return bin_.decode('utf-8')

def str2hex(text: str):
    strBytes = text.encode('utf-8')
    return bytes2hex(strBytes)

def hex2str(hexstr: str):
    strBytes = hexstr.split()
    pkt = bytearray(int(x, 16) for x in strBytes)
    return pkt.decode('utf-8')

def getRandomBin(num):
    intlist = [random.randint(0,255) for i in range(num)]
    pkt = bytearray(intlist)
    return pkt

def ProtobufOfInt(key,value):
    pack = Pack()
    pack.write_hex(key)
    pack.write_bytes(Value2Varint(value))
    return pack.get_all()

def ProtobufOfLenDe(key,value):
    pack = Pack()
    pack.write_hex(key)
    pack.write_bytes(Value2Varint(len(value)))
    pack.write_bytes(value)
    return pack.get_all()

def ProtobufOfLenDe_Hex(key,value):
    pack = Pack()
    value = hex2bytes(value)
    pack.write_hex(key)
    pack.write_bytes(Value2Varint(len(value)))
    pack.write_bytes(value)
    return pack.get_all()

def ProtobufOfString(key,value):
    pack = Pack()
    pack.write_hex(key)
    value = value.encode('utf-8')
    pack.write_bytes(Value2Varint(len(value)))
    pack.write_bytes(value)
    return pack.get_all()

def Value2Varint(num):
    a = num
    c = []
    if a >= 127:
        while True:
            c.append((a & 127)|128)
            a = a >> 7
            if a <= 127:
                break
        c.append(a)
        c = bytearray(c)
    else:
        c = int2bytes(a,1)
    return c

def teaEncrypt(data: bytes,key: bytes) -> bytes:
    tea = pytea.TEA(secret_key=key, encrypt_times=16)
    return tea.encrypt(data)

def teaDecrypt(data: bytes,key: bytes) -> bytes:
    tea = pytea.TEA(secret_key=key, encrypt_times=16)
    return tea.decrypt(data)
    