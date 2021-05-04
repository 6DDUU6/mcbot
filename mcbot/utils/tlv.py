# -*- coding: utf-8 -*-
from .pack import Pack
from .tools import getRandomBin,str2bytes,teaEncrypt

class Tlv(object):
    """
    tlv工具类
    """
    def __init__(self):
        # 其实tlvxxx应该定义为classmethod更好的,不用Tlv.tlv_pack,直接tlv_pack,但是懒得改了
        pass

    @staticmethod
    def tlv_pack(cmd, bin_):
        pack = Pack()
        pack.write_hex(cmd)
        pack.write_short(len(bin_))
        pack.write_bytes(bin_)
        return pack.get_all()

    @staticmethod
    def tlv016(appid,subappid,guid,apkid,version,apksign):
        pack = Pack()
        pack.write_hex('00 00 00 05')
        pack.write_int(appid)
        pack.write_int(subappid)
        pack.write_hex(guid)
        pack.write_short(len(apkid))
        pack.write_str(apkid)
        pack.write_short(len(version))
        pack.write_str(version)
        pack.write_hex('00 10')
        pack.write_hex(apksign)
        return Tlv.tlv_pack('00 16', pack.get_all())
    
    @staticmethod
    def tlv01B():
        pack = Pack()
        pack.write_hex('00 00 00 00 00 00 00 00 00 00 00 03 00 00 00 04 00 00 00 48 00 00 00 02 00 00 00 02 00 00')
        return Tlv.tlv_pack('00 1B', pack.get_all())
    
    @staticmethod
    def tlv01D(miscBitmap):
        pack = Pack()
        pack.write_hex('01')
        pack.write_int(miscBitmap)
        pack.write_hex('00 00 00 00 00 00 00 00 00')
        return Tlv.tlv_pack('00 1D', pack.get_all())
    
    @staticmethod
    def tlv01F(version: str):
        pack = Pack()
        pack.write_hex('00')
        pack.write_hex('00 07')
        pack.write_hex('61 6E 64 72 6F 69 64') #android
        pack.write_short(len(version))
        pack.write_str(version)
        pack.write_hex('00 02')
        pack.write_hex('00 10')
        pack.write_hex('43 68 69 6E 61 20 4D 6F 62 69 6C 65 20 47 53 4D') #China Mobile GSM
        pack.write_hex('00 00 00 04')
        pack.write_hex('77 69 66 69') #wifi
        return Tlv.tlv_pack('00 1F',pack.get_all())

    @staticmethod
    def tlv033(guid):
        pack = Pack()
        pack.write_hex(guid)
        return Tlv.tlv_pack('00 33', pack.get_all())

    @staticmethod
    def tlv035():
        pack = Pack()
        pack.write_int(8)
        return Tlv.tlv_pack('00 35', pack.get_all())

    @staticmethod
    def tlv018(qq: str):
        pack = Pack()
        pack.write_hex('00 01 00 00 06 00 00 00 00 10 00 00 00 00')
        pack.write_int(int(qq))
        pack.write_bytes(bytes(4))
        return Tlv.tlv_pack('00 18', pack.get_all())

    @staticmethod
    def tlv001(qq,time):
        pack = Pack()
        pack.write_hex('00 01')
        pack.write_bytes(getRandomBin(4))
        pack.write_int(int(qq))
        pack.write_int(time)
        pack.write_bytes(bytes(6))
        return Tlv.tlv_pack('00 01',pack.get_all())
    
    @staticmethod
    def tlv106(qq:str,md5pass,md52pass,tgtkey,deviceguid:str,time,appid):
        pack = Pack()
        pack.write_hex('00 04')
        pack.write_bytes(getRandomBin(4))
        pack.write_hex('00 00 00 0D')
        pack.write_hex('00 00 00 10')
        pack.write_hex('00 00 00 00')
        pack.write_hex('00 00 00 00')
        pack.write_int(int(qq))
        pack.write_int(time)
        pack.write_hex('00 00 00 00 01')
        pack.write_bytes(md5pass)
        pack.write_bytes(tgtkey)
        pack.write_hex('00 00 00 00 01')
        pack.write_hex(deviceguid)
        pack.write_int(appid)
        pack.write_hex('00 00 00 01')
        pack.write_short(len(qq))
        pack.write_str(qq)
        pack.write_hex('00 00')
        return Tlv.tlv_pack('01 06',teaEncrypt(pack.get_all(),md52pass))

    @staticmethod
    def tlv116():
        pack = Pack()
        pack.write_hex('00 0A F7 FF 7C 00 01 04 00 01 5F 5E 10 E2')
        return Tlv.tlv_pack('01 16',pack.get_all())

    @staticmethod
    def tlv100(appid,main_signmap):
        pack = Pack()
        pack.write_hex('00 01 00 00 00 0D 00 00 00 10')
        pack.write_int(appid)
        pack.write_bytes(bytes(4))
        pack.write_int(main_signmap)
        return Tlv.tlv_pack('01 00',pack.get_all())

    @staticmethod
    def tlv107():
        pack = Pack()
        pack.write_hex('00 00 00 00 00 01')
        return Tlv.tlv_pack('01 07',pack.get_all())

    @staticmethod
    def tlv142(apkid:str):
        pack = Pack()
        pack.write_int(len(apkid))
        pack.write_str(apkid)
        return Tlv.tlv_pack('01 42',pack.get_all())

    @staticmethod
    def tlv109(AndroidId):
        pack = Pack()
        pack.write_hex(AndroidId)
        return Tlv.tlv_pack('01 09',pack.get_all())
    
    @staticmethod
    def tlv124(version: str):
        pack = Pack()
        pack.write_hex('00 07')
        pack.write_hex('61 6E 64 72 6F 69 64') #android
        pack.write_short(len(version))
        pack.write_str(version)
        pack.write_hex('00 02')
        pack.write_hex('00 10')
        pack.write_hex('43 68 69 6E 61 20 4D 6F 62 69 6C 65 20 47 53 4D') #China Mobile GSM
        pack.write_hex('00 00 00 04')
        pack.write_hex('77 69 66 69') #wifi
        return Tlv.tlv_pack('01 24',pack.get_all())

    @staticmethod
    def tlv128(devicename,devicebrand,deviceguid):
        pack = Pack()
        pack.write_hex('00 00 01 01 00 11 00 00 00')
        pack.write_short(len(devicename))
        pack.write_str(devicename)
        pack.write_hex('00 10')
        pack.write_hex(deviceguid)
        pack.write_short(len(devicebrand))
        pack.write_str(devicebrand)
        return Tlv.tlv_pack('01 28',pack.get_all())

    @staticmethod
    def tlv16E(devicename):
        pack = Pack()
        pack.write_str(devicename)
        return Tlv.tlv_pack('01 6E',pack.get_all())

    @staticmethod
    def tlv144(tgtkey,tlv109,tlv124,tlv128,tlv16E):
        pack = Pack()
        pack.write_short(4)
        pack.write_bytes(tlv109)
        pack.write_bytes(tlv124)
        pack.write_bytes(tlv128)
        pack.write_bytes(tlv16E)
        return Tlv.tlv_pack('01 44',teaEncrypt(pack.get_all(),tgtkey))

    @staticmethod
    def tlv145(deviceguid):
        pack = Pack()
        pack.write_hex(deviceguid)
        return Tlv.tlv_pack('01 45',pack.get_all())

    @staticmethod
    def tlv147(apk_v:str,apk_sig:str):
        pack = Pack()
        pack.write_hex('00 00 00 10')
        pack.write_short(len(apk_v))
        pack.write_str(apk_v)
        pack.write_hex('00 10')
        pack.write_hex(apk_sig)
        return Tlv.tlv_pack('01 47',pack.get_all())

    @staticmethod
    def tlv154(reqid):
        pack = Pack()
        pack.write_int(reqid)
        return Tlv.tlv_pack('01 54',pack.get_all())

    @staticmethod
    def tlv141():
        pack = Pack()
        pack.write_hex('00 01')
        pack.write_hex('00 10')
        pack.write_hex('43 68 69 6E 61 20 4D 6F 62 69 6C 65 20 47 53 4D')
        pack.write_hex('00 02')
        pack.write_hex('00 04')
        pack.write_hex('77 69 66 69')
        return Tlv.tlv_pack('01 41',pack.get_all())
    
    @staticmethod
    def tlv008():
        pack = Pack()
        pack.write_hex('00 00 00 00 08 04 00 00')
        return Tlv.tlv_pack('00 08',pack.get_all())

    @staticmethod
    def tlv511():
        pack = Pack()
        domainlist = ['tenpay.com','qzone.qq.com','vip.qq.com','qun.qq.com','yundong.qq.com']
        pack.write_short(len(domainlist))
        for x in domainlist:
            pack.write_hex('01')
            pack.set_token(str2bytes(x))
        return Tlv.tlv_pack('05 11',pack.get_all())

    @staticmethod
    def tlv187(devicemac:str):
        pack = Pack()
        pack.write_hex(devicemac)
        return Tlv.tlv_pack('01 87',pack.get_all())

    @staticmethod
    def tlv188(AndroidId:str):
        pack = Pack()
        pack.write_hex(AndroidId)
        return Tlv.tlv_pack('01 88',pack.get_all())

    @staticmethod
    def tlv194(imsi:str):
        pack = Pack()
        # pack.write_hex(imsi)
        pack.write_hex('DE 99 6F 72 08 45 79 04 DE B5 AF 92 27 8E 40 A2')
        return Tlv.tlv_pack('01 94',pack.get_all())

    @staticmethod
    def tlv191(typehex):
        pack = Pack()
        pack.write_hex(typehex)
        return Tlv.tlv_pack('01 91',pack.get_all())

    @staticmethod
    def tlv202(bssid,ssid):
        pack = Pack()
        pack.write_hex('00 10')
        pack.write_hex(bssid)
        pack.set_token(str2bytes('"' + ssid + '"'))
        return Tlv.tlv_pack('02 02',pack.get_all())

    @staticmethod
    def tlv177(time,sdkversion):
        pack = Pack()
        pack.write_hex('01')
        pack.write_int(time)
        pack.write_short(len(sdkversion))
        pack.write_str(sdkversion)
        return Tlv.tlv_pack('01 77',pack.get_all())

    @staticmethod
    def tlv516():
        pack = Pack()
        pack.write_bytes(bytes(4))
        return Tlv.tlv_pack('05 16',pack.get_all())

    @staticmethod
    def tlv521():
        pack = Pack()
        pack.write_bytes(bytes(6))
        return Tlv.tlv_pack('05 21',pack.get_all())

    @staticmethod
    def tlv525():
        pack = Pack()
        pack.write_hex('00 01 05 36 00 02 01 00')
        return Tlv.tlv_pack('05 25',pack.get_all())
    
    @staticmethod
    def tlv104(token:bytes):
        pack = Pack()
        pack.write_bytes(token)
        return Tlv.tlv_pack('01 04',pack.get_all())

    @staticmethod
    def tlv401():
        pack = Pack()
        pack.write_hex('40 14 4E C7 5E FC 75 2B 69 0D E3 8C D7 D9 50 2F')
        return Tlv.tlv_pack('04 01',pack.get_all())