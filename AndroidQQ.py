from mcbot.utils.pack import Pack
from mcbot.utils.unpack import Unpack
from mcbot.utils.tlv import Tlv
from mcbot.utils.tools import *
from mcbot.response import *
from mcbot.protocol.builder import *
import time
import hashlib


class AndroidQQ(object):
    def __init__(self):
        self.qq = '0'
        self.starttime = int(time.time())
        self.requestId = 10000
        self.tgtkey = getRandomBin(16)
        self.sharekey = hex2bytes(
            '4A ED 5E CF F6 19 92 A8 BB 62 B3 A8 B3 C4 B0 8E')
        self.publickey = hex2bytes(
            '04 5F FB B8 6D 00 A3 7F A9 9B 6A DB 6B C5 B1 75 B3 DD 51 5A FF 66 F6 04 76 85 BA 7F 66 69 69 D8 72 6F 4E 8F 40 B6 EC 17 80 F0 64 A5 51 2F 2B AD 18 5C C2 50 A9 4E BB 25 49 E4 D0 65 54 F9 66 0F A0'
        )
        self.privatekey = hex2bytes(
            '00 00 00 21 00 94 C7 25 8B 78 45 33 AB 23 73 B4 3A 60 AB 37 1D D4 53 3B 5A BD FB D6 43 C7 A2 3F CB 5A 08 01 A5'
        )
        self.msgCookies = getRandomBin(4)
        self.syncCookies = ProtobufOfInt("08", self.starttime) + ProtobufOfInt(
            "10",
            self.starttime) + ProtobufOfInt("18", 2698482287) + ProtobufOfInt(
                "20",
                2661279345) + ProtobufOfInt("28", 3976759562) + ProtobufOfInt(
                    "48", 813968566) + ProtobufOfInt(
                        "58",
                        1553502109) + ProtobufOfInt("60", 56) + ProtobufOfInt(
                            "68", self.starttime) + ProtobufOfInt("70", 0)
        self.token010A = bytes()
        self.token0143 = bytes()
        self.token0116 = bytes()
        self.token0104 = bytes()
        self.sessionKey = bytes()

        self.verifysig = bytes()
        self.QRPicData = bytes()
        self.tmpPwd = bytes()
        self.tmpNoPicSig = bytes()
        self.tgtQR = bytes()

        self.deviceguid = 'C3 6D 03 70 6B 7C 4E DD C0 77 46 91 C1 FB 91 F8'
        self.devicename = 'oppo r9 plustm a'
        self.devicebrand = 'oppo'
        self.deviceVersion = '2.0.5'
        self.deviceMac = '54 44 61 90 FC 9C 7E 08 C4 13 59 26 B8 73 4B C2'
        self.deviceImsi = '460001330114682'
        self.deviceimie = '865166024867445'
        self.ver = '|' + self.deviceImsi + '|A8.2.7.27f6ea96'
        self.bssid = '15 EC 8E DC 49 FE B2 52 11 D0 81 AC 84 2E 81 36'
        self.ssid = 'dlb'
        self.AndroidId = 'CC 3C DD 51 8A 92 6C 6C 54 FF 46 48 CE E2 1D 29'
        self.appid = 537064446
        self.appid2 = 537064446
        self.main_signmap = 34869472
        self.miscBitmap = 16252796
        self.apk_v = '8.2.7'
        self.apk_sig = 'A6 B7 45 BF 24 A2 C2 77 52 77 16 F6 F3 6E B6 8D'
        self.apkid = 'com.tencent.qqlite'
        self.sdkversion = '6.0.0.236'

        self.nick = ''

    def initFromQQ(self, qq: str):
        self.qq = qq
        self.intqq = int(qq)

    def setSyncCookies(self, syncCookies):
        self.syncCookies = syncCookies

    def getQRCode(self):
        pack = Pack()
        pack.write_short(0)
        pack.write_int(16)
        pack.write_bytes(bytes(8))
        pack.write_hex('08')
        pack.write_short(0)
        pack.write_short(6)
        pack.write_bytes(
            Tlv.tlv016(16, self.appid, self.deviceguid, self.apkid,
                       self.deviceVersion, self.apk_sig))
        pack.write_bytes(Tlv.tlv01B())
        pack.write_bytes(Tlv.tlv01D(self.miscBitmap))
        pack.write_bytes(Tlv.tlv01F(self.deviceVersion))
        pack.write_bytes(Tlv.tlv033(self.deviceguid))
        pack.write_bytes(Tlv.tlv035())
        data = pack.get_all()
        data = self.BuildCode2DRequestPacket('00 31', 0, data)

        pack.set_empty()
        pack.write_hex('00 01 11 00 00 00 10 00 00 00 72 00 00 00')
        pack.write_int(int(time.time()))
        pack.write_bytes(data)
        data = pack.get_all()
        data = teaEncrypt(data, self.sharekey)
        data = self.Pack_LoginHead('wtlogin.trans_emp', data, '12')
        data = self.Pack_QRHead(data)
        return data

    def BuildCode2DRequestPacket(self, cmd, seq, data):
        pack = Pack()
        pack.write_hex('02')
        pack.write_short(43 + len(data) + 1)
        pack.write_hex(cmd)
        pack.write_hex(
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 00 00 00 32'
        )
        pack.write_int(seq)
        pack.write_bytes(bytes(8))
        pack.write_bytes(data)
        pack.write_hex('03')
        return pack.get_all()

    def getQRStatus(self):
        pack = Pack()
        pack.write_hex('00 05 01 00 00 00 08 00 00 00 10')
        pack.write_short(len(self.verifysig))
        pack.write_bytes(self.verifysig)
        pack.write_hex('00 00 00 00 00 00 00 00 08 00 00 00 00')
        data = pack.get_all()
        data = self.BuildCode2DRequestPacket('00 12', 1, data)

        pack.set_empty()
        pack.write_hex('00 00 62 00 00 00 10 00 00 00 72 00 00 00')
        pack.write_int(int(time.time()))
        pack.write_bytes(data)
        data = pack.get_all()

        data = teaEncrypt(data, self.sharekey)
        data = self.Pack_LoginHead('wtlogin.trans_emp', data, '12')
        data = self.Pack_QRHead(data)
        return data

    def Pack_Login(self):
        pack = Pack()
        pack.write_short(9)
        pack.write_short(24)  #24个tlv
        pack.write_bytes(Tlv.tlv018(self.qq))
        pack.write_bytes(Tlv.tlv001(self.qq, self.starttime))
        pack.write_bytes(Tlv.tlv_pack("01 06", self.tmpPwd))
        pack.write_bytes(Tlv.tlv116())
        pack.write_bytes(Tlv.tlv100(self.appid, self.main_signmap))
        pack.write_bytes(Tlv.tlv107())
        pack.write_bytes(Tlv.tlv142(self.apkid))
        pack.write_bytes(
            Tlv.tlv144(
                self.tgtkey, Tlv.tlv109(self.AndroidId),
                Tlv.tlv124(self.deviceVersion),
                Tlv.tlv128(self.devicename, self.devicebrand, self.deviceguid),
                Tlv.tlv16E(self.devicename)))
        pack.write_bytes(Tlv.tlv145(self.deviceguid))
        pack.write_bytes(Tlv.tlv147(self.apk_v, self.apk_sig))
        pack.write_bytes(Tlv.tlv_pack("01 6A", self.tmpNoPicSig))
        pack.write_bytes(Tlv.tlv154(self.requestId))
        pack.write_bytes(Tlv.tlv141())
        pack.write_bytes(Tlv.tlv008())
        pack.write_bytes(Tlv.tlv511())
        pack.write_bytes(Tlv.tlv187(self.deviceMac))
        pack.write_bytes(Tlv.tlv188(self.deviceMac))
        pack.write_bytes(Tlv.tlv194(self.deviceImsi))
        pack.write_bytes(Tlv.tlv191("00"))
        pack.write_bytes(Tlv.tlv202(self.bssid, self.ssid))
        pack.write_bytes(Tlv.tlv177(self.starttime, self.sdkversion))
        pack.write_bytes(Tlv.tlv516())
        pack.write_bytes(Tlv.tlv521())
        pack.write_bytes(Tlv.tlv_pack("03 18", self.tgtQR))

        pkt = teaEncrypt(pack.get_all(), self.sharekey)
        pkt = self.Pack_LoginHead('wtlogin.login', pkt, '10')
        pkt = self.Pack_Head(pkt, 1)
        return pkt

    def Pack_LoginHead(self, cmd, pkt, cmd2):
        pack = Pack()
        pack.write_int(self.requestId)
        pack.write_int(self.appid)
        pack.write_int(self.appid2)
        pack.write_hex('01 00 00 00 00 00 00 00 00 00 01 00 00 00 00 04')
        pack.write_int(len(cmd) + 4)
        pack.write_str(cmd)
        pack.write_hex('00 00 00 08')
        pack.write_bytes(getRandomBin(4))  #msgCookie
        pack.write_int(len(self.deviceimie) + 4)
        pack.write_str(self.deviceimie)
        pack.write_hex('00 00 00 04')
        pack.write_short(len(self.ver) + 2)
        pack.write_str(self.ver)
        pack.write_hex('00 00 00 04')

        headpkt = pack.get_all()
        pack.set_empty()
        pack.write_int(len(headpkt) + 4)
        pack.write_bytes(headpkt)
        headpkt = pack.get_all()

        pack.set_empty()
        pack.write_hex('1F 41 08 ' + cmd2 + ' 00 01')
        pack.write_int(int(self.qq))
        pack.write_hex('03 87 00 00 00 00 02 00 00 00 00 00 00 00 00 02 01')
        pack.write_bytes(getRandomBin(16))
        pack.write_hex('01 31 00 01')
        pack.write_short(len(self.publickey))
        pack.write_bytes(self.publickey)
        pack.write_bytes(pkt)

        pkt = pack.get_all()

        pack.set_empty()
        pack.write_hex('02')
        pack.write_short(len(pkt) + 4)
        pack.write_bytes(pkt)
        pack.write_hex('03')

        pkt = pack.get_all()

        pack.set_empty()
        pack.write_bytes(headpkt)
        pack.write_int(len(pkt) + 4)
        pack.write_bytes(pkt)

        pkt = teaEncrypt(pack.get_all(), bytes(16))
        return pkt

    def Pack_Head(self, pkt, mtype):
        pack = Pack()
        if mtype == 1:
            pack.write_hex('00 00 00 0A 02 00 00 00 04')
        elif mtype == 2:
            pack.write_hex('00 00 00 0A 01')
            pack.write_int(len(self.token0143) + 4)
            pack.write_bytes(self.token0143)
        elif mtype == 3:
            pack.write_hex('00 00 00 0B 01')
            pack.write_int(self.requestId)
        else:
            pack.write_hex('00 00 00 0B 02')
            pack.write_int(self.requestId)
        pack.write_hex('00 00 00')
        pack.write_short(len(self.qq) + 4)
        pack.write_str(self.qq)
        pack.write_bytes(pkt)

        pkt = pack.get_all()

        pack.set_empty()
        pack.write_int(len(pkt) + 4)
        pack.write_bytes(pkt)

        pkt = pack.get_all()
        return pkt

    def Pack_QRHead(self, pkt):
        pack = Pack()
        pack.write_hex('00 00 00 0A 02 00 00 00 04')
        pack.write_hex('00 00 00')
        pack.write_short(5)
        pack.write_hex('30')
        pack.write_bytes(pkt)
        pkt = pack.get_all()

        pack.set_empty()
        pack.write_int(len(pkt) + 4)
        pack.write_bytes(pkt)

        pkt = pack.get_all()
        return pkt

    def Pack_Login_204(self):
        pack = Pack()
        pack.write_short(20)
        pack.write_short(4)
        pack.write_bytes(Tlv.tlv008())
        pack.write_bytes(Tlv.tlv104(self.token0104))
        pack.write_bytes(Tlv.tlv116())
        pack.write_bytes(Tlv.tlv401())
        data = pack.get_all()
        data = teaEncrypt(data, self.sharekey)
        data = self.Pack_LoginHead('wtlogin.login', data, '10')
        data = self.Pack_Head(data, 1)
        return data

    def Unpack_QRreturn(self, maindata: bytes):
        resp = QRresponse()
        if len(maindata) == 0:
            resp.status = -1
            resp.msg = '包体解析错误'
            return resp
        up = Unpack(maindata)
        datalen = up.getInt()
        data = up.getAll()
        up.setData(data)
        up.getByte()
        datalen = up.getShort()
        up.getBin(10)
        t = up.getShort()
        verify = up.getByte()
        if verify == 0:
            data = up.getBin(datalen - 17)
        else:
            resp.status = verify
            resp.msg = '返回状态不为0'
            return resp
        data = teaDecrypt(data, self.sharekey)
        up.setData(data)
        up.getBin(9)
        cmd = up.getByte()
        if cmd == 49:
            up.getBin(45)
            self.verifysig = up.getBin(up.getShort())
            data = up.getAll()
            data = data[:-1]
            self.Unpack_Login_Tlv(data)
            resp.cmd = cmd
            resp.PicData = self.QRPicData
            resp.msg = 'suc'
            return resp
        elif cmd == 18:
            up.getBin(49)
            status = up.getByte()
            if status == 0:
                up.getInt()
                uin = up.getInt()
                self.initFromQQ(str(uin))
                up.getInt()
                data = up.getAll()
                data = data[:-1]
                self.Unpack_Login_Tlv(data)
            resp.cmd = cmd
            resp.status = status
            resp.msg = 'suc'
            return resp
        else:
            resp.cmd = cmd
            resp.status = -1
            resp.msg = 'suc'
            return resp

    def Unpack_Login(self, maindata: bytes):
        if len(maindata) == 0:
            return -1, '包体解析错误'
        up = Unpack(maindata)
        datalen = up.getInt()
        data = up.getAll()
        up.setData(data)
        up.getByte()
        datalen = up.getShort()
        up.getBin(10)
        t = up.getShort()
        verify = up.getByte()
        if verify == 0:  #登录成功
            pkt = up.getBin(datalen - 17)
            pkt = teaDecrypt(pkt, self.sharekey)
        elif verify == 160:  #设备真锁
            return verify, "需要验证设备锁"
        elif verify == 239:  #设备假锁
            return verify, "需要验证短信"
        elif verify == 204:  #验证码
            pkt = up.getBin(datalen - 17)
            pkt = teaDecrypt(pkt, self.sharekey)
            up.setData(pkt)
            up.getShort()
            up.getByte()
            pkt = up.getAll()
            self.Unpack_Login_Tlv(pkt)
            return verify, "需要再次发包"
        elif verify == 9:  #登录失败
            return verify, "登录失败！"
        elif verify == 1:  #账号密码错误
            return verify, "账号或者密码错误"
        elif verify == 40:  #账号冻结
            return verify, "账号冻结！"
        elif verify == 180:  #一般是组包错误
            return verify, "组包有错误"
        elif verify == 161:  #短信额度限制
            return verify, "短信额度限制"
        elif verify == 162:  #短信发送失败，可能是频率太快或额度限制
            return verify, "短信发送失败，可能是频率太快或额度限制"
        elif verify == 163:  #短信验证码输入错误
            return verify, "短信验证码输入错误"
        elif verify == 237:  #上网环境异常
            return verify, "环境异常，请重试"
        elif verify == 2:  #过滑块
            return verify, "需要过滑块"
        else:
            return verify, "未知登录类型"
        up.setData(pkt)
        up.getBin(7)
        datalen = up.getShort()
        pkt = up.getBin(datalen)
        pkt = teaDecrypt(pkt, self.tgtkey)
        self.Unpack_Login_Tlv(pkt)

        return 0, "登录成功！"

    def Unpack_Login_Tlv(self, pkt):
        up = Unpack(pkt)
        tlvnum = up.getShort()
        print('返回tlv个数:' + str(tlvnum))
        for i in range(tlvnum):
            tlvcmd = up.getBin(2)
            tlvlen = up.getShort()
            tlvdata = up.getBin(tlvlen)
            self.Unpack_Login_Key(bytes2hex(tlvcmd), tlvdata)

    def Unpack_Login_Key(self, cmd, data):
        cmd = cmd.strip()
        up = Unpack(data)
        if cmd == '01 0A':
            self.token010A = data
        elif cmd == '01 1A':
            up.getShort()
            age = up.getByte()
            sex = up.getByte()
            nicklen = up.getByte()
            nick = up.getBin(nicklen).decode('utf-8')
            print('昵称:' + nick)
        elif cmd == '01 43':
            self.token0143 = data
        elif cmd == '03 05':
            self.sessionKey = data
        elif cmd == '01 16':
            self.token0116 = data
        elif cmd == '01 04':
            self.token0104 = data
        elif cmd == '00 1E':
            self.tgtkey = data
        elif cmd == '00 17':
            self.QRPicData = data
        elif cmd == '00 18':
            self.tmpPwd = data
        elif cmd == '00 19':
            self.tmpNoPicSig = data
        elif cmd == '00 65':
            self.tgtQR = data
        else:
            pass

    def Pack_Online(self, mtype):
        pack = Pack()
        pack.write_int(self.requestId)
        pack.write_int(self.appid)
        pack.write_int(self.appid2)
        pack.write_hex('01 00 00 00 00 00 00 00 00 00 01 00')
        pack.write_hex('00 00 00 4C')
        pack.write_bytes(self.token010A)
        pack.write_int(len('StatSvc.register') + 4)
        pack.write_str('StatSvc.register')
        pack.write_hex('00 00 00 08')
        pack.write_bytes(self.msgCookies)
        pack.write_int(len(self.deviceimie) + 4)
        pack.write_str(self.deviceimie)
        if mtype == 0:
            pack.write_hex('00 00 00 04')
        else:
            pack.set_long_token(getRandomBin(16))
        pack.write_short(len(self.ver) + 2)
        pack.write_str(self.ver)
        pack.write_hex('00 00 00 04')
        headdata = pack.get_all()

        pack.set_empty()
        pack.write_hex(
            '10 03 2C 3C 4C 56 0B 50 75 73 68 53 65 72 76 69 63 65 66 0E 53 76 63 52 65 71 52 65 67 69 73 74 65 72 7D'
        )
        if mtype == 0:
            pack.write_hex('00 01 00 E6 08 00')
        elif mtype == 1:
            pack.write_hex('00 01 00 EA 08 00')
        elif mtype == 2:
            pack.write_hex('00 01 00 BD 08 00')
        pack.write_hex('01 06 0E 53 76 63 52 65 71 52 65 67 69 73 74 65 72')
        if mtype == 0:
            pack.write_hex('1D 00 01 00 CE 0A 03 00 00 00 00')
        elif mtype == 1:
            pack.write_hex('1D 00 01 00 D2 0A 03 00 00 00 00')
        elif mtype == 2:
            pack.write_hex('1D 00 01 00 A5 0A 03 00 00 00 00')
        pack.write_int(self.intqq)
        if mtype == 2:
            pack.write_hex('1C')
        else:
            pack.write_hex('10 07')
        pack.write_hex('2C 36 00')
        if mtype == 2:
            pack.write_hex('40 15')
        else:
            pack.write_hex('40 0B')
        pack.write_hex(
            '5C 6C 7C 8C 9C A0 75 B0 16 C0 01 D6 00 EC FD 10 00 00 10')
        pack.write_hex(self.deviceguid)
        pack.write_hex('F1 11 08 04 FC 12 F6 13')
        pack.write_bytes(int2bytes(len(self.devicename), 1))
        pack.write_str(self.devicename)
        pack.write_hex('F6 14')
        pack.write_bytes(int2bytes(len(self.devicename), 1))
        pack.write_str(self.devicename)
        pack.write_hex('F6 15 05')
        pack.write_hex('35 2E 31 2E 31')  #5.1.1
        pack.write_hex('F0 16 01')
        if mtype == 2:
            pack.write_hex('F1 17')
        else:
            pack.write_hex('F1 17 00 D7')
        pack.write_hex('FC 18')
        if mtype == 0:
            pack.write_hex('F3 1A 00 00 00 00 A6 3C 5E 7D F2 1B 5F 0D 60 71')
        elif mtype == 1:
            pack.write_hex(
                'F3 1A 00 00 00 00 D9 0C 60 71 F3 1B 00 00 00 00 A6 3C 5E 7D')
        elif mtype == 2:
            pack.write_hex('FC 1A FC 1B')
        pack.write_hex('F6 1C 00 FC 1D')
        if mtype == 2:
            pack.write_hex('F6 1E 00 F6 1F 00')
        else:
            pack.write_hex(
                'F6 1E 07 5B 75 5D 6F 70 70 6F F6 1F 14 3F 4C 59 5A 32 38 4E 3B 61 6E 64 72 6F 69 64 5F 78 38 36 2D'
            )
        pack.write_hex(
            'F6 20 00 FD 21 00 00 11 0A 08 08 2E 10 9A EF 9C FB 05 0A 05 08 9B 02 10 00 FC 22 FC 24'
        )
        if mtype == 2:
            pack.write_hex('F0 26 FF')
        else:
            pack.write_hex('FC 26')
        pack.write_hex('FC 27 FA 2A 00 01 0B 0B 8C 98 0C A8 0C')
        data = pack.get_all()

        pack.set_empty()
        pack.write_int(len(headdata) + 4)
        pack.write_bytes(headdata)
        pack.write_int(len(data) + 4)
        pack.write_bytes(data)
        data = pack.get_all()

        data = teaEncrypt(data, self.sessionKey)
        data = self.Pack_Head(data, 2)

        return data

    def Unpack_All(self, pkt: bytes):
        position = pkt.find(str2bytes(self.qq))
        if position == -1:
            position = pkt.find(hex2bytes('00 00 00 05 30'))
            if position == -1:
                return '', b''
            pkt = pkt[position + 5:]
        else:
            pkt = pkt[position + len(self.qq):]
        if len(self.sessionKey) != 0:
            pkt = teaDecrypt(pkt, self.sessionKey)
        else:
            pkt = teaDecrypt(pkt, bytes(16))
        up = Unpack(pkt)
        headlen = up.getInt()
        headdata = up.getBin(headlen - 4)
        maindata = up.getAll()
        up.setData(headdata)
        up.getInt()
        if up.getBin(4) == bytes(4):
            up.getBin(4)
        else:
            up.getBin(up.getInt() - 4)
        cmd = bytes2str(up.getBin(up.getInt() - 4))
        up.getBin(4)
        self.msgCookies = up.getBin(4)

        return cmd, maindata

    def Pack_FunHead(self, cmd, pkt: bytes):
        pack = Pack()
        pack.write_int(len(cmd) + 4)
        pack.write_str(cmd)
        pack.write_int(8)
        pack.write_bytes(self.msgCookies)
        pack.write_int(4)
        data = pack.get_all()

        pack.set_empty()
        pack.write_int(len(data) + 4)
        pack.write_bytes(data)
        pack.write_int(len(pkt) + 4)
        pack.write_bytes(pkt)
        return pack.get_all()

    def Pack_GetFriendMsg(self):
        data = PB_GetFriendMsg(self.syncCookies)
        data = self.Pack_FunHead('MessageSvc.PbGetMsg', data)
        data = teaEncrypt(data, self.sessionKey)
        data = self.Pack_Head(data, 3)
        return data

    def Pack_SendGroupMsg_raw(self, groupCode, rawmsg):
        data = PB_SendGroupMsg_raw(groupCode, rawmsg)
        data = self.Pack_FunHead('MessageSvc.PbSendMsg', data)
        data = teaEncrypt(data, self.sessionKey)
        data = self.Pack_Head(data, 3)
        return data

    def Pack_SendFriendMsg_raw(self, toUin, rawmsg):
        data = PB_SendFriend_raw(self.syncCookies, toUin, rawmsg)
        data = self.Pack_FunHead('MessageSvc.PbSendMsg', data)
        data = teaEncrypt(data, self.sessionKey)
        data = self.Pack_Head(data, 3)
        return data