import asyncio
from typing import Tuple
from mcbot.utils.tools import *
from AndroidQQ import AndroidQQ
from mcbot.response import QRresponse
from mcbot.protocol.decode import *
from mcbot.utils.unpack import Unpack


class QQProtocol(asyncio.Protocol):
    def __init__(self, loop, logText):
        self.log_data_text = logText  # 这产生了耦合...不过既然是大作业，也没办法啦
        self._loop = loop or asyncio.get_event_loop()
        self.transport: asyncio.Transport = None
        self._login_waiter: asyncio.Future = None
        self._getQRCode_waiter: asyncio.Future = None
        self._getQRCodestatus_waiter: asyncio.Future = None
        self._closed_waiter = self._loop.create_future()

        self.lastbuf = bytes()
        self.lastbuflen = 0
        self.lastlen = 0

    def connection_made(self, transport: asyncio.Transport) -> None:
        self.transport = transport

    def connection_lost(self, exc) -> None:
        if exc:
            self._closed_waiter.set_exception(exc)
        else:
            self._closed_waiter.set_result(None)
        self.transport = None

    def data_received(self, data: bytes) -> None:
        tlen = len(data)
        up = Unpack(data)
        if self.lastlen > 0:
            datalen = self.lastlen
            tlen += self.lastbuflen
            up.setData(self.lastbuf + data)
        else:
            datalen = up.getInt()
        if datalen > tlen:
            self.lastbuf = self.lastbuf + data
            self.lastlen = datalen
            self.lastbuflen = tlen
            return
        self.lastbuf = bytes()
        self.lastlen = 0
        self.lastbuflen = 0
        while tlen != 0:
            buf = int2bytes(datalen, 4) + up.getBin(datalen)
            cmd, maindata = self.LoginQQ.Unpack_All(buf)
            print('收到命令:' + cmd)
            if cmd == 'wtlogin.trans_emp':  # 扫码返回包
                resp = self.LoginQQ.Unpack_QRreturn(maindata)
                if resp.cmd == 49:
                    self._getQRCode_waiter.set_result(resp)
                elif resp.cmd == 18:
                    self._getQRCodestatus_waiter.set_result(resp)
            elif cmd == 'wtlogin.login':  # 登录包
                a, b = self.LoginQQ.Unpack_Login(maindata)
                self._login_waiter.set_result((a, b))
            elif cmd == 'OnlinePush.PbPushGroupMsg':  # 收到群消息
                Unpack_PbPushGroupMsg(maindata, self.log_data_text)  # 反正都已经耦合了，不妨再耦合一点？直接把控件传进去
            elif cmd == 'MessageSvc.PushNotify':  # 收到好友状态
                self.transport.write(self.LoginQQ.Pack_GetFriendMsg())
            elif cmd == 'MessageSvc.PbGetMsg':  # 收到好友消息
                syncCookies = Unpack_PbGetMsg(maindata, self.log_data_text)
                self.LoginQQ.setSyncCookies(syncCookies)
            tlen -= datalen
            datalen = up.getInt()

    async def getQRCode(self) -> Tuple[int, str, AndroidQQ]:
        assert self._getQRCode_waiter is None
        self._getQRCode_waiter = self._loop.create_future()
        try:
            self.LoginQQ = AndroidQQ()
            self.transport.write(self.LoginQQ.getQRCode())
            return await self._getQRCode_waiter
        finally:
            self._getQRCode_waiter = None

    async def getQRCodeStatus(self):
        assert self._getQRCodestatus_waiter is None
        self._getQRCodestatus_waiter = self._loop.create_future()
        try:
            self.transport.write(self.LoginQQ.getQRStatus())
            return await self._getQRCodestatus_waiter
        finally:
            self._getQRCodestatus_waiter = None

    async def login(self):
        assert self._login_waiter is None
        self._login_waiter = self._loop.create_future()
        try:
            self.transport.write(self.LoginQQ.Pack_Login())
            return await self._login_waiter
        finally:
            self._login_waiter = None

    async def login204(self):
        assert self._login_waiter is None
        self._login_waiter = self._loop.create_future()
        try:
            self.transport.write(self.LoginQQ.Pack_Login_204())
            return await self._login_waiter
        finally:
            self._login_waiter = None

    def StatSvc_register(self, mtype):
        self.transport.write(self.LoginQQ.Pack_Online(mtype))

    def sendGroupMsg_raw(self, groupCode, rawmsg):
        self.transport.write(
            self.LoginQQ.Pack_SendGroupMsg_raw(groupCode, rawmsg))

    def sendFriendMsg_raw(self, toUin, rawmsg):
        self.transport.write(
            self.LoginQQ.Pack_SendFriendMsg_raw(toUin, rawmsg))
