import asyncio
from mcbot.utils.tools import *
import time
from AndroidQQ import AndroidQQ
from mcbot.response import QRresponse
from mcbot.protocol.decode import *
from mcbot.utils.unpack import Unpack
from socket import socket, AF_INET, SOCK_STREAM

LoginQQ = AndroidQQ()
s = socket(AF_INET, SOCK_STREAM)
s.connect(('113.96.12.224', 8080))

s.send(LoginQQ.getQRCode())
buf = s.recv(2048)
cmd, maindata = LoginQQ.Unpack_All(buf)
a, b = LoginQQ.Unpack_QRreturn(maindata)
print('获取二维码状态:', a, b)
with open('qrcode.png', 'wb') as f:
    f.write(LoginQQ.QRPicData)
for i in range(180):
    print('请在' + str(360 - i * 2) + '秒内扫码(' + str(a) + ')')
    s.send(LoginQQ.getQRStatus())
    buf = s.recv(2048)
    cmd, maindata = LoginQQ.Unpack_All(buf)
    a, b = LoginQQ.Unpack_QRStatus(maindata)
    if a == 0:
        break
    elif a == 53:
        print('已扫码，请确认登录')
    elif a == 54:
        print('您取消了扫码QAQ')
        exit(0)
    elif a == 17:
        print('二维码已失效...')
        exit(0)
    time.sleep(2)

s.send(LoginQQ.Pack_Login())
buf = s.recv(2048)
a, b = LoginQQ.Unpack_Login(buf)
print(len(LoginQQ.token0104))
while True:
    print("验证方式:", a, b)
    if a == 0:
        break
    elif a == 204:
        s.send(LoginQQ.Pack_Login_204())
        buf = s.recv(2048)
        a, b = LoginQQ.Unpack_Login(buf)
    else:
        exit(0)

s.send(LoginQQ.Pack_Online(0))
up = Unpack()
while True:
    buf = s.recv(2048)
    try:
        up.setData(buf)
        datalen = up.getInt()
        if datalen >= 10000:
            continue
        while len(buf) > datalen:
            LoginQQ.Unpack_All(int2bytes(datalen, 4) + up.getBin(datalen))
            buf = up.getAll()
            datalen = up.getInt()
        while len(buf) < datalen:
            buf = buf + s.recv(2048)
            up.setData(buf)
            datalen = up.getInt()
            while len(buf) > datalen:
                LoginQQ.Unpack_All(int2bytes(datalen, 4) + up.getBin(datalen))
                buf = up.getAll()
                datalen = up.getInt()
        LoginQQ.Unpack_All(buf)
    except Exception as e:
        print(e)
