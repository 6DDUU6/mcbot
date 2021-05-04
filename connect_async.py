import asyncio
from QQProtocol import QQProtocol
from mcbot.utils.tools import *
from AndroidQQ import AndroidQQ
from mcbot.response import QRresponse
from mcbot.protocol.decode import *
from mcbot.utils.unpack import Unpack

async def test():
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_connection(
        lambda: QQProtocol(loop), '113.96.12.224', 8080)
    resp = await protocol.getQRCode()
    print('获取二维码状态:', resp.status, resp.msg)
    with open('qrcode.png', 'wb') as f:
        f.write(resp.PicData)
    for i in range(180):
        print('请在' + str(360 - i * 2) + '秒内扫码(' + str(resp.status) + ')')
        resp = await protocol.getQRCodeStatus()
        if resp.status == 0:
            break
        elif resp.status == 53:
            print('已扫码，请确认登录')
        elif resp.status == 54:
            print('您取消了扫码QAQ')
            exit(0)
        elif resp.status == 17:
            print('二维码已失效...')
            exit(0)
        await asyncio.sleep(2)
    else:
        print('您未在360s内扫码...')
        exit(0)

    a, b = await protocol.login()
    while True:
        print("验证方式:", a, b)
        if a == 0:
            break
        elif a == 204:
            a, b = await protocol.login204()
        else:
            exit(0)
    await protocol.StatSvc_register(0)

    while True:
        await asyncio.sleep(2)


if __name__ == '__main__':
    asyncio.run(test())