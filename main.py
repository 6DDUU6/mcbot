import asyncio
from QQProtocol import QQProtocol
from tkinter import *
from threading import Thread
from PIL import Image, ImageTk


class Form(object):
    def __init__(self):
        # 窗口控件初始化
        self.root = Tk()
        self.root.geometry('600x500')
        self.root.title('手表QQ协议')
        self.lb1 = Label(self.root, text="群号/QQ号")
        self.lb1.place(x=1,y=8)
        self.en1 = Entry(self.root,width=15)
        self.en1.place(x=71,y=8)
        self.button_sendgroupmsg = Button(self.root,text="发送群消息",command=self.sendgroupmsg)
        self.button_sendgroupmsg.place(x=190,y=3)
        self.button_sendfriendmsg = Button(self.root,text="发送好友消息",command=self.sendfriendmsg)
        self.button_sendfriendmsg.place(x=270,y=3)
        self.text_send = Text(self.root, width=65, height=7)
        self.text_send.place(x=1,y=38)
        self.label_qr = Label(master=self.root)
        self.label_qr.place(x=465,y=1)
        self.log_data_text = Text(self.root, width=85, height=27)
        self.log_data_text.place(x=1,y=140)
        # 初始化连接腾讯服务器,获取二维码并显示窗口
        self.init()
        self.getqrcode()
        self.root.mainloop()

    def get_loop(self, loop):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def init(self):
        new_loop = asyncio.new_event_loop()
        self.loop = new_loop
        self._getqr_waiter = new_loop.create_future()
        t = Thread(target=self.get_loop, args=(new_loop, ))
        t.start()

    def getqrcode(self):
        coroutine = self.showqrcode()
        asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        coroutine = self.getqrstatus()
        asyncio.run_coroutine_threadsafe(coroutine, self.loop)

    def sendgroupmsg(self):
        togroup = self.en1.get()
        text = self.text_send.get('1.0','end')
        text = text[:-1]
        self.protocol.sendGroupMsg_raw(int(togroup),text)

    def sendfriendmsg(self):
        touin = self.en1.get()
        text = self.text_send.get('1.0','end')
        text = text[:-1]
        self.protocol.sendFriendMsg_raw(int(touin),text)

    def addlog(self, text):
        print(text)
        text = text + '\n'
        self.log_data_text.insert(END, text)
        self.log_data_text.see(END)

    async def connect_server(self):
        '''连接腾讯的tcp服务器,ip:113.96.12.224,port:8080'''
        self.transport, self.protocol = await self.loop.create_connection(
            lambda: QQProtocol(self.loop, self.log_data_text), '113.96.12.224',
            8080)
        return

    async def showqrcode(self):
        await self.connect_server()
        resp = await self.protocol.getQRCode()
        self.addlog('获取二维码:' + resp.msg)
        if resp.status == 0:
            self._getqr_waiter.set_result(0)  # 获取二维码成功啦，赶快告诉getqrstatus可以继续运行了
        with open('qrcode.png', 'wb') as f:
            f.write(resp.PicData)
        img_open = Image.open('qrcode.png')
        img = ImageTk.PhotoImage(img_open)
        self.label_qr.config(image=img)
        self.label_qr.image = img

    async def getqrstatus(self):
        await self._getqr_waiter  # 等待获取二维码成功
        flag = 0
        for i in range(180):
            self.addlog('请在' + str(360 - i * 2) + '秒内扫码')
            resp = await self.protocol.getQRCodeStatus()
            if resp.status == 0:
                break
            elif resp.status == 53:
                self.addlog('已扫码，请确认登录')
            elif resp.status == 54:
                self.addlog('您取消了扫码QAQ')
                flag = 1
                break
            elif resp.status == 17:
                self.addlog('二维码已失效...')
                flag = 1
                break
            await asyncio.sleep(2)
        else:
            self.addlog('您未在360s内扫码...')
            flag = 1
        self.addlog("获取到扫码QQ:" + self.protocol.LoginQQ.qq)
        if flag == 0:
            a, b = await self.protocol.login()
            while True:
                self.addlog("验证方式:" + str(a) + b)
                if a == 0:
                    self.protocol.StatSvc_register(0)
                    break
                elif a == 204:
                    a, b = await self.protocol.login204()
                else:
                    break


if __name__ == '__main__':
    form = Form()