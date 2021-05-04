class QRresponse():
    def __init__(self):
        self.cmd = 0
        self.status = 0
        self.PicData = bytes()
        self.msg = ''

class Msgresponse():
    def __init__(self):
        self.msg_content = ''
        self.msgtype = 0
        self.status = 0