from mcbot.utils.pack import Pack
from mcbot.utils.unpack import Unpack
from mcbot.utils.tools import bytes2hex, _bytes2hex
import mcbot.pb.msg.msg_pb2 as recvmsg
import time


def Unpack_PbPushGroupMsg(data, logtext):
    data = data[4:]
    msg = recvmsg.PushMessagePacket()
    msg.ParseFromString(data)
    fromUin = msg.message.head.fromUin
    groupCard = msg.message.head.groupInfo.groupCard
    groupCode = msg.message.head.groupInfo.groupCode
    groupName = msg.message.head.groupInfo.groupName
    content = ""
    for elem in msg.message.body.richText.elems:
        if elem.HasField("text"):  # 文本
            content += elem.text.str
        if elem.HasField("customFace"):  # 图片或动画表情
            content += "[pic,hash=" + _bytes2hex(
                elem.customFace.md5
            ) + ",url=http://gchat.qpic.cn" + elem.customFace.origUrl + "]"
    if content != "":
        ret = "收到群 " + groupName.decode('utf-8','ignore') + "(" + str(
            groupCode) + ") " + groupCard + "(" + str(
                fromUin) + ")的消息: " + content
        print(ret)
        logtext.insert('end', ret + '\n')
        logtext.see('end')


def Unpack_PbGetMsg(data, logtext):
    data = data[4:]
    msg = recvmsg.GetMessageResponse()
    msg.ParseFromString(data)
    syncCookies = msg.syncCookie
    for upm in msg.uinPairMsgs:
        fromUin = upm.peerUin
        content = ""
        for message in upm.messages:
            content = ""
            for elem in message.body.richText.elems:
                if elem.HasField("text"):  # 文本
                    content += elem.text.str
                if elem.HasField("notOnlineImage"):  # 图片或动画表情
                    content += "[pic,hash=" + _bytes2hex(
                        elem.notOnlineImage.picMd5
                    ) + ",url=http://gchat.qpic.cn" + elem.notOnlineImage.origUrl + "]"
        if content != "":
            ret = "收到好友 (" + str(fromUin) + ") 的消息: " + content
            print(ret)
            logtext.insert('end', ret + '\n')
            logtext.see('end')
    return syncCookies
