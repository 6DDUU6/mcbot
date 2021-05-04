import mcbot.pb.msg.msg_pb2 as sendmsg
from random import randint


def PB_SendGroupMsg_raw(groupCode, rawmsg) -> bytes:
    send = sendmsg.SendMessageRequest()
    send.routingHead.grp.groupCode = groupCode
    send.contentHead.pkgNum = 1
    send.contentHead.pkgIndex = 0
    send.contentHead.divSeq = 0
    send.msgBody.richText.elems.add().text.str = rawmsg
    send.msgSeq = randint(5000, 99999)
    send.msgRand = randint(10000000, 2147483648)
    send.msgVia = 0
    return send.SerializeToString()

def PB_SendFriend_raw(syncCookies, toUin, rawmsg) -> bytes:
    send = sendmsg.SendMessageRequest()
    send.routingHead.c2c.toUin = toUin
    send.contentHead.pkgNum = 1
    send.contentHead.pkgIndex = 0
    send.contentHead.divSeq = 0
    send.msgBody.richText.elems.add().text.str = rawmsg
    send.msgSeq = randint(5000, 99999)
    send.msgRand = randint(10000000, 2147483648)
    send.syncCookie = syncCookies
    send.msgVia = 1
    return send.SerializeToString()

def PB_GetFriendMsg(syncCookies) -> bytes:
    send = sendmsg.GetMessageRequest()
    send.syncFlag = sendmsg.SyncFlag.START
    send.syncCookie = syncCookies
    send.rambleFlag = 0
    send.latestRambleNumber = 20
    send.otherRambleNumber = 3
    send.onlineSyncFlag = 1
    send.contextFlag = 1
    send.msgReqType = 0
    send.serverBuf = bytes()
    return send.SerializeToString()