# mcbot
~~为了应付某大作业,恰好此项目刚好满足大作业的需求,从而继续写了一点~~
qq-android协议的python实现

参考自：
[pymirai](https://github.com/synodriver/pymirai),[MiraiGo](https://github.com/Mrs4s/MiraiGo)

# 开始使用
    pip install -r requirements.txt
    python main.py

由于大作业要求是必须含有界面（？就使用了tk库。

# 已完成功能/开发计划
#### 登录
- [ ] 账号密码登录
- [x] 二维码登录
- [ ] 验证码提交
- [ ] 设备锁验证
- [ ] 错误信息解析

#### 消息类型
- [x] 文本
- [ ] 图片
- [ ] 语音
- [ ] 表情
- [ ] At
- [ ] 回复
- [ ] 长消息(仅群聊/私聊)
- [ ] 链接分享
- [ ] 小程序(暂只支持RAW)
- [ ] 短视频
- [ ] 合并转发
- [ ] 群文件(上传与接收信息)

#### 事件
- [x] 好友消息
- [x] 群消息
- [ ] 临时会话消息
- [ ] 登录号加群
- [ ] 登录号退群(包含T出)
- [ ] 新成员进群/退群
- [ ] 群/好友消息撤回 
- [ ] 群禁言
- [ ] 群成员权限变更
- [ ] 收到邀请进群通知
- [ ] 收到其他用户进群请求
- [ ] 新好友
- [ ] 新好友请求
- [ ] 客户端离线
- [ ] 群提示 (戳一戳/运气王等) 

#### 主动操作
> 为防止滥用，将不支持主动邀请新成员进群

- [x] 发送群消息
- [x] 发送好友消息
- [ ] 发送临时会话消息
- [ ] 获取/刷新群列表
- [ ] 获取/刷新群成员列表
- [ ] 获取/刷新好友列表
- [ ] 获取群荣誉 (龙王/群聊火焰等)
- [ ] 处理加群请求
- [ ] 处理被邀请加群请求
- [ ] 处理好友请求
- [ ] 撤回群消息
- [ ] 群公告设置
- [ ] 获取群文件下载链接
- [ ] 群设置 (全体禁言/群名)
- [ ] 修改群成员Card
- [ ] 修改群成员头衔
- [ ] 群成员邀请
- [ ] 群成员禁言/解除禁言
- [ ] T出群成员
- [ ] 戳一戳群友
- [ ] 获取陌生人信息

# 特别鸣谢
感谢[鸽子近卫军](https://github.com/synodriver)提供的帮助与支持
