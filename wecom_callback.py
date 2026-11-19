#!/usr/bin/env python3
"""企微自建应用回调桥 v2.1：TG 3 号机器人同款功能菜单。

部署在 NAS 的 Docker 容器里，作为企微自建应用的回调服务器。
和 v1.0（智能机器人长连接）不同，v2 走的是自建应用 + 回调 URL：

- 企微管理后台 → 应用 → 接收消息 → 设置 API 接收，填 URL / Token / EncodingAESKey；
- 用户在应用里发消息、点底部菜单，企微把回调 POST 到这个服务；
- 服务 5 秒内回 "success"（慢活丢后台线程做），再用自建应用接口主动把答案发回去。

为什么 v2 存在：朋友走的就是这条路。底部常驻菜单只有自建应用才有，
菜单点击以事件形式走回调；智能机器人频道能回消息、没有菜单。
两条路各有各的卡点，v1 的卡点在 Muse VM（vault 密钥进不了 WebSocket 帧，
853000），v2 的卡点在“回调地址要公网可达 + 发消息要可信 IP”——
这两点在 NAS 上都能解（已有 Lucky 反代域名；可信 IP 在管理后台手动加家里出口 IP）。

安全规则（硬性）：
- 全部凭证（CorpID、Secret、AgentId、Token、EncodingAESKey、LLM Key）
  只从环境变量读，绝不写进代码、README、日志。
  日志只记“已配置 / 长度 N 位”，绝不记值。
- 不 import 任何 Muse vault / dynamic_credentials 助手。
- OWNER_USERIDS 为空时拒绝所有消息（fail safe），绝不放行陌生人。
- v2 不执行任何破坏性操作（停/启/重启容器、重启 NAS），只读 + 聊天。
  破坏性请求一律回绝，并指到 Telegram 3 号机器人去确认执行。
  v2.1 起：破坏性操作（启动/停止/重启/更新容器、清理镜像、VM 电源、
  重启 NAS、自我更新安装）改走两步确认卡片（✅ 确认 / ❌ 取消），
  确认令牌 5 分钟过期，绝不在一次点击、一条文字命令里直接执行。
- LLM 调用失败只回一句人话，绝不把 traceback 发给用户。

渲染规则（硬性，用户亲测）：
- 绝不把 NAS 状态 / 磁盘 / 温度发成 emoji 彩条文本块：
  企微里会从色条中间换行、错位，比 Telegram 难看得多。
- 状态 / 磁盘详情 / 温度详情一律发模板卡片（button_interaction）：
  主标题 + 横向 key-value 行（每行一个值，短，不换行）+ 按钮行
  （温度详情 / 磁盘详情 / 刷新 / 主菜单）。
- 容器列表发 markdown 短行：每容器一行（状态点 + 名字 + 状态），不带彩条、不带镜像长行。
- LLM 聊天回复保持 markdown 短段落。

协议来源：企业微信开发者中心《接收消息》（自建应用回调）
https://developer.work.weixin.qq.com/document/path/90930
关键格式（官方 WXBizMsgCrypt 样本逻辑，不要凭记忆改）：
- 签名：sha1(sorted([token, timestamp, nonce, encrypt_msg]) 拼起来)。
  GET 验证时 encrypt_msg = echostr；POST 解密时 encrypt_msg = 信封里的 Encrypt。
- 加密：明文 = 16 字节随机 + 4 字节大端消息长度 + 消息 + corpid，
  PKCS7 补到 32 字节倍数，AES-256-CBC（key = base64 解码 EncodingAESKey，
  IV = key 前 16 字节），再 base64。解密反过来，并校验 corpid。
- GET /wecom/callback：验签 → 解密 echostr → 原样返回明文 echostr。
- POST /wecom/callback：信封 <xml><ToUserName/><Encrypt/><AgentID/></xml>，
  验签 → 解密得到内层 XML（<MsgType>text</MsgType><Content/>… 或
  <MsgType>event</MsgType><Event>click</Event><EventKey>MENU_*</EventKey>）。
- 5 秒内必须回 "success"，否则企微重试 3 次；所以 POST 处理只做
  验签/解密/解析/排重，然后把活丢给后台线程，立即回 "success"。
  真正的答案之后用 gettoken + message/send 主动发给用户。
- message/send 文本内容最长 2048 字节，超长分多条发。
- 模板卡片（message/send 的 template_card msgtype）：
  button_interaction 卡片 = main_title + horizontal_content_list（最多 6 行，
  keyname 建议不超过 5 个字，value 建议不超过 30 个字）
  + button_list（最多 6 个按钮，每个按钮 {text, style, key}）+ task_id（每发一次唯一）。
  点按钮后回调推 template_card_event 事件，EventKey 就是按钮的 key，
  TaskId 是发卡片时填的 task_id。v2 收到点击后发一条新消息作答，
  不调 update_template_card 原地改卡。
- 自定义菜单：POST /cgi-bin/menu/create?access_token=..&agentid=..，
  一级最多 3 个按钮（名字 ≤16 字节），子菜单最多 5 个、只允许一级子菜单，
  菜单 key ≤128 字节。
- v2.1 与 TG 3 号的取舍（详见 README）：卡片每张最多 6 个按钮，
  所以容器管理页用编号列表 + 回复序号选容器（TG 是每容器一个按钮），
  容器详情卡 6 个操作按钮、返回靠底部菜单；“给 Muse 下指令”跳转按钮
  在企微没有等价物，已省略；/docker 的启停命令在 TG 是直接执行，
  在企微一律先出确认卡。
"""

import base64
import concurrent.futures
import glob
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import requests
from flask import Flask, request

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - 部署时 requirements.txt 会装好
    AES = None

VERSION = "2.1.1"

# ---------------- 配置（只从环境变量读） ----------------

WECOM_CORPID = os.environ.get("WECOM_CORPID", "").strip()
WECOM_SECRET = os.environ.get("WECOM_SECRET", "").strip()  # 自建应用 Secret，只在内存里用
WECOM_AGENTID = os.environ.get("WECOM_AGENTID", "").strip()
WECOM_TOKEN = os.environ.get("WECOM_TOKEN", "").strip()     # 回调 Token，只在内存里用
WECOM_AESKEY = os.environ.get("WECOM_AESKEY", "").strip()   # 回调 EncodingAESKey，只在内存里用
OWNER_USERIDS = {u.strip() for u in os.environ.get("OWNER_USERIDS", "").split(",") if u.strip()}
LLM_API_BASE = os.environ.get("LLM_API_BASE", "https://api.anyrouter.top/v1").strip() or "https://api.anyrouter.top/v1"
LLM_API_KEY = os.environ.get("LLM_API_KEY", "").strip()
LLM_MODEL = os.environ.get("LLM_MODEL", "muse-spark").strip() or "muse-spark"
BOT_NAME = os.environ.get("BOT_NAME", "Marlowe").strip() or "Marlowe"
CALLBACK_PORT = int(os.environ.get("WECOM_CALLBACK_PORT", "18789"))
DATA_DIR = os.environ.get("DATA_DIR", "/data")
DOCKER_SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")


def _env_int(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_float(name, default):
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


# ESXi（可选）：填了才能用 ESXi VM、重启 NAS；不填时相关功能回一句“未配置”。
ESXI_HOST = os.environ.get("ESXI_HOST", "").strip()
ESXI_USER = os.environ.get("ESXI_USER", "root").strip() or "root"
ESXI_PASSWORD = os.environ.get("ESXI_PASSWORD", "")
ESXI_KEY_FILE = os.environ.get("ESXI_KEY_FILE", "").strip()
NAS_VM_NAME = os.environ.get("NAS_VM_NAME", "").strip()
NAS_VM_ID = os.environ.get("NAS_VM_ID", "").strip()
# 自我更新（可选）：UPDATE_REPO 例如 wdw6733/wecom-callback-bridge，
# 仓库根目录放 wecom_callback.py；私有仓库再填 UPDATE_TOKEN（只读）。
UPDATE_REPO = os.environ.get("UPDATE_REPO", "").strip()
UPDATE_BRANCH = os.environ.get("UPDATE_BRANCH", "main").strip() or "main"
UPDATE_TOKEN = os.environ.get("UPDATE_TOKEN", "").strip()
SELF_CONTAINER_NAME = os.environ.get("SELF_CONTAINER_NAME", "wecom-callback").strip() or "wecom-callback"
# 主动告警（可选，默认开；阈值与 bot3 3 号机器人一致）
ALERT_ENABLED_DEFAULT = os.environ.get("ALERT_ENABLED", "1").strip() not in ("0", "false", "no")
ALERT_INTERVAL_SEC = _env_int("ALERT_INTERVAL_SEC", 300)
ALERT_DISK_PCT = _env_float("ALERT_DISK_PCT", 90)
ALERT_LOAD_MULT = _env_float("ALERT_LOAD_MULT", 2.0)
ALERT_MEM_PCT = _env_float("ALERT_MEM_PCT", 92)
ALERT_COOLDOWN_SEC = _env_int("ALERT_COOLDOWN_SEC", 3600)
# 容器镜像更新检查（可选，默认开；与 bot3 一致，每 6 小时自动检查一次）
IMAGE_CHECK_ENABLED = os.environ.get("IMAGE_CHECK_ENABLED", "1").strip() not in ("0", "false", "no")
IMAGE_CHECK_INTERVAL_SEC = _env_int("IMAGE_CHECK_INTERVAL_SEC", 21600)
_HOST_DATA_PATHS_RAW = os.environ.get("HOST_DATA_PATHS", "").strip()
# 留空默认看 /mnt/PT 和 /mnt/Strongge（NAS 的两个数据目录）；.env 里填了就按填的来。
HOST_DATA_PATHS = [p.strip() for p in _HOST_DATA_PATHS_RAW.split(",") if p.strip()] or ["/mnt/PT", "/mnt/Strongge"]
MSGID_TTL_SEC = 600           # MsgId 去重缓存 10 分钟
LLM_TIMEOUT_SEC = 120
MAX_ANSWER_CHARS = 6000       # 单次回答截断长度（再按 2048 字节分条发）
MAX_TEXT_BYTES = 2048         # 自建应用 message/send 文本上限（官方规定）
WECOM_API_BASE = "https://qyapi.weixin.qq.com"

SYSTEM_PROMPT = (
    f"你是 {BOT_NAME}，ww 的个人助理。用简洁中文回答，"
    "讲清楚是什么、用来干什么、怎么用即可，不要考试级深度，"
    "不要编造没有把握的命令、价格或配置。"
)

WELCOME_TEXT = (
    f"你好，我是{BOT_NAME}，企微通道已接通 ✅\n"
    "底部菜单可以直接点，也可以直接发指令。\n"
    "可以问我：系统状态、磁盘空间、容器列表、容器日志 <名字>，"
    "也可以直接聊天提问。\n"
    "危险操作（启停/更新容器、重启 NAS 等）要点两次确认才会执行。"
)
REFUSAL_TEXT = "抱歉，我只认主人。请联系管理员把你的企微 userid 加进白名单。"
OWNER_EMPTY_HINT = "OWNER_USERIDS 为空，已拒绝全部消息。请在 .env 里填 OWNER_USERIDS。"
DESTRUCTIVE_TEXT = (
    "这个操作我现在不能直接执行，需要你确认。\n"
    "请去 Telegram 3 号机器人那里点按钮确认执行（重启/停止容器、重启 NAS 都走那边确认流程）。"
)
LLM_NOT_CONFIGURED_TEXT = (
    "聊天功能还没配好：.env 里没有填 LLM_API_KEY。\n"
    "本地查询（系统状态 / 磁盘空间 / 容器列表 / 容器日志）不受影响，可以直接问。"
)
LLM_ERROR_TEXT = "抱歉，聊天服务刚才出问题了，稍后再试一次。本地查询不受影响。"
TEMP_UNAVAILABLE_TEXT = (
    "VM 内读不到温度传感器。NAS 是 ESXi 上的虚拟机，传感器一般不直通进 VM；"
    "温度请看 ESXi 主机或 TrueNAS 界面。"
)
ESXI_NOT_CONFIGURED_TEXT = (
    "ESXi 未配置：在 .env 里填 ESXI_HOST / ESXI_USER / ESXI_PASSWORD 后重启容器。"
)
NAS_REBOOT_NOT_CONFIGURED_TEXT = (
    "重启 NAS 还差一步：在 .env 里填 NAS_VM_NAME（NAS 这个 VM 在 ESXi 里的名字，"
    "或用 NAS_VM_ID 填 ID），然后 docker compose up -d --build 重启容器。"
    "填好后这个功能才能用。"
)
SELFUPDATE_NOT_CONFIGURED_TEXT = (
    "自我更新未配置。\n\n"
    "要在 .env 里填 UPDATE_REPO（例如 wdw6733/wecom-callback-bridge，"
    "仓库根目录放 wecom_callback.py），私有仓库再填 UPDATE_TOKEN（只读）。"
    "填好后重启容器，这个功能才能检查更新。"
)

HELP_TEXT = (
    f"你好，我是{BOT_NAME}。\n"
    "本地查询（直接发，或点底部菜单）：\n"
    "· 系统状态 / 公网 IP / 磁盘空间 / 温度 / 进程 TOP / 网络流量\n"
    "· 容器列表 / 容器管理 / 容器资源 / 检查容器更新 / 清理镜像\n"
    "· ESXi VM / 告警 / 检查更新（自我更新）\n"
    "· 容器日志 <容器名> [行数] [关键词]\n"
    "命令也一样能用：/status /docker /esxi /disk /check_updates /alerts /menu /help\n"
    "危险操作（启停/更新容器、清理镜像、VM 电源、重启 NAS、自我更新安装）\n"
    "都会先出一张确认卡，点 ✅ 确认才会执行，5 分钟内有效。"
)

# 菜单点击 → 等价的文字指令（走同一套 handle_text 路由）
# 底部菜单 3 个一级 × 每个 5 个子项，与 TG 3 号主菜单一一对应：
# 总览 = 系统状态/公网 IP/磁盘空间/温度/帮助；
# 容器 = 容器列表/容器管理/容器资源/检查容器更新/清理镜像；
# 更多 = ESXi VM/网络流量/进程 TOP/告警/检查更新（自我更新）。
# 一级名字 ≤4 个汉字、子项 ≤7 个汉字、key ≤128 字节（官方限制，见 README）。
MENU_KEY_TO_TEXT = {
    "MENU_STATUS": "系统状态",
    "MENU_IP": "公网 IP",
    "MENU_DISK": "磁盘空间",
    "MENU_TEMP": "温度",
    "MENU_HELP": "帮助",
    "MENU_CONTAINERS": "容器列表",
    "MENU_MANAGE": "容器管理",
    "MENU_STATS": "容器资源",
    "MENU_CHECK_UPDATES": "检查容器更新",
    "MENU_PRUNE": "清理镜像",
    "MENU_ESXI": "ESXi VM",
    "MENU_NET": "网络流量",
    "MENU_TOP": "进程 TOP",
    "MENU_ALERTS": "告警",
    "MENU_SELFUPDATE": "检查更新",
}

# 破坏性操作关键词：v2 一律不执行，只回绝 + 记日志
DESTRUCTIVE_KEYWORDS = (
    "重启容器", "停止容器", "启动容器", "删除容器", "停容器", "删容器",
    "重启nas", "重启 nas", "重启服务器", "重启主机", "关机", "重启系统",
    "docker restart", "docker stop", "docker start", "docker rm",
    "reboot", "shutdown", "poweroff",
)


def log(*args):
    """日志：时间戳 + 内容。调用处保证绝不传入任何凭证值。"""
    print(time.strftime("[%Y-%m-%d %H:%M:%S]"), *args, flush=True)


def cst_now():
    return (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")


# ---------------- 加解密（WXBizMsgCrypt 官方样本逻辑） ----------------

def calc_signature(token, timestamp, nonce, encrypt_msg):
    """sha1(sorted([token, timestamp, nonce, encrypt_msg]) 拼起来的字符串)。"""
    parts = sorted([token, timestamp, nonce, encrypt_msg])
    return hashlib.sha1("".join(parts).encode("utf-8")).hexdigest()


def _pkcs7_pad(data, block_size=32):
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data, block_size=32):
    if not data:
        raise ValueError("解密后内容为空")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("PKCS7 填充长度非法")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("PKCS7 填充校验失败")
    return data[:-pad_len]


class WXBizMsgCrypt:
    """企业微信官方 WXBizMsgCrypt 的等价实现（Python）。

    token：回调 Token；encoding_aes_key：43 位 EncodingAESKey；
    corpid：企业 ID（解密时校验，收到的消息必须属于本企业）。
    """

    def __init__(self, token, encoding_aes_key, corpid):
        if AES is None:
            raise RuntimeError("缺少 pycryptodome，请检查 requirements.txt 是否装好")
        if len(encoding_aes_key) != 43:
            raise ValueError("EncodingAESKey 必须是 43 位字符")
        self.token = token
        self.corpid = corpid
        self.key = base64.b64decode(encoding_aes_key + "=")
        if len(self.key) != 32:
            raise ValueError("EncodingAESKey 解码后不是 32 字节")
        self.iv = self.key[:16]

    def encrypt_msg(self, plaintext):
        """加密一段明文（str），返回 base64 字符串。"""
        msg = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
        raw = os.urandom(16) + struct.pack(">I", len(msg)) + msg + self.corpid.encode("utf-8")
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(_pkcs7_pad(raw))).decode("ascii")

    def decrypt_msg_bytes(self, encrypt_msg):
        """解密 base64 密文，返回明文 bytes（已校验 corpid）。"""
        try:
            ciphertext = base64.b64decode(encrypt_msg)
        except Exception as e:
            raise ValueError(f"密文不是合法 base64：{e}")
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        try:
            raw = _pkcs7_unpad(cipher.decrypt(ciphertext))
        except ValueError as e:
            raise ValueError(f"解密失败：{e}")
        if len(raw) < 20:
            raise ValueError("解密后内容过短")
        msg_len = struct.unpack(">I", raw[16:20])[0]
        msg = raw[20:20 + msg_len]
        appid = raw[20 + msg_len:].decode("utf-8", errors="replace")
        if appid != self.corpid:
            raise ValueError("解密出的 corpid 与配置不符")
        if len(msg) != msg_len:
            raise ValueError("解密出的消息长度与标称长度不符")
        return msg

    def verify_url(self, msg_signature, timestamp, nonce, echostr):
        """GET 验证：验签 → 解密 echostr → 返回明文 echostr。验签/解密失败抛 ValueError。"""
        expect = calc_signature(self.token, timestamp, nonce, echostr)
        if expect != msg_signature:
            raise ValueError("URL 验证签名不匹配")
        return self.decrypt_msg_bytes(echostr).decode("utf-8")

    def decrypt_msg(self, post_xml, msg_signature, timestamp, nonce):
        """POST 解密：从信封 XML 取 Encrypt → 验签 → 解密 → 返回内层 XML 字符串。"""
        try:
            root = ET.fromstring(post_xml)
        except ET.ParseError as e:
            raise ValueError(f"回调 XML 解析失败：{e}")
        encrypt_el = root.find("Encrypt")
        if encrypt_el is None or not encrypt_el.text:
            raise ValueError("回调 XML 里没有 Encrypt 字段")
        encrypt_msg = encrypt_el.text.strip()
        expect = calc_signature(self.token, timestamp, nonce, encrypt_msg)
        if expect != msg_signature:
            raise ValueError("回调消息签名不匹配")
        return self.decrypt_msg_bytes(encrypt_msg).decode("utf-8")


# ---------------- XML 解析（纯函数，可单测） ----------------

def _xml_text(root, tag):
    el = root.find(tag)
    return (el.text or "").strip() if el is not None else ""


def parse_inner_message(inner_xml):
    """解析解密后的内层消息 XML，返回 dict。

    文本消息：{"kind": "text", "from_user": ..., "content": ..., "msgid": ...,
              "create_time": ...}
    菜单点击：{"kind": "click", "from_user": ..., "event_key": ...,
              "create_time": ...}
    其他：{"kind": <msgtype 或 event>, ...}，调用方按需处理。
    """
    try:
        root = ET.fromstring(inner_xml)
    except ET.ParseError as e:
        raise ValueError(f"内层消息 XML 解析失败：{e}")
    msgtype = _xml_text(root, "MsgType")
    base = {
        "msgtype": msgtype,
        "from_user": _xml_text(root, "FromUserName"),
        "create_time": _xml_text(root, "CreateTime"),
        "msgid": _xml_text(root, "MsgId"),
    }
    if msgtype == "text":
        base["kind"] = "text"
        base["content"] = _xml_text(root, "Content")
        return base
    if msgtype == "event":
        event = _xml_text(root, "Event")
        base["kind"] = "click" if event == "click" else event
        base["event"] = event
        base["event_key"] = _xml_text(root, "EventKey")
        base["task_id"] = _xml_text(root, "TaskId")
        base["response_code"] = _xml_text(root, "ResponseCode")
        if event == "template_card_event":
            base["kind"] = "card_click"
        return base
    base["kind"] = msgtype or "unknown"
    return base


def validate_menu_payload(payload):
    """按官方限制校验菜单：返回错误提示，否则返回 None。

    一级 1-3 个、名字 ≤16 字节；子菜单 1-5 个、只允许一级；
    key ≤128 字节。名字再按更严的习惯收紧（一级 ≤4 汉字、子项 ≤7 汉字），
    超了企微客户端会截断成“…”。
    """
    buttons = payload.get("button") or []
    if not (1 <= len(buttons) <= 3):
        return f"一级菜单个数不对：{len(buttons)}（应为 1-3 个）"
    seen_keys = set()
    for b in buttons:
        name = b.get("name", "")
        if len(name.encode("utf-8")) > 16:
            return f"一级菜单名字太长：{name}"
        if len(name) > 4:
            return f"一级菜单名字超过 4 个汉字：{name}"
        sub = b.get("sub_button") or []
        if sub:
            if not (1 <= len(sub) <= 5):
                return f"子菜单个数不对：{len(sub)}（应为 1-5 个）"
            if "key" in b or "type" in b:
                return f"带子菜单的一级按钮不能同时有 key/type：{name}"
            for s in sub:
                if s.get("sub_button"):
                    return f"子菜单不能再嵌套：{s.get('name')}"
                sname = s.get("name", "")
                if len(sname.encode("utf-8")) > 40:
                    return f"子菜单名字太长：{sname}"
                if len(sname) > 7:
                    return f"子菜单名字超过 7 个汉字：{sname}"
                key = s.get("key", "")
                if not key or len(key.encode("utf-8")) > 128:
                    return f"子菜单 key 非法：{sname}"
                if key in seen_keys:
                    return f"菜单 key 重复：{key}"
                seen_keys.add(key)
        else:
            key = b.get("key", "")
            if not key or len(key.encode("utf-8")) > 128:
                return f"一级菜单 key 非法：{name}"
            if key in seen_keys:
                return f"菜单 key 重复：{key}"
            seen_keys.add(key)
    return None


def build_menu_payload():
    """自建应用自定义菜单（menu/create 的 body），3 个一级 × 每个 5 个子项。

    总览 = 系统状态/公网 IP/磁盘空间/温度/帮助；
    容器 = 容器列表/容器管理/容器资源/检查容器更新/清理镜像；
    更多 = ESXi VM/网络流量/进程 TOP/告警/检查更新（自我更新）。
    key 与 MENU_KEY_TO_TEXT 对应。重启 NAS 不进菜单（TG 里也要点两次确认，
    企微这里只接受文字“重启 NAS”再出确认卡，绝不一键触发）。
    “给 Muse 下指令”跳转按钮在企微没有等价物，已省略（见 README）。
    """
    return {
        "button": [
            {"name": "总览", "sub_button": [
                {"type": "click", "name": "系统状态", "key": "MENU_STATUS"},
                {"type": "click", "name": "公网 IP", "key": "MENU_IP"},
                {"type": "click", "name": "磁盘空间", "key": "MENU_DISK"},
                {"type": "click", "name": "温度", "key": "MENU_TEMP"},
                {"type": "click", "name": "帮助", "key": "MENU_HELP"},
            ]},
            {"name": "容器", "sub_button": [
                {"type": "click", "name": "容器列表", "key": "MENU_CONTAINERS"},
                {"type": "click", "name": "容器管理", "key": "MENU_MANAGE"},
                {"type": "click", "name": "容器资源", "key": "MENU_STATS"},
                {"type": "click", "name": "检查容器更新", "key": "MENU_CHECK_UPDATES"},
                {"type": "click", "name": "清理镜像", "key": "MENU_PRUNE"},
            ]},
            {"name": "更多", "sub_button": [
                {"type": "click", "name": "ESXi VM", "key": "MENU_ESXI"},
                {"type": "click", "name": "网络流量", "key": "MENU_NET"},
                {"type": "click", "name": "进程 TOP", "key": "MENU_TOP"},
                {"type": "click", "name": "告警", "key": "MENU_ALERTS"},
                {"type": "click", "name": "检查更新", "key": "MENU_SELFUPDATE"},
            ]},
        ]
    }


# ---------------- 去重 ----------------

class DedupCache:
    """MsgId / 事件去重缓存，TTL 默认 10 分钟（企微失败会重试 3 次）。"""

    def __init__(self, ttl_sec=MSGID_TTL_SEC, time_fn=None):
        self.ttl = ttl_sec
        self._time = time_fn or time.monotonic
        self._seen = {}
        self._lock = threading.Lock()

    def is_duplicate(self, key):
        """True = 已处理过（重复投递，跳过）；False = 首次见到，已记下。"""
        if not key:
            return False
        now = self._time()
        with self._lock:
            for k in [k for k, exp in self._seen.items() if exp <= now]:
                del self._seen[k]
            if key in self._seen:
                return True
            self._seen[key] = now + self.ttl
            return False

    def reset(self):
        with self._lock:
            self._seen.clear()


DEDUP = DedupCache()


# ---------------- 白名单 ----------------

def is_owner(userid):
    """OWNER_USERIDS 为空 = fail safe，拒绝所有人。"""
    if not OWNER_USERIDS:
        return False
    return bool(userid) and userid in OWNER_USERIDS


# ---------------- NAS 只读查询（从 v1.0 / Telegram bot3 复制的最小逻辑） ----------------
# 注意：这里只复制“读”的函数，不复制任何改动容器的函数。
# v1.0 源码：~/workspace/wecom-bridge/wecom_bridge.py
# bot3 源码：~/workspace/telegram-bots/bot3/bot.py

def human_bytes(n):
    n = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024.0 or unit == "T":
            if unit == "B":
                return f"{int(n)}B"
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}T"


def fmt_gib_from_kib(kib):
    return f"{kib / 1024.0 / 1024.0:.1f}G"


def disk_label(mount):
    """磁盘挂载点 → 卡片里显示的短名字。"""
    if mount == "/host":
        return "根分区"
    if mount.startswith("/host/mnt/"):
        return mount[len("/host/mnt/"):]
    if mount.startswith("/host") and len(mount) > 5:
        return mount[5:]
    return mount


def temperature_readings():
    """读温度传感器（从 Telegram bot3 复制的逻辑），返回 [(标签, 摄氏度)]。

    读不到返回 []（NAS 是 ESXi 上的虚拟机，传感器一般不直通进 VM）。
    """
    readings = []
    for type_path in glob.glob("/host/sys/class/thermal/thermal_zone*/type"):
        zone = os.path.dirname(type_path)
        temp_path = os.path.join(zone, "temp")
        label = (_read_text(type_path) or "").strip()
        raw = (_read_text(temp_path) or "").strip()
        try:
            val = int(raw)
        except ValueError:
            continue
        readings.append((label or os.path.basename(zone), val / 1000.0))
    for name_path in glob.glob("/host/sys/class/hwmon/hwmon*/name"):
        hwmon = os.path.dirname(name_path)
        chip = (_read_text(name_path) or "").strip()
        for input_path in sorted(glob.glob(os.path.join(hwmon, "temp*_input"))):
            base = input_path[:-len("_input")]
            label_path = base + "_label"
            label = (_read_text(label_path) or "").strip()
            raw = (_read_text(input_path) or "").strip()
            try:
                val = int(raw)
            except ValueError:
                continue
            name = f"{chip} {label}".strip() if label else chip
            readings.append((name or os.path.basename(hwmon), val / 1000.0))
    return readings


def _short_keyname(label):
    """传感器标签 → 卡片 keyname（建议不超过 5 个字，取短名）。"""
    m = re.match(r"thermal_zone(\d+)", label or "")
    if m:
        return f"温区{m.group(1)}"
    return (label or "传感器")[:8]


# ---------------- 模板卡片（状态 / 磁盘 / 温度的唯一渲染方式） ----------------
# 注意：这里绝不拼 emoji 彩条文本块。企微会把彩条从中间换行、错位，
# 朋友截图里就是这么难看的。状态一律走模板卡片。

CARD_BUTTONS = [
    {"text": "温度详情", "style": 1, "key": "CARD_TEMP"},
    {"text": "磁盘详情", "style": 1, "key": "CARD_DISK"},
    {"text": "刷新", "style": 2, "key": "CARD_REFRESH"},
    {"text": "主菜单", "style": 2, "key": "CARD_MENU"},
]

# 状态卡片多一个“容器列表”入口（TG 主菜单同款，卡片按钮上限 6 个，5 个够放）。
STATUS_BUTTONS = [
    {"text": "温度详情", "style": 1, "key": "CARD_TEMP"},
    {"text": "磁盘详情", "style": 1, "key": "CARD_DISK"},
    {"text": "容器列表", "style": 1, "key": "CARD_CONTAINERS"},
    {"text": "刷新", "style": 2, "key": "CARD_REFRESH"},
    {"text": "主菜单", "style": 2, "key": "CARD_MENU"},
]

# 容器管理卡片的按钮（每页 6 个容器，按钮上限 6 个，放不下每容器一个按钮，
# 所以容器用编号列表 + 回复序号选容器；取舍说明见 README）。
# 注意：翻页按钮带页码后缀（MG_PREV_<页> / MG_NEXT_<页>），见 build_manage_card。

# 容器详情卡片的按钮（TG 同款 6 个操作；卡片按钮上限 6 个，返回靠底部菜单）。
DETAIL_BUTTONS_TEMPLATE = [
    {"text": "▶️ 启动", "style": 1, "key": "C_ASK_START_{sid}"},
    {"text": "⏹️ 停止", "style": 1, "key": "C_ASK_STOP_{sid}"},
    {"text": "🔄 重启", "style": 1, "key": "C_ASK_RESTART_{sid}"},
    {"text": "📋 看日志", "style": 1, "key": "C_LOGS_{sid}"},
    {"text": "🔍 搜日志", "style": 1, "key": "C_SEARCH_{sid}"},
    {"text": "⬆️ 更新容器", "style": 1, "key": "C_ASK_UPDATE_{sid}"},
]

# VM 详情卡片的按钮（TG 同款 3 个电源操作 + 2 个返回）。
VM_BUTTONS_TEMPLATE = [
    {"text": "▶️ 开机", "style": 1, "key": "E_ASK_ON_{vmid}"},
    {"text": "⏻ 优雅关机", "style": 1, "key": "E_ASK_OFF_{vmid}"},
    {"text": "⚡ 强制断电", "style": 1, "key": "E_ASK_KILL_{vmid}"},
    {"text": "⬅️ VM 列表", "style": 2, "key": "E_LIST"},
    {"text": "⬅️ 主菜单", "style": 2, "key": "CARD_MENU"},
]

# 告警卡片的按钮（开关随当前状态变，见 build_alerts_card）。
ALERT_BUTTONS_ON = [
    {"text": "🔕 关闭告警", "style": 1, "key": "ALERT_OFF"},
    {"text": "⬅️ 主菜单", "style": 2, "key": "CARD_MENU"},
]
ALERT_BUTTONS_OFF = [
    {"text": "🔔 开启告警", "style": 1, "key": "ALERT_ON"},
    {"text": "⬅️ 主菜单", "style": 2, "key": "CARD_MENU"},
]

# 功能菜单卡片的按钮。
HELP_BUTTONS = [
    {"text": "系统状态", "style": 1, "key": "CARD_STATUS"},
    {"text": "容器列表", "style": 1, "key": "CARD_CONTAINERS"},
    {"text": "主菜单", "style": 2, "key": "CARD_MENU"},
]


def _new_task_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _card_value(value, limit=30):
    """卡片 value 建议不超过 30 个字，超了截断（官方建议值）。"""
    value = str(value)
    return value if len(value) <= limit else value[:limit - 1] + "…"


def _make_card(title, rows, buttons=None, task_prefix="nas", sub_title=None):
    """button_interaction 卡片：主标题 + 横向 key-value 行（最多 6 行）+ 按钮。

    buttons 不传时用默认 4 个按钮；官方限制 button_list 最多 6 个。
    """
    card = {
        "card_type": "button_interaction",
        "source": {"desc": BOT_NAME, "desc_color": 0},
        "main_title": {"title": title, "desc": sub_title or cst_now()},
        "horizontal_content_list": rows[:6],
        "button_list": buttons if buttons is not None else CARD_BUTTONS,
        "task_id": _new_task_id(task_prefix),
    }
    return card


def build_status_card():
    """NAS 总览卡片：CPU、内存、各磁盘用量、容器数，每行一个短值。"""
    rows = []
    cpu = cpu_percent()
    if cpu is not None:
        rows.append({"keyname": "CPU", "value": f"{cpu:.0f}%"})
    mem = _meminfo()
    if mem.get("MemTotal"):
        total = mem["MemTotal"]
        avail = mem.get("MemAvailable", 0)
        used = total - avail
        pct = used / total * 100.0 if total else 0.0
        rows.append({"keyname": "内存",
                     "value": f"{pct:.0f}% · {fmt_gib_from_kib(used)} / {fmt_gib_from_kib(total)}"})
    for d in disk_usages():
        rows.append({"keyname": disk_label(d["mount"]),
                     "value": f"{d['pct']:.0f}% · 剩 {d['avail']} / {d['size']}"})
    try:
        items = list_containers()
        running = sum(1 for c in items if c.get("State") == "running")
        rows.append({"keyname": "容器", "value": f"运行 {running} / 共 {len(items)}"})
    except Exception as e:
        log("容器汇总失败：", type(e).__name__, str(e)[:200])
    return _make_card("NAS 状态", rows, buttons=STATUS_BUTTONS)


def build_disk_card():
    """磁盘详情卡片：每个卷一行（用量百分比 · 已用 · 剩余）。无数据返回 None。"""
    rows = []
    for d in disk_usages():
        rows.append({"keyname": disk_label(d["mount"]),
                     "value": f"{d['pct']:.0f}% · 已用 {d['used']} · 剩 {d['avail']}"})
    if not rows:
        return None
    return _make_card("磁盘详情", rows)


def build_temp_card():
    """温度详情卡片：每个传感器一行。读不到传感器返回 None。"""
    readings = temperature_readings()
    if not readings:
        return None
    rows = [{"keyname": _short_keyname(label), "value": f"{celsius:.1f}°C"}
            for label, celsius in readings[:6]]
    return _make_card("温度详情", rows)


def fmt_containers_markdown():
    """容器列表 markdown：每容器一行（状态点 + 名字 + 状态），不带彩条、不带镜像。"""
    try:
        items = list_containers()
    except Exception as e:
        return f"容器列表读不到：{e}"
    if not items:
        return "🐳 容器列表\n没有容器。"
    lines = ["🐳 容器列表"]
    for c in items[:30]:
        state = c.get("State", "?")
        dot = "🟢" if state == "running" else "⚪"
        lines.append(f"{dot} {container_display_name(c)} · {state}")
    if len(items) > 30:
        lines.append(f"…还有 {len(items) - 30} 个未显示")
    return "\n".join(lines)


# ---------------- 两步确认卡片 + 选择状态（v2.1 新增） ----------------
# 破坏性操作绝不在一次点击里执行：先出一张确认卡，点 ✅ 才执行。
# 确认令牌只活 5 分钟，存在内存里（容器重启就失效，要重新操作一次）。

CONFIRM_TTL_SEC = 300
_PENDING_CONFIRM = {}   # token -> {"kind","action","target","label","userid","expires"}
_PENDING_CONFIRM_LOCK = threading.Lock()
_PENDING_SEARCH = {}    # userid -> (shortid, expires)：搜日志等用户回关键词
_MANAGE_STATE = {}      # userid -> {"page": int, "items": [shortid], "expires": float}
_ESXI_STATE = {}        # userid -> {"items": [vmid], "expires": float}
_SELECT_TTL_SEC = 600


def new_confirm(kind, action, target, label, userid):
    """建一个待确认操作，返回确认卡片里要用的 token。"""
    token = uuid.uuid4().hex[:10]
    with _PENDING_CONFIRM_LOCK:
        _PENDING_CONFIRM[token] = {
            "kind": kind, "action": action, "target": target,
            "label": label, "userid": userid,
            "expires": time.monotonic() + CONFIRM_TTL_SEC,
        }
    return token


def take_confirm(token, userid):
    """取走一次确认：不存在/过期/不是本人 → 返回 None（不执行）。"""
    with _PENDING_CONFIRM_LOCK:
        entry = _PENDING_CONFIRM.pop(token, None)
    if entry is None:
        return None
    if entry.get("userid") != userid:
        return None
    if time.monotonic() > entry.get("expires", 0):
        return None
    return entry


def build_confirm_card(label, detail, token):
    """两步确认卡片：操作 + 说明 + [✅ 确认][❌ 取消]。"""
    rows = [
        {"keyname": "操作", "value": _card_value(label)},
        {"keyname": "说明", "value": _card_value(detail)},
    ]
    buttons = [
        {"text": "✅ 确认", "style": 1, "key": f"CF_OK_{token}"},
        {"text": "❌ 取消", "style": 2, "key": f"CF_NO_{token}"},
    ]
    return _make_card("请确认", rows, buttons=buttons, task_prefix="cf",
                      sub_title="5 分钟内有效，过期请重新操作")


def ask_confirm(kind, action, target, label, detail, userid):
    """建确认、返回确认卡片回复。调用方只负责展示，不执行。"""
    token = new_confirm(kind, action, target, label, userid)
    log("已出确认卡：", kind, action, target, "来自", userid)
    return card_reply(build_confirm_card(label, detail, token))


# ---------------- 容器管理 / 详情 / ESXi / 告警 / 功能菜单卡片 ----------------

MANAGE_PAGE_SIZE = 6  # 卡片每页最多 6 行，正好一页 6 个容器


def build_manage_card(page=0, userid=""):
    """容器管理卡：每页 6 个容器编号列表 + [上一页][下一页][清理镜像][主菜单]。

    取舍（卡片按钮上限 6 个，TG 那种每容器一个按钮放不下）：
    卡片行里按序号列出本页容器，回复序号（或容器名）选容器进详情卡。
    """
    items = sorted(list_containers(), key=container_display_name)
    total_pages = max(1, (len(items) + MANAGE_PAGE_SIZE - 1) // MANAGE_PAGE_SIZE)
    page = max(0, min(page, total_pages - 1))
    page_items = items[page * MANAGE_PAGE_SIZE:(page + 1) * MANAGE_PAGE_SIZE]
    shortids = [c["Id"][:12] for c in page_items]
    if userid:
        _MANAGE_STATE[userid] = {
            "page": page, "items": shortids,
            "expires": time.monotonic() + _SELECT_TTL_SEC,
        }
    rows = []
    for i, c in enumerate(page_items):
        state = c.get("State", "?")
        dot = "🟢" if state == "running" else "⚪"
        rows.append({"keyname": f"{i + 1} {container_display_name(c)[:12]}",
                     "value": _card_value(f"{dot} {state}")})
    if not rows:
        rows.append({"keyname": "容器", "value": "没有容器"})
    buttons = []
    if page > 0:
        buttons.append({"text": "⬅️ 上一页", "style": 2, "key": f"MG_PREV_{page - 1}"})
    if page < total_pages - 1:
        buttons.append({"text": "下一页 ➡️", "style": 2, "key": f"MG_NEXT_{page + 1}"})
    buttons.append({"text": "🧹 清理镜像", "style": 1, "key": "MG_PRUNE"})
    buttons.append({"text": "⬅️ 主菜单", "style": 2, "key": "CARD_MENU"})
    card = _make_card(
        f"容器管理（第 {page + 1}/{total_pages} 页，共 {len(items)} 个）",
        rows, buttons=buttons, task_prefix="mg",
        sub_title="回复序号选容器，例如：3")
    return card, page, total_pages, len(items)


def build_container_detail_card(c, inspect=None):
    """容器详情卡：镜像/状态/ID/端口/创建时间/重启策略 + 6 个操作按钮。

    取舍：卡片按钮上限 6 个，6 个操作按钮占满，返回靠底部菜单
    （容器 → 容器管理）或直接发“容器管理”。
    """
    name = container_display_name(c)
    shortid = c["Id"][:12]
    ports = c.get("Ports") or []
    port_s = ", ".join(f"{p.get('PublicPort', '')}->{p.get('PrivatePort', '')}"
                       for p in ports if p.get("PrivatePort")) or "无"
    rows = [
        {"keyname": "镜像", "value": _card_value(c.get("Image", "?"))},
        {"keyname": "状态", "value": _card_value(f"{c.get('State', '?')} {c.get('Status', '')}")},
        {"keyname": "ID", "value": shortid},
        {"keyname": "端口", "value": _card_value(port_s)},
    ]
    if inspect:
        created = (inspect.get("Created", "") or "")[:19].replace("T", " ")
        restart = ((inspect.get("HostConfig") or {}).get("RestartPolicy") or {}).get("Name", "?")
        rows.append({"keyname": "创建时间", "value": _card_value(created or "？")})
        rows.append({"keyname": "重启策略", "value": _card_value(restart)})
    buttons = []
    for b in DETAIL_BUTTONS_TEMPLATE:
        buttons.append({"text": b["text"], "style": b["style"],
                        "key": b["key"].replace("{sid}", shortid)})
    return _make_card(f"🐳 {name}", rows, buttons=buttons, task_prefix="cd")


def build_esxi_list_card(vms, userid=""):
    """ESXi VM 列表卡：每 VM 一行（ID → 名字 + 电源状态）+ 每 VM 一个按钮。

    VM 一般不多，按钮放得下（≤5 个 VM 按钮 + 主菜单 = 6 个上限）；
    超过 5 个改走编号列表 + 回复序号选 VM。
    """
    if userid:
        _ESXI_STATE[userid] = {
            "items": [v["vmid"] for v in vms],
            "expires": time.monotonic() + _SELECT_TTL_SEC,
        }
    rows = []
    for v in vms[:6]:
        dot = "🟢" if v.get("state") == "on" else "⚪"
        rows.append({"keyname": str(v["vmid"]),
                     "value": _card_value(f"{dot} {v['name']} {v.get('state', '?')}")})
    if not rows:
        rows.append({"keyname": "VM", "value": "没有 VM"})
    buttons = []
    if len(vms) <= 5:
        for v in vms:
            dot = "🟢" if v.get("state") == "on" else "⚪"
            buttons.append({"text": f"{dot} {v['name'][:8]}", "style": 1,
                            "key": f"E_DETAIL_{v['vmid']}"})
    buttons.append({"text": "⬅️ 主菜单", "style": 2, "key": "CARD_MENU"})
    sub = "回复序号选 VM" if len(vms) > 5 else "点 VM 看详情、开关机"
    return _make_card("🖥️ ESXi VM", rows, buttons=buttons[:6],
                      task_prefix="esxi", sub_title=sub)


def build_vm_detail_card(v):
    """VM 详情卡：名字/ID/电源 + [开机][优雅关机][强制断电][VM 列表][主菜单]。"""
    rows = [
        {"keyname": "名字", "value": _card_value(v["name"])},
        {"keyname": "ID", "value": str(v["vmid"])},
        {"keyname": "电源", "value": _card_value(v.get("state", "?"))},
    ]
    buttons = []
    for b in VM_BUTTONS_TEMPLATE:
        buttons.append({"text": b["text"], "style": b["style"],
                        "key": b["key"].replace("{vmid}", str(v["vmid"]))})
    return _make_card(f"🖥️ {v['name']}", rows, buttons=buttons, task_prefix="vm")


def build_alerts_card():
    """告警状态卡：开关/间隔/阈值/上次检查 + [开启或关闭告警][主菜单]。"""
    enabled = alerts_enabled()
    rows = [
        {"keyname": "开关", "value": "开启" if enabled else "关闭"},
        {"keyname": "间隔", "value": f"每 {ALERT_INTERVAL_SEC // 60} 分钟"},
        {"keyname": "磁盘阈值", "value": f"{ALERT_DISK_PCT:g}%"},
        {"keyname": "负载阈值", "value": f"{_cpu_count()} 线程 ×{ALERT_LOAD_MULT:g}"},
        {"keyname": "内存阈值", "value": f"{ALERT_MEM_PCT:g}%"},
        {"keyname": "上次检查", "value": _card_value(_ALERT_STATE.get("last_check") or "还没有")},
    ]
    buttons = ALERT_BUTTONS_ON if enabled else ALERT_BUTTONS_OFF
    return _make_card("🔔 主动告警", rows, buttons=buttons, task_prefix="al")


def build_help_card():
    """功能菜单卡：三组功能一览 + [系统状态][容器列表][主菜单]。"""
    rows = [
        {"keyname": "总览", "value": "系统状态 公网IP 磁盘 温度 帮助"},
        {"keyname": "容器", "value": "列表 管理 资源 检查更新 清理"},
        {"keyname": "更多", "value": "ESXi 网络 进程 告警 检查更新"},
    ]
    return _make_card("功能菜单", rows, buttons=HELP_BUTTONS, task_prefix="help",
                      sub_title="底部菜单常驻，也可直接发指令")


def _read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _meminfo():
    mem = {}
    text = _read_text("/host/proc/meminfo")
    if text:
        for line in text.splitlines():
            k, _, v = line.partition(":")
            parts = v.strip().split()
            if parts:
                try:
                    mem[k.strip()] = int(parts[0])
                except ValueError:
                    pass
    return mem


def _cpu_times():
    text = _read_text("/host/proc/stat")
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("cpu "):
            fields = [int(x) for x in line.split()[1:]]
            total = sum(fields)
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
            return total, idle
    return None


def cpu_percent():
    first = _cpu_times()
    if first is None:
        return None
    time.sleep(1.0)
    second = _cpu_times()
    if second is None:
        return None
    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0:
        return None
    return (1.0 - idle_delta / total_delta) * 100.0


def _loadavg():
    text = _read_text("/host/proc/loadavg")
    if not text:
        return None
    parts = text.split()
    return parts[:3] if len(parts) >= 3 else None


def _uptime_text():
    text = _read_text("/host/proc/uptime")
    if not text:
        return None
    try:
        seconds = int(float(text.split()[0]))
    except (ValueError, IndexError):
        return None
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    if days:
        return f"{days} 天 {hours} 小时 {minutes} 分"
    return f"{hours} 小时 {minutes} 分"


def _cpu_count():
    text = _read_text("/host/proc/cpuinfo")
    if text:
        n = text.count("processor\t:")
        if n:
            return n
    return os.cpu_count() or 1


def disk_usages():
    paths = ["/host"]
    for p in HOST_DATA_PATHS:
        hp = "/host" + p
        if os.path.exists(hp):
            paths.append(hp)
        else:
            log("磁盘路径不存在，已跳过（检查挂载）：", hp)
    try:
        r = subprocess.run(["df", "-h"] + paths, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return []
    seen = set()
    out = []
    for line in r.stdout.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        fs, size, used, avail, pct_s, mount = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        key = (fs, mount)
        if key in seen:
            continue
        seen.add(key)
        try:
            pct = float(pct_s.rstrip("%"))
        except ValueError:
            pct = 0.0
        out.append({"fs": fs, "size": size, "used": used, "avail": avail,
                    "pct": pct, "mount": mount})
    return out


# ---------------- Docker（Unix socket + Engine API，只读） ----------------

import http.client
import socket


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, sock_path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self._sock_path = sock_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._sock_path)


def docker_api(method, path, timeout=30):
    conn = UnixHTTPConnection(DOCKER_SOCK, timeout=timeout)
    try:
        conn.request(method, path)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body
    finally:
        conn.close()


def docker_json(method, path, timeout=30):
    status, body = docker_api(method, path, timeout=timeout)
    if status >= 400:
        raise RuntimeError(f"Docker API {method} {path} 返回 {status}：{body[:200]!r}")
    return json.loads(body) if body else None


def list_containers():
    return docker_json("GET", "/containers/json?all=1")


def container_display_name(c):
    names = c.get("Names") or []
    if names:
        return names[0].lstrip("/")
    return c.get("Id", "?")[:12]


def resolve_container(query):
    items = list_containers()
    exact = [c for c in items
             if query in [n.lstrip("/") for n in c.get("Names", [])]
             or c["Id"].startswith(query)]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise ValueError("匹配到多个容器：" + "、".join(
            container_display_name(c) for c in exact))
    partial = [c for c in items if any(query in n for n in c.get("Names", []))]
    if len(partial) == 1:
        return partial[0]
    if len(partial) > 1:
        raise ValueError("匹配到多个容器：" + "、".join(
            container_display_name(c) for c in partial))
    raise ValueError(f"找不到容器：{query}")


def demux_logs(raw):
    """Docker 日志是 8 字节头 + 内容的帧流；tty 容器则是纯文本。"""
    frames = []
    i = 0
    framed = True
    while i + 8 <= len(raw):
        stream, size = raw[i], int.from_bytes(raw[i + 4:i + 8], "big")
        if stream not in (0, 1, 2) or i + 8 + size > len(raw):
            framed = False
            break
        frames.append(raw[i + 8:i + 8 + size])
        i += 8 + size
    if framed and frames:
        return b"".join(frames).decode("utf-8", errors="replace")
    return raw.decode("utf-8", errors="replace")


def container_logs(name, tail=50):
    c = resolve_container(name)
    status, body = docker_api(
        "GET", f"/containers/{c['Id']}/logs?stdout=1&stderr=1&tail={tail}")
    if status >= 400:
        raise RuntimeError(f"读日志失败 {status}")
    return demux_logs(body)


# ---------------- Docker 写操作（v2.1 新增，从 Telegram bot3 复制） ----------------
# 注意：这些函数会改动容器，只通过两步确认卡片调用，绝不直接由文字触发。

def docker_api_body(method, path, body, timeout=60, content_type="application/json"):
    conn = UnixHTTPConnection(DOCKER_SOCK, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers={"Content-Type": content_type})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def docker_json_body(method, path, payload, timeout=60):
    status, body = docker_api_body(method, path, json.dumps(payload).encode("utf-8"), timeout=timeout)
    if status >= 400:
        raise RuntimeError(f"Docker API {method} {path} 返回 {status}：{body[:200]!r}")
    return json.loads(body) if body else None


# 主人主动停的容器，15 分钟内不触发“容器停了”告警。
_INTENTIONAL_STOPS = {}


def record_intentional_stop(cid):
    _INTENTIONAL_STOPS[cid] = time.monotonic() + 900


def container_action(name, action):
    """启动/停止/重启容器。action ∈ {"start", "stop", "restart"}。"""
    c = resolve_container(name)
    path = f"/containers/{c['Id']}/{action}"
    if action == "stop":
        path += "?t=10"
    status, body = docker_api("POST", path)
    if status not in (204, 304):
        raise RuntimeError(f"{action} 失败 {status}：{body[:200]!r}")
    if action == "stop":
        record_intentional_stop(c["Id"])
    return c


def inspect_container(cid):
    return docker_json("GET", f"/containers/{cid}/json")


def _split_image(image):
    image = image.strip()
    if "@" in image:
        raise ValueError("带 digest 的镜像暂不支持更新")
    slash = image.rfind("/")
    colon = image.rfind(":")
    if colon > slash:
        return image[:colon], image[colon + 1:]
    return image, "latest"


def docker_pull(image, timeout=600):
    """拉取镜像。返回 (ok, message)。流式读进度，遇到 error 即失败。"""
    name, tag = _split_image(image)
    path = f"/images/create?fromImage={quote(name, safe='')}&tag={quote(tag, safe='')}"
    conn = UnixHTTPConnection(DOCKER_SOCK, timeout=timeout)
    try:
        conn.request("POST", path)
        resp = conn.getresponse()
        if resp.status >= 400:
            return False, f"拉取失败 {resp.status}：{resp.read()[:200]!r}"
        last_status = ""
        while True:
            line = resp.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("error"):
                return False, f"拉取失败：{ev['error']}"
            if ev.get("status"):
                last_status = ev["status"]
        return True, last_status or "拉取完成"
    finally:
        conn.close()


def prune_images():
    """只清悬空镜像（dangling=true），不碰正在用的镜像。返回 (个数, 释放字节)。"""
    result = docker_json("POST", "/images/prune?dangling=true", timeout=60)
    deleted = (result or {}).get("ImagesDeleted") or []
    reclaimed = (result or {}).get("SpaceReclaimed", 0)
    return len(deleted), reclaimed


def search_container_logs(name, keyword, tail=200, max_hits=30):
    """在容器最近 tail 行日志里找关键词（不区分大小写）。返回 (命中行, 命中总数)。"""
    text = container_logs(name, tail)
    kw = keyword.lower()
    hits = [ln for ln in text.splitlines() if kw in ln.lower()]
    return hits[:max_hits], len(hits)


def build_recreate_config(inspect_data, new_image):
    """从 inspect 构造 create 请求体（只保留可安全重建的字段）。

    关键：匿名卷不会自动跟到新容器，必须把 Mounts 里的 volume 显式绑回，
    否则数据会丢在孤卷里。环境变量会原样带过去（重建必需），但绝不显示。
    """
    cfg = inspect_data.get("Config") or {}
    host = inspect_data.get("HostConfig") or {}
    binds = list(host.get("Binds") or [])
    bound_dests = set()
    for b in binds:
        parts = b.split(":")
        if len(parts) >= 2:
            bound_dests.add(parts[1])
    for m in inspect_data.get("Mounts") or []:
        if m.get("Type") == "volume":
            dest = m.get("Destination")
            src = m.get("Name")
            if dest and src and dest not in bound_dests:
                mode = "rw" if m.get("RW") else "ro"
                binds.append(f"{src}:{dest}:{mode}")
                bound_dests.add(dest)
    network_mode = host.get("NetworkMode") or "default"
    if network_mode.startswith("container:"):
        raise ValueError("该容器用了 container: 网络模式，无法安全重建")
    endpoints = {}
    if network_mode not in ("host", "none"):
        nets = ((inspect_data.get("NetworkSettings") or {}).get("Networks") or {})
        for net_name, ep in nets.items():
            endpoints[net_name] = {"Aliases": (ep or {}).get("Aliases") or []}
    host_cfg = {
        "Binds": binds,
        "PortBindings": host.get("PortBindings") or {},
        "RestartPolicy": host.get("RestartPolicy") or {"Name": "no"},
        "NetworkMode": network_mode,
        "Privileged": bool(host.get("Privileged")),
        "CapAdd": host.get("CapAdd") or [],
        "CapDrop": host.get("CapDrop") or [],
        "Devices": host.get("Devices") or [],
        "Dns": host.get("Dns") or [],
        "ExtraHosts": host.get("ExtraHosts") or [],
        "LogConfig": host.get("LogConfig") or {},
        "Memory": host.get("Memory") or 0,
        "NanoCpus": host.get("NanoCpus") or 0,
        "PidMode": host.get("PidMode") or "",
        "IpcMode": host.get("IpcMode") or "",
        "Ulimits": host.get("Ulimits") or [],
        "Tmpfs": host.get("Tmpfs") or {},
        "Sysctls": host.get("Sysctls") or {},
    }
    if host.get("StopTimeout"):
        host_cfg["StopTimeout"] = host["StopTimeout"]
    create = {
        "Image": new_image,
        "User": cfg.get("User") or "",
        "AttachStdin": False, "AttachStdout": False, "AttachStderr": False,
        "Tty": bool(cfg.get("Tty")),
        "OpenStdin": bool(cfg.get("OpenStdin")),
        "StdinOnce": bool(cfg.get("StdinOnce")),
        "Env": list(cfg.get("Env") or []),
        "Cmd": cfg.get("Cmd"),
        "Entrypoint": cfg.get("Entrypoint"),
        "WorkingDir": cfg.get("WorkingDir") or "",
        "Labels": dict(cfg.get("Labels") or {}),
        "ExposedPorts": cfg.get("ExposedPorts") or {},
        "Volumes": cfg.get("Volumes") or {},
        "HostConfig": host_cfg,
    }
    if cfg.get("Hostname"):
        create["Hostname"] = cfg["Hostname"]
    if cfg.get("Domainname"):
        create["Domainname"] = cfg["Domainname"]
    if cfg.get("StopSignal"):
        create["StopSignal"] = cfg["StopSignal"]
    if endpoints:
        create["NetworkingConfig"] = {"EndpointsConfig": endpoints}
    return create


def _container_state(cid):
    try:
        data = inspect_container(cid)
        state = data.get("State") or {}
        return state.get("Status"), (state.get("Health") or {}).get("Status")
    except Exception:
        return None, None


_UPDATE_LOCK = threading.Lock()


def update_container_flow(query):
    """拉取新镜像并重建容器。旧容器保留到新容器跑起来后才删；失败则回滚。"""
    if not _UPDATE_LOCK.acquire(blocking=False):
        return False, "已有容器更新在进行中，稍后再试。"
    try:
        return _update_container_inner(query)
    finally:
        _UPDATE_LOCK.release()


def _update_container_inner(query):
    try:
        c = resolve_container(query)
    except Exception as e:
        return False, f"找不到容器：{e}"
    name = container_display_name(c)
    cid = c["Id"]
    if name == SELF_CONTAINER_NAME:
        return False, "企微桥自己不能用这种方式更新，请用菜单的“检查更新”。"
    image_ref = (c.get("Image") or "").strip()
    if not image_ref:
        return False, "读不到该容器的镜像名，无法更新。"
    try:
        inspect_data = inspect_container(cid)
    except Exception as e:
        return False, f"读容器详情失败：{e}"
    old_image_id = inspect_data.get("Image", "")
    try:
        ok, pull_msg = docker_pull(image_ref)
    except Exception as e:
        return False, f"拉取镜像失败：{e}"
    if not ok:
        return False, pull_msg
    try:
        img = docker_json("GET", "/images/" + quote(image_ref, safe="") + "/json")
        if img.get("Id") and old_image_id and img["Id"] == old_image_id:
            return True, f"✅ {name} 的镜像已是最新（{image_ref}），无需重建。"
    except Exception:
        pass
    try:
        create_cfg = build_recreate_config(inspect_data, image_ref)
    except Exception as e:
        return False, f"无法安全重建：{e}"
    temp_name = re.sub(r"[^a-zA-Z0-9_.-]", "-", f"{name}-upd-{int(time.time()) % 100000}")
    try:
        created = docker_json_body("POST", f"/containers/create?name={quote(temp_name, safe='')}",
                                   create_cfg, timeout=60)
    except Exception as e:
        return False, f"创建新容器失败（旧容器未动）：{e}"
    new_id = (created or {}).get("Id")
    if not new_id:
        return False, "创建新容器失败（旧容器未动）：Docker 没有返回新容器 ID。"
    try:
        docker_api("POST", f"/containers/{cid}/stop?t=10", timeout=30)
    except Exception as e:
        log("update: stop old failed:", e)
    status, body = docker_api("POST", f"/containers/{new_id}/start", timeout=30)
    if status >= 400:
        _rollback_update(new_id, cid)
        return False, f"新容器启动失败（已回滚到旧容器）：{body[:200]!r}"
    st, health = None, None
    running = False
    for _ in range(15):
        time.sleep(2)
        st, health = _container_state(new_id)
        if st == "running" and health != "unhealthy":
            running = True
            break
        if st in ("exited", "dead"):
            break
    if not running:
        _rollback_update(new_id, cid)
        return False, f"新容器没有跑起来（状态：{st}），已回滚到旧容器。请看新容器日志排查。"
    warnings = []
    status, _body = docker_api("DELETE", f"/containers/{cid}", timeout=30)
    if status >= 400:
        warnings.append(f"旧容器删除失败（{status}），请手动清理停止的旧容器。")
    status, _body = docker_api("POST", f"/containers/{new_id}/rename?name={quote(name, safe='')}", timeout=30)
    if status >= 400:
        warnings.append(f"新容器已在跑，但改回原名失败（现在叫 {temp_name}）。")
        return True, f"✅ {name} 已更新到新镜像。\n" + "\n".join(warnings)
    msg = f"✅ {name} 已更新到新镜像并重建完成（{image_ref}）。"
    if warnings:
        msg += "\n" + "\n".join(warnings)
    return True, msg


def _rollback_update(new_id, old_id):
    try:
        docker_api("POST", f"/containers/{new_id}/stop?t=5", timeout=20)
    except Exception:
        pass
    try:
        docker_api("DELETE", f"/containers/{new_id}?force=true", timeout=30)
    except Exception as e:
        log("update rollback: remove new failed:", e)
    try:
        docker_api("POST", f"/containers/{old_id}/start", timeout=30)
    except Exception as e:
        log("update rollback: start old failed:", e)


def update_container_async(query, userid):
    """后台线程跑容器更新，完成后把结果发给用户（确认卡点完就回“开始更新…”）。"""
    def _run():
        try:
            _ok, msg = update_container_flow(query)
        except Exception:
            log("update thread error:", traceback.format_exc(limit=3))
            msg = "更新过程出错了，请看容器日志。"
        send_reply(userid, text_reply(msg))
    threading.Thread(target=_run, daemon=True).start()


def calc_cpu_percent(stats):
    try:
        cpu = stats.get("cpu_stats", {}) or {}
        pre = stats.get("precpu_stats", {}) or {}
        cpu_delta = (cpu.get("cpu_usage", {}) or {}).get("total_usage", 0) - (pre.get("cpu_usage", {}) or {}).get("total_usage", 0)
        sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        percpu = (cpu.get("cpu_usage", {}) or {}).get("percpu_usage") or []
        ncpu = len(percpu) or cpu.get("online_cpus") or 1
        if sys_delta > 0 and cpu_delta >= 0:
            return cpu_delta / sys_delta * ncpu * 100.0
    except Exception:
        pass
    return 0.0


def _one_container_stats(c):
    try:
        stats = docker_json("GET", f"/containers/{c['Id']}/stats?stream=0&one-shot=1", timeout=10)
    except Exception:
        return None
    mem = stats.get("memory_stats", {}) or {}
    usage = mem.get("usage", 0) or 0
    cache = (mem.get("stats", {}) or {}).get("cache", 0) or 0
    used = usage - cache if usage >= cache else usage
    return {"name": container_display_name(c),
            "cpu": calc_cpu_percent(stats),
            "mem_used": used, "mem_limit": mem.get("limit", 0) or 0}


def container_stats_all():
    items = [c for c in list_containers() if c.get("State") == "running"]
    if not items:
        return []
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for r in pool.map(_one_container_stats, items):
            if r is not None:
                results.append(r)
    results.sort(key=lambda r: r["cpu"], reverse=True)
    return results


def fmt_stats_markdown():
    """容器资源 markdown：按 CPU 排序，每容器一行（CPU% + 内存用量）。"""
    try:
        results = container_stats_all()
    except Exception as e:
        return f"容器资源读不到：{e}"
    if not results:
        return "📈 容器资源\n没有运行中的容器，或资源数据读不到。"
    lines = ["📈 容器资源（按 CPU 排序）"]
    for r in results[:15]:
        mem_pct = r["mem_used"] / r["mem_limit"] * 100.0 if r["mem_limit"] else 0.0
        lines.append(f"{r['name']}  CPU {r['cpu']:.1f}%  内存 {human_bytes(r['mem_used'])}/{human_bytes(r['mem_limit'])}（{mem_pct:.0f}%）")
    if len(results) > 15:
        lines.append(f"…还有 {len(results) - 15} 个容器未显示")
    return "\n".join(lines)


# ---------------- 进程 TOP / 网络流量 / 公网 IP（v2.1 新增，从 bot3 复制） ----------------

def _read_procs():
    """读 /proc：每进程 (pid, comm, cpu_secs, mem_kb)。"""
    out = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/stat", encoding="utf-8", errors="ignore") as f:
                    parts = f.read().split()
                with open(f"/proc/{pid}/status", encoding="utf-8", errors="ignore") as f:
                    status_txt = f.read()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            comm = parts[1].strip("()") if len(parts) > 1 else "?"
            try:
                utime = int(parts[13]); stime = int(parts[14])
            except (IndexError, ValueError):
                utime = stime = 0
            mem = 0
            for ln in status_txt.splitlines():
                if ln.startswith("VmRSS:"):
                    try:
                        mem = int(ln.split()[1])
                    except (IndexError, ValueError):
                        mem = 0
                    break
            out.append({"pid": int(pid), "comm": comm, "cpu": (utime + stime) / 100.0,
                        "mem_kb": mem})
    except Exception as e:
        log("read /proc failed:", e)
    return out


def fmt_top_markdown():
    """进程 TOP markdown：CPU 前 10 + 内存前 5。"""
    procs = _read_procs()
    if not procs:
        return "进程 TOP 读不到（/proc 不可用）。"
    lines = ["📊 进程 TOP（CPU 前 10）"]
    for p in sorted(procs, key=lambda x: x["cpu"], reverse=True)[:10]:
        lines.append(f"{p['pid']} {p['comm']}  CPU {p['cpu']:.1f}s  内存 {human_bytes(p['mem_kb'] * 1024)}")
    lines.append("")
    lines.append("内存前 5")
    for p in sorted(procs, key=lambda x: x["mem_kb"], reverse=True)[:5]:
        lines.append(f"{p['pid']} {p['comm']}  {human_bytes(p['mem_kb'] * 1024)}")
    return "\n".join(lines)


def _read_net_dev():
    """读 /proc/net/dev：每网卡 (收字节, 发字节)。"""
    out = {}
    try:
        with open("/proc/net/dev", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()[2:]
        for ln in lines:
            if ":" not in ln:
                continue
            name, rest = ln.split(":", 1)
            fields = rest.split()
            if len(fields) >= 9:
                out[name.strip()] = {"rx": int(fields[0]), "tx": int(fields[8])}
    except Exception as e:
        log("read /proc/net/dev failed:", e)
    return out


def fmt_net_markdown():
    """网络流量 markdown：每网卡一行累计收发（lo 除外）。"""
    devs = _read_net_dev()
    if not devs:
        return "网络流量读不到（/proc/net/dev 不可用）。"
    lines = ["🌐 网络流量（累计收发）"]
    for name, v in sorted(devs.items()):
        if name == "lo":
            continue
        lines.append(f"{name}  ↓ {human_bytes(v['rx'])}  ↑ {human_bytes(v['tx'])}")
    if len(lines) == 1:
        lines.append("没有非 lo 网卡。")
    return "\n".join(lines)


def read_disk_usage():
    """告警用的磁盘用量：返回 [{"mountpoint", "total", "used"}]（字节）。

    用 shutil.disk_usage 直接读挂载点（/host 下的宿主机路径），
    比解析 df -h 更稳。
    """
    out = []
    paths = ["/host"]
    for p in HOST_DATA_PATHS:
        hp = "/host" + p
        if os.path.exists(hp):
            paths.append(hp)
    for path in paths:
        try:
            usage = shutil.disk_usage(path)
            out.append({"mountpoint": path, "total": usage.total,
                        "used": usage.used})
        except OSError:
            continue
    return out


def read_memory():
    """告警用的内存用量：返回 {"used_pct"}。"""
    mem = _meminfo()
    total = mem.get("MemTotal", 0)
    if not total:
        return {"used_pct": 0.0}
    used = total - mem.get("MemAvailable", 0)
    return {"used_pct": used / total * 100.0}


def http_get_json(url, timeout=10):
    """GET 一个 URL：能解析 JSON 就返回解析结果，否则返回原始文本。"""
    req = urllib.request.Request(url, headers={"User-Agent": "wecom-callback-bridge"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    try:
        return json.loads(body)
    except ValueError:
        return body


def fmt_public_ip_markdown():
    """公网 IP markdown：调用 ip.sb 查询出口 IP（VM 里的接口 IP 一般是内网）。"""
    try:
        data = http_get_json("https://api.ip.sb/ip", timeout=10)
        ip = data if isinstance(data, str) else str(data)
        return f"🌐 公网 IP\n{ip.strip()}"
    except Exception as e:
        return f"公网 IP 查不到：{e}"


# ---------------- ESXi（v2.1 新增，从 Telegram bot3 复制） ----------------

def _esxi_connect():
    """paramiko 连 ESXi：优先 key，失败再试密码。未填密码/key 时直接抛错。"""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {"hostname": ESXI_HOST, "username": ESXI_USER,
                      "timeout": 15, "banner_timeout": 15, "auth_timeout": 15}
    if ESXI_KEY_FILE:
        try:
            client.connect(look_for_keys=False, allow_agent=False,
                           key_filename=ESXI_KEY_FILE, **connect_kwargs)
            return client
        except Exception as e:
            log("ESXi key 失败，改试密码：", type(e).__name__, str(e)[:100])
    if not ESXI_PASSWORD:
        client.close()
        raise RuntimeError("ESXi 未配置密码或 key，请在 .env 里填 ESXI_PASSWORD。")
    client.connect(password=ESXI_PASSWORD, look_for_keys=False,
                   allow_agent=False, **connect_kwargs)
    return client


def esxi_run(cmd, timeout=30):
    """在 ESXi 上跑一条命令，返回 (stdout, stderr, rc)。"""
    client = _esxi_connect()
    try:
        _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return out, err, stdout.channel.recv_exit_status()
    finally:
        client.close()


def esxi_list_vms():
    """列出 ESXi 上的 VM：[{vmid, name, state}]。"""
    out, err, rc = esxi_run("vim-cmd vmsvc/getallvms")
    if rc != 0:
        raise RuntimeError(f"getallvms 失败（{rc}）：{err[:200]}")
    vms = []
    for ln in out.splitlines():
        m = re.match(r"^\s*(\d+)\s+(\S+)\s+\[", ln)
        if not m:
            continue
        vmid, name = m.group(1), m.group(2)
        state = "?"
        try:
            out2, _err, rc2 = esxi_run(f"vim-cmd vmsvc/power.getstate {vmid}")
            if rc2 == 0:
                state = "on" if "Powered on" in out2 else "off"
        except Exception:
            pass
        vms.append({"vmid": vmid, "name": name, "state": state})
    return vms


def esxi_vm_power(vmid, action):
    """VM 电源操作：on / off（优雅关机）/ kill（强制断电）。"""
    cmds = {
        "on": f"vim-cmd vmsvc/power.on {vmid}",
        "off": f"vim-cmd vmsvc/power.shutdown {vmid}",
        "kill": f"vim-cmd vmsvc/power.off {vmid}",
    }
    if action not in cmds:
        raise ValueError(f"未知 VM 电源操作：{action}")
    out, err, rc = esxi_run(cmds[action])
    if rc != 0:
        raise RuntimeError(f"VM {action} 失败（{rc}）：{(err or out)[:200]}")
    return True


def esxi_find_nas_vm():
    """按 .env 里的 NAS_VM_NAME / NAS_VM_ID 找到 NAS 这个 VM 的 vmid。"""
    if NAS_VM_ID:
        return NAS_VM_ID
    vms = esxi_list_vms()
    for v in vms:
        if v["name"] == NAS_VM_NAME:
            return v["vmid"]
    raise RuntimeError(f"在 ESXi 上找不到名字为 {NAS_VM_NAME} 的 VM。")


def reboot_nas_async(userid):
    """重启 NAS（后台线程跑 vim-cmd power.reboot，完成后把结果发给用户）。"""
    def _run():
        try:
            vmid = esxi_find_nas_vm()
            esxi_run(f"vim-cmd vmsvc/power.reboot {vmid}")
            msg = "✅ 已下发重启 NAS 的指令。NAS 正在重启，几分钟后恢复。\n此桥跑在 NAS 上，重启期间我会暂时掉线，恢复后会自动上线。"
        except Exception as e:
            msg = f"重启 NAS 失败：{e}"
        send_reply(userid, text_reply(msg))
    threading.Thread(target=_run, daemon=True).start()


# ---------------- 主动告警（v2.1 新增，从 Telegram bot3 复制） ----------------

_ALERT_STATE_FILE = "alerts.json"
_ALERT_STATE = {"last_check": "", "last_alert": {}}


def alerts_state_path():
    return os.path.join(DATA_DIR, _ALERT_STATE_FILE)


def alerts_enabled():
    """告警开关：只看 alerts.json 里的 enabled，默认 ALERT_ENABLED_DEFAULT。"""
    try:
        with open(alerts_state_path(), encoding="utf-8") as f:
            return bool(json.load(f).get("enabled", ALERT_ENABLED_DEFAULT))
    except (FileNotFoundError, ValueError):
        return ALERT_ENABLED_DEFAULT


def alerts_set_enabled(enabled):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(alerts_state_path(), "w", encoding="utf-8") as f:
        json.dump({"enabled": bool(enabled)}, f)


def _alert_allowed(key):
    """同一种告警 1 小时内只发一次；从没发过的第一次一定发。"""
    last = _ALERT_STATE["last_alert"].get(key)
    if last is not None and time.monotonic() - last < ALERT_COOLDOWN_SEC:
        return False
    _ALERT_STATE["last_alert"][key] = time.monotonic()
    return True


def run_alert_check():
    """一次告警检查，返回告警正文列表（无事返回 []）。"""
    alerts = []
    try:
        items = list_containers()
        now = time.monotonic()
        for c in items:
            if c.get("State") != "running":
                stop_deadline = _INTENTIONAL_STOPS.get(c["Id"], 0)
                if now < stop_deadline:
                    continue
                key = f"container:{c['Id']}"
                if _alert_allowed(key):
                    alerts.append(f"⚠️ 容器 {container_display_name(c)} 已停止（状态：{c.get('State', '?')}）。")
    except Exception as e:
        log("告警检查（容器）失败：", e)
    try:
        for fs in read_disk_usage():
            pct = fs["used"] / fs["total"] * 100.0 if fs["total"] else 0
            if pct > ALERT_DISK_PCT and _alert_allowed(f"disk:{fs['mountpoint']}"):
                alerts.append(f"⚠️ 磁盘 {fs['mountpoint']} 已用 {pct:.0f}%（>{ALERT_DISK_PCT:g}%）。")
    except Exception as e:
        log("告警检查（磁盘）失败：", e)
    try:
        load1, _, _ = os.getloadavg()
        load_limit = _cpu_count() * ALERT_LOAD_MULT
        if load1 > load_limit and _alert_allowed("load"):
            alerts.append(f"⚠️ 系统负载 {load1:.2f} 超过阈值 {load_limit:.1f}（{_cpu_count()} 核 ×{ALERT_LOAD_MULT:g}）。")
    except Exception as e:
        log("告警检查（负载）失败：", e)
    try:
        mem = read_memory()
        if mem["used_pct"] > ALERT_MEM_PCT and _alert_allowed("mem"):
            alerts.append(f"⚠️ 内存占用 {mem['used_pct']:.0f}% 超过 {ALERT_MEM_PCT:g}%。")
    except Exception as e:
        log("告警检查（内存）失败：", e)
    _ALERT_STATE["last_check"] = cst_now()
    return alerts


def alert_loop():
    """后台循环：每 ALERT_INTERVAL_SEC 秒检查一次，告警发给全部白名单用户。"""
    while True:
        time.sleep(ALERT_INTERVAL_SEC)
        try:
            if not alerts_enabled():
                continue
            alerts = run_alert_check()
            if alerts:
                text = "🚨 NAS 告警\n" + "\n".join(alerts)
                for uid in OWNER_USERIDS:
                    send_reply(uid, text_reply(text))
        except Exception:
            log("alert loop error:", traceback.format_exc(limit=3))


# ---------------- 容器镜像更新检查（v2.1 新增，从 bot3 复制） ----------------

_IMAGE_CHECK_STATE = {"last_check": "", "last_result": ""}


def run_image_check_all():
    """全部容器拉新镜像、比 image Id。返回 (有更新的 [{name, image}], 消息)。

    带 digest 的镜像跳过；本桥自己跳过（用菜单“检查更新”走自我更新流程）。
    """
    try:
        items = list_containers()
    except Exception as e:
        return [], f"容器列表读不到：{e}"
    updates = []
    for c in items:
        name = container_display_name(c)
        if name == SELF_CONTAINER_NAME:
            continue
        image = (c.get("Image") or "").strip()
        if not image:
            continue
        if "@" in image:
            continue  # 带 digest 的镜像无法拉取最新，跳过
        try:
            inspect_data = inspect_container(c["Id"])
        except Exception:
            continue
        old_id = inspect_data.get("Image", "")
        try:
            ok, _msg = docker_pull(image)
            if not ok:
                continue
            img = docker_json("GET", "/images/" + quote(image, safe="") + "/json")
            new_id = img.get("Id", "")
            if new_id and old_id and new_id != old_id:
                updates.append({"name": name, "image": image})
        except Exception as e:
            log("image check skip:", name, type(e).__name__, str(e)[:100])
    _IMAGE_CHECK_STATE["last_check"] = cst_now()
    _IMAGE_CHECK_STATE["last_result"] = (f"发现 {len(updates)} 个容器有新镜像"
                                         if updates else "全部容器镜像都是最新")
    return updates, _IMAGE_CHECK_STATE["last_result"]


def image_check_loop():
    """后台循环：启动后 60 秒先检查一次，之后每 IMAGE_CHECK_INTERVAL_SEC 检查一次。

    只在“新发现”有更新的容器时才通知；已通知过的镜像更新只会出现在
    “检查容器更新”结果卡里，不会重复打扰。
    """
    if not IMAGE_CHECK_ENABLED:
        return
    notified = set()
    while True:
        time.sleep(60 if not _IMAGE_CHECK_STATE["last_check"] else IMAGE_CHECK_INTERVAL_SEC)
        try:
            updates, _msg = run_image_check_all()
            fresh = [u for u in updates if u["name"] not in notified]
            if fresh:
                text = ("🐳 发现容器镜像有更新\n" +
                        "\n".join(f"· {u['name']}（{u['image']}）" for u in fresh) +
                        "\n点“检查容器更新”看详情，每个容器可单独确认更新。")
                for uid in OWNER_USERIDS:
                    send_reply(uid, text_reply(text))
                for u in fresh:
                    notified.add(u["name"])
        except Exception:
            log("image check loop error:", traceback.format_exc(limit=3))


# ---------------- 自我更新（v2.1 新增，从 bot3 复制，适配 WeCom） ----------------

_SELFUPDATE_STATE = {"candidate": None, "candidate_at": 0}


def _github_headers():
    headers = {"Accept": "application/vnd.github.v3+json",
               "User-Agent": "wecom-callback-bridge"}
    if UPDATE_TOKEN:
        headers["Authorization"] = f"Bearer {UPDATE_TOKEN}"
    return headers


def github_file_sha(ref="main", path="wecom_callback.py"):
    """查 GitHub 上 wecom_callback.py 当前的 sha。"""
    url = f"https://api.github.com/repos/{UPDATE_REPO}/contents/{path}?ref={ref}"
    req = urllib.request.Request(url, headers=_github_headers())
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RuntimeError(f"仓库或文件不存在：{UPDATE_REPO}（ref={ref}）")
        if e.code == 401:
            raise RuntimeError("GitHub 认证失败：UPDATE_TOKEN 无效或过期")
        raise RuntimeError(f"GitHub API 失败：{e.code}")
    except Exception as e:
        raise RuntimeError(f"GitHub 请求失败：{e}")
    return data.get("sha"), data.get("content", "").replace("\n", "")


def _validate_candidate(src):
    """校验候选更新：大小 10KB-500KB、UTF-8、版本比当前新、含关键函数、可编译。"""
    if not (10 * 1024 <= len(src) <= 500 * 1024):
        return False, f"候选文件大小异常（{len(src)} 字节）"
    try:
        src_str = src.decode("utf-8")
    except UnicodeDecodeError:
        return False, "候选文件不是 UTF-8"
    m = re.search(r'^VERSION\s*=\s*"([0-9.]+)"', src_str, re.M)
    if not m:
        return False, "候选文件里没有 VERSION"
    new_version = m.group(1)
    if new_version <= VERSION:
        return False, f"候选版本 {new_version} 不比当前版本 {VERSION} 新"
    for marker in ("def main(", "def handle_callback(", "def handle("):
        if marker not in src_str:
            return False, f"候选文件缺关键函数 {marker}"
    try:
        compile(src_str, "wecom_callback.py", "exec")
    except SyntaxError as e:
        return False, f"候选文件语法错误：{e}"
    return True, new_version


def _self_update_candidate_path():
    return os.path.join(DATA_DIR, "update_candidate.py")


def check_self_update():
    """检查 GitHub 上有没有新版本。返回 (有新版本, 消息)。"""
    if not UPDATE_REPO:
        return False, SELFUPDATE_NOT_CONFIGURED_TEXT
    try:
        sha, content_b64 = github_file_sha(ref=UPDATE_BRANCH)
    except Exception as e:
        return False, f"检查更新失败：{e}"
    try:
        src = base64.b64decode(content_b64)
    except Exception:
        return False, "GitHub 返回的内容解不开。"
    ok, info = _validate_candidate(src)
    if not ok:
        if info.startswith("候选版本"):
            return False, f"✅ 当前已是最新版本 v{VERSION}（GitHub 上 {info}）。"
        return False, f"检查更新失败：{info}"
    with open(_self_update_candidate_path(), "wb") as f:
        f.write(src)
    _SELFUPDATE_STATE["candidate"] = src
    _SELFUPDATE_STATE["candidate_at"] = time.monotonic()
    return True, f"⬆️ 发现新版本 v{info}（当前 v{VERSION}），已下载到本地待确认。"


def install_staged_update():
    """装已验证的候选更新：备份当前文件、换成候选、重启容器。"""
    candidate_path = _self_update_candidate_path()
    if not os.path.exists(candidate_path):
        return False, "没有待安装的更新候选，请先点“检查更新”。"
    if time.monotonic() - _SELFUPDATE_STATE.get("candidate_at", 0) > 1800:
        try:
            os.remove(candidate_path)
        except OSError:
            pass
        return False, "更新候选已过期（30 分钟），请重新检查更新。"
    src = _SELFUPDATE_STATE.get("candidate")
    if src is None:
        with open(candidate_path, "rb") as f:
            src = f.read()
    ok, info = _validate_candidate(src)
    if not ok:
        return False, f"候选校验失败，拒绝安装：{info}"
    script_path = os.path.abspath(__file__)
    backup_path = script_path + ".bak"
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(script_path, "rb") as f:
            old = f.read()
        with open(backup_path, "wb") as f:
            f.write(old)
        with open(script_path, "wb") as f:
            f.write(src)
        os.remove(candidate_path)
        _SELFUPDATE_STATE["candidate"] = None
        log(f"自我更新：已备份到 {backup_path}，正在重启容器")
        threading.Thread(target=_restart_self, daemon=True).start()
        return True, f"✅ 已安装 v{info}，正在重启容器（备份在 {backup_path}，30 秒后恢复）。"
    except Exception as e:
        log("install update error:", traceback.format_exc(limit=3))
        return False, f"安装失败：{e}"


def _restart_self():
    """本容器重启：优先用 Docker API 重启自己（容器内可调 Docker socket）。"""
    time.sleep(2)
    try:
        self_id = None
        with open("/proc/self/cgroup", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                m = re.search(r"/docker/([0-9a-f]{64})", ln)
                if m:
                    self_id = m.group(1)
                    break
        if self_id:
            docker_api("POST", f"/containers/{self_id}/restart?t=5", timeout=30)
            return
    except Exception as e:
        log("restart self via Docker API failed:", e)
    try:
        os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)])
    except Exception as e:
        log("restart self exec failed:", e)


# ---------------- 消息路由（与 v1.0 同一套优先级，可单测） ----------------

def strip_mention(text):
    """群聊里 @机器人 的前缀去掉，只留正文。"""
    text = (text or "").strip()
    if text.startswith("@"):
        parts = text.split(None, 1)
        if len(parts) == 2:
            return parts[1].strip()
        return ""
    return text


def is_destructive(text):
    lowered = text.lower()
    return any(kw.lower() in lowered for kw in DESTRUCTIVE_KEYWORDS)


def truncate_answer(text, limit=MAX_ANSWER_CHARS):
    if len(text) <= limit:
        return text
    return text[:limit] + "\n…（已截断）"


def chat_llm(user_text):
    """走 OpenAI 兼容接口聊天。未配置或出错只返回人话，绝不抛 traceback。"""
    if not LLM_API_KEY:
        log("LLM 未配置：LLM_API_KEY 为空")
        return LLM_NOT_CONFIGURED_TEXT
    url = LLM_API_BASE.rstrip("/") + "/chat/completions"
    try:
        resp = requests.post(url, json={
            "model": LLM_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_text},
            ],
        }, timeout=LLM_TIMEOUT_SEC)
        resp.raise_for_status()
        data = resp.json()
        content = (((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
        if not content:
            log("LLM 返回空内容")
            return LLM_ERROR_TEXT
        return content
    except Exception as e:
        # 只记错误类型，不把响应体/堆栈发给用户。
        log("LLM 调用失败：", type(e).__name__, str(e)[:200])
        return LLM_ERROR_TEXT


def text_reply(content):
    """文本回复（markdown 短段落），超长按字符截断。"""
    return {"kind": "text", "content": truncate_answer(content)}


def card_reply(card):
    """模板卡片回复。"""
    return {"kind": "template_card", "card": card}


def handle_text(text, userid=""):
    """路由一条文本消息，返回回复对象 {"kind": "text"|"template_card", ...}。

    优先级：(a) 搜日志关键词输入 → (b) 容器管理序号选择 → (c) /命令和中文直达
    （只读本地查询）→ (d) 需要确认的危险操作 → (e) 帮助 → (f) LLM 聊天。
    状态 / 磁盘 / 温度走模板卡片，容器列表走 markdown 短行，绝不发彩条文本块。
    """
    text = strip_mention(text)
    if not text:
        return text_reply(HELP_TEXT)
    lowered = text.lower().replace(" ", "").replace("　", "")
    # (a) 正在等用户回“搜日志关键词”（卡片 [搜日志] 点完后）
    pending = _PENDING_SEARCH.get(userid)
    if pending:
        shortid, expires = pending
        if time.monotonic() <= expires:
            del _PENDING_SEARCH[userid]
            try:
                hits, total = search_container_logs(shortid, text, tail=200)
                if not hits:
                    return text_reply(f"🔍 在 {shortid} 最近 200 行日志里没找到“{text}”。")
                body = "\n".join(hits)
                return text_reply(f"🔍 “{text}”在 {shortid} 里命中 {total} 行\n{body[-3000:]}")
            except Exception as e:
                log("搜日志失败：", type(e).__name__, str(e)[:200])
                return text_reply(f"搜日志失败：{e}")
        del _PENDING_SEARCH[userid]
    # (b) 容器管理 / ESXi 列表的序号选择
    state = _MANAGE_STATE.get(userid)
    if state and time.monotonic() <= state.get("expires", 0) and lowered.isdigit():
        idx = int(lowered) - 1
        items = state.get("items") or []
        if 0 <= idx < len(items):
            try:
                c = inspect_container(items[idx])
                return card_reply(build_container_detail_card(c, inspect=c))
            except Exception as e:
                log("容器详情失败：", type(e).__name__, str(e)[:200])
                return text_reply(f"容器详情读不到：{e}")
    esxi_state = _ESXI_STATE.get(userid)
    if esxi_state and time.monotonic() <= esxi_state.get("expires", 0) and lowered.isdigit():
        idx = int(lowered) - 1
        items = esxi_state.get("items") or []
        if 0 <= idx < len(items):
            try:
                vms = esxi_list_vms()
                for v in vms:
                    if v["vmid"] == items[idx]:
                        return card_reply(build_vm_detail_card(v))
                return text_reply("这个 VM 现在找不到了，请重新点 ESXi VM。")
            except Exception as e:
                log("VM 详情失败：", type(e).__name__, str(e)[:200])
                return text_reply(f"VM 详情读不到：{e}")
    # (c) /命令和中文直达
    try:
        if lowered in ("系统状态", "nas状态", "状态", "status", "/status"):
            return card_reply(build_status_card())
        if lowered in ("公网ip", "公网", "ip", "/ip"):
            return text_reply(fmt_public_ip_markdown())
        if lowered in ("磁盘空间", "磁盘", "disk", "/disk"):
            card = build_disk_card()
            if card is None:
                return text_reply("磁盘读不到，请稍后再试，或去 Telegram 3 号机器人查。")
            return card_reply(card)
        if lowered in ("温度", "temp", "temperature"):
            card = build_temp_card()
            if card is None:
                return text_reply(TEMP_UNAVAILABLE_TEXT)
            return card_reply(card)
        if lowered in ("进程top", "top", "进程"):
            return text_reply(fmt_top_markdown())
        if lowered in ("网络流量", "网络", "流量", "net"):
            return text_reply(fmt_net_markdown())
        if lowered in ("容器列表", "容器", "containers", "/docker"):
            return text_reply(fmt_containers_markdown())
        if lowered in ("容器管理", "管理容器", "管理"):
            card, _page, _total, _n = build_manage_card(page=0, userid=userid)
            return card_reply(card)
        if lowered in ("容器资源", "资源", "stats"):
            return text_reply(fmt_stats_markdown())
        if lowered in ("检查容器更新", "容器更新"):
            return _check_updates_reply(userid)
        if lowered in ("清理镜像", "清理", "prune"):
            return ask_confirm("prune", "prune", "", "🧹 清理悬空镜像",
                               "只清悬空镜像，不碰正在用的镜像。",
                               userid)
        if lowered in ("esxi", "esxivm", "vm", "/esxi"):
            return _esxi_list_reply(userid)
        if lowered in ("告警", "alerts", "/alerts"):
            return card_reply(build_alerts_card())
        if lowered in ("检查更新", "自我更新", "自升", "检查更新（自升）"):
            return _self_update_check_reply(userid)
        if lowered in ("/check_updates", "/checkupdates"):
            return _check_updates_reply(userid)
        if lowered in ("重启nas", "重启", "reboot"):
            if not (ESXI_HOST and (NAS_VM_NAME or NAS_VM_ID)):
                return text_reply(NAS_REBOOT_NOT_CONFIGURED_TEXT)
            return ask_confirm("nas", "reboot", "", "🔄 重启 NAS",
                               "NAS 整个重启，桥会掉线几分钟。",
                               userid)
        if lowered in ("帮助", "help", "/help", "你好", "hi", "hello",
                       "你能做什么", "功能"):
            return text_reply(HELP_TEXT)
        if lowered in ("菜单", "menu", "/menu"):
            return card_reply(build_help_card())
        m = re.match(r"^(?:容器日志|日志|logs?)\s*(.+)$", text, re.IGNORECASE)
        if lowered in ("容器日志", "日志"):
            return text_reply("请告诉我容器名，例如：容器日志 tg-bot3")
        if m:
            name = m.group(1).strip()
            if not name:
                return text_reply("请告诉我容器名，例如：容器日志 tg-bot3")
            logs = container_logs(name, tail=50)
            logs = logs[-3000:] if len(logs) > 3000 else logs
            return text_reply(f"📋 {name} 最近日志\n{logs}" if logs else f"📋 {name} 最近没有日志。")
        m2 = re.match(r"^/docker\s+(.+)$", text, re.IGNORECASE)
        if m2:
            return _docker_command(m2.group(1).strip(), userid)
        m3 = re.match(r"^/esxi\s+(.+)$", text, re.IGNORECASE)
        if m3:
            return _esxi_command(m3.group(1).strip(), userid)
        m4 = re.match(r"^/alerts\s+(.+)$", text, re.IGNORECASE)
        if m4:
            return _alerts_command(m4.group(1).strip(), userid)
    except Exception as e:
        log("本地查询失败：", type(e).__name__, str(e)[:200])
        return text_reply(f"本地查询失败：{e}。请稍后再试，或去 Telegram 3 号机器人查。")
    # (d) 需要确认的危险操作（TG 里是直接执行 / 两次确认，企微一律先出确认卡）
    if is_destructive(text):
        return _destructive_confirm(text, userid)
    return text_reply(chat_llm(text))


def _check_updates_reply(userid):
    """“检查容器更新”：先回“正在检查…”，后台线程跑完再把结果卡发给用户。"""
    def _run():
        try:
            updates, msg = run_image_check_all()
        except Exception as e:
            send_reply(userid, text_reply(f"检查容器更新失败：{e}"))
            return
        if not updates:
            send_reply(userid, text_reply("🐳 全部容器镜像都是最新。"))
            return
        rows = []
        buttons = []
        for u in updates[:5]:
            rows.append({"keyname": u["name"][:12], "value": _card_value(u["image"])})
            buttons.append({"text": f"⬆️ 更新 {u['name'][:8]}", "style": 1,
                            "key": f"U_ASK_{u['name']}"})
        buttons.append({"text": "⬅️ 主菜单", "style": 2, "key": "CARD_MENU"})
        sub = "点“更新”会先出确认卡"
        if len(updates) > 5:
            sub += f"，还有 {len(updates) - 5} 个有更新的容器未列出"
        card = _make_card(f"🐳 发现 {len(updates)} 个容器有新镜像", rows,
                          buttons=buttons[:6], task_prefix="uc",
                          sub_title=sub)
        send_reply(userid, card_reply(card))
    threading.Thread(target=_run, daemon=True).start()
    return text_reply("🐳 正在检查全部容器镜像（要拉一遍镜像，请稍等，查完我发结果给你）。")


def _esxi_list_reply(userid):
    """ESXi VM 列表：未配置回提示，否则出列表卡。"""
    if not ESXI_HOST:
        return text_reply(ESXI_NOT_CONFIGURED_TEXT)
    try:
        vms = esxi_list_vms()
    except Exception as e:
        log("ESXi 列表失败：", type(e).__name__, str(e)[:200])
        return text_reply(f"ESXi 列表读不到：{e}")
    if not vms:
        return text_reply("🖥️ ESXi 上没有 VM。")
    return card_reply(build_esxi_list_card(vms, userid=userid))


def _self_update_check_reply(userid):
    """“检查更新（自我更新）”：有新版本 → 确认卡；已是最新 / 未配置 → 文本。"""
    try:
        has_update, msg = check_self_update()
    except Exception as e:
        return text_reply(f"检查更新失败：{e}")
    if not has_update:
        return text_reply(msg)
    return ask_confirm("selfupdate", "install", "", "⬆️ 安装自我更新",
                       msg, userid)


def _docker_command(args, userid):
    """处理 /docker <子命令>：logs/start/stop/restart/prune/update。

    TG 里 start/stop/restart 是直接执行；企微一律先出确认卡。
    """
    parts = args.split()
    if not parts:
        return text_reply(fmt_containers_markdown())
    sub = parts[0].lower()
    if sub == "logs":
        if len(parts) < 2:
            return text_reply("用法：/docker logs <容器名> [行数] [关键词]")
        tail = 50
        keyword = None
        rest = parts[2:]
        if rest and rest[0].isdigit():
            tail = int(rest[0])
            rest = rest[1:]
        if rest:
            keyword = " ".join(rest)
        try:
            if keyword:
                hits, total = search_container_logs(parts[1], keyword, tail=200)
                if not hits:
                    return text_reply(f"🔍 在 {parts[1]} 最近 200 行日志里没找到“{keyword}”。")
                return text_reply(f"🔍 “{keyword}”在 {parts[1]} 里命中 {total} 行\n" + "\n".join(hits)[-3000:])
            logs = container_logs(parts[1], tail=tail)
            logs = logs[-3000:] if len(logs) > 3000 else logs
            return text_reply(f"📋 {parts[1]} 最近日志\n{logs}" if logs else f"📋 {parts[1]} 最近没有日志。")
        except Exception as e:
            return text_reply(f"读日志失败：{e}")
    if sub in ("start", "stop", "restart"):
        if len(parts) < 2:
            return text_reply(f"用法：/docker {sub} <容器名>")
        try:
            c = resolve_container(parts[1])
        except Exception as e:
            return text_reply(f"找不到容器：{e}")
        labels = {"start": "▶️ 启动容器", "stop": "⏹️ 停止容器", "restart": "🔄 重启容器"}
        return ask_confirm("container", sub, c["Id"],
                           f"{labels[sub]} {container_display_name(c)}",
                           f"目标：{container_display_name(c)}（{c['Id'][:12]}）",
                           userid)
    if sub == "prune":
        return ask_confirm("prune", "prune", "", "🧹 清理悬空镜像",
                           "只清悬空镜像，不碰正在用的镜像。", userid)
    if sub == "update":
        if len(parts) < 2:
            return text_reply("用法：/docker update <容器名>")
        try:
            c = resolve_container(parts[1])
        except Exception as e:
            return text_reply(f"找不到容器：{e}")
        return ask_confirm("container", "update", c["Id"],
                           f"⬆️ 更新容器 {container_display_name(c)}",
                           "拉新镜像并重建，失败自动回滚旧容器。",
                           userid)
    return text_reply(f"不知道 /docker {sub}。用法：/docker [logs|start|stop|restart|prune|update] <容器名>")


def _esxi_command(args, userid):
    """处理 /esxi <子命令>：on/off/kill <vmid>，一律先出确认卡。"""
    parts = args.split()
    if not parts:
        return _esxi_list_reply(userid)
    sub = parts[0].lower()
    if sub in ("on", "off", "kill"):
        if len(parts) < 2:
            return text_reply(f"用法：/esxi {sub} <VM ID>")
        labels = {"on": "▶️ 开机", "off": "⏻ 优雅关机", "kill": "⚡ 强制断电"}
        return ask_confirm("vm", sub, parts[1],
                           f"{labels[sub]} VM {parts[1]}",
                           "VM 电源操作，请确认。", userid)
    return text_reply(f"不知道 /esxi {sub}。用法：/esxi [on|off|kill] <VM ID>")


def _alerts_command(args, userid):
    """处理 /alerts <子命令>：on/off 开关告警。"""
    sub = args.split()[0].lower() if args.split() else ""
    if sub == "on":
        alerts_set_enabled(True)
        return text_reply("🔔 告警已开启。")
    if sub == "off":
        alerts_set_enabled(False)
        return text_reply("🔕 告警已关闭。")
    return card_reply(build_alerts_card())


def _destructive_confirm(text, userid):
    """把一条危险文字指令转成确认卡（绝不直接执行）。

    识别：重启 NAS / 容器 start|stop|restart|update / 清理镜像 / VM 电源。
    认不出的危险词仍按 v2.0 回绝（不猜目标）。
    """
    lowered = text.lower().replace(" ", "").replace("　", "")
    if ("重启nas" in lowered or lowered in ("重启", "reboot")
            or any(k in lowered for k in ("重启服务器", "重启主机", "重启系统"))):
        if not (ESXI_HOST and (NAS_VM_NAME or NAS_VM_ID)):
            return text_reply(NAS_REBOOT_NOT_CONFIGURED_TEXT)
        return ask_confirm("nas", "reboot", "", "🔄 重启 NAS",
                           "NAS 整个重启，桥会掉线几分钟。", userid)
    if "清理镜像" in lowered or "清理" in lowered:
        return ask_confirm("prune", "prune", "", "🧹 清理悬空镜像",
                           "只清悬空镜像，不碰正在用的镜像。", userid)
    m = re.match(r"^(?:启动|停止|重启|更新)(.+)$", text)
    if m:
        name = re.sub(r"^容器\s*", "", m.group(1).strip())
        try:
            c = resolve_container(name)
        except Exception as e:
            return text_reply(f"找不到容器：{e}")
        action = {"启动": "start", "停止": "stop", "重启": "restart", "更新": "update"}[text[:2]]
        labels = {"start": "▶️ 启动容器", "stop": "⏹️ 停止容器",
                  "restart": "🔄 重启容器", "update": "⬆️ 更新容器"}
        detail = ("拉新镜像并重建，失败自动回滚旧容器。" if action == "update"
                  else f"目标：{container_display_name(c)}（{c['Id'][:12]}）")
        return ask_confirm("container", action, c["Id"],
                           f"{labels[action]} {container_display_name(c)}",
                           detail, userid)
    log("破坏性操作请求已回绝（无法识别目标）：", userid, text[:80])
    return text_reply(DESTRUCTIVE_TEXT)


def route_menu_click(event_key, userid=""):
    """底部菜单点击 → 等价的文字指令 → 同一套路由。未知 key 返回帮助。"""
    text = MENU_KEY_TO_TEXT.get(event_key)
    if text is None:
        log("未知的菜单 EventKey：", event_key, "来自", userid)
        return text_reply(HELP_TEXT)
    log("菜单点击：", event_key, "→", text, "来自", userid)
    return handle_text(text, userid)


def route_card_click(event_key, userid=""):
    """卡片按钮点击 → 对应的卡片 / 文本 / 确认卡。未知 key 返回帮助。

    破坏性按钮（C_ASK_*/E_ASK_*/MG_PRUNE/U_ASK_*/SU_ASK/CF_OK_）只建确认，
    绝不直接执行；执行只发生在 CF_OK_（确认令牌有效且是本人）。
    """
    if event_key == "CARD_TEMP":
        card = build_temp_card()
        if card is None:
            return text_reply(TEMP_UNAVAILABLE_TEXT)
        return card_reply(card)
    if event_key == "CARD_DISK":
        card = build_disk_card()
        if card is None:
            return text_reply("磁盘读不到，请稍后再试，或去 Telegram 3 号机器人查。")
        return card_reply(card)
    if event_key == "CARD_REFRESH":
        return card_reply(build_status_card())
    if event_key == "CARD_STATUS":
        return card_reply(build_status_card())
    if event_key == "CARD_CONTAINERS":
        return text_reply(fmt_containers_markdown())
    if event_key == "CARD_MENU":
        return card_reply(build_help_card())
    if event_key.startswith("MG_PREV_") or event_key.startswith("MG_NEXT_"):
        try:
            page = int(event_key.rsplit("_", 1)[1])
        except ValueError:
            return text_reply(HELP_TEXT)
        card, _p, _t, _n = build_manage_card(page=page, userid=userid)
        return card_reply(card)
    if event_key == "MG_PRUNE":
        return ask_confirm("prune", "prune", "", "🧹 清理悬空镜像",
                           "只清悬空镜像，不碰正在用的镜像。", userid)
    if event_key.startswith("C_LOGS_"):
        shortid = event_key[len("C_LOGS_"):]
        try:
            logs = container_logs(shortid, tail=50)
            logs = logs[-3000:] if len(logs) > 3000 else logs
            return text_reply(f"📋 {shortid} 最近日志\n{logs}" if logs else f"📋 {shortid} 最近没有日志。")
        except Exception as e:
            return text_reply(f"读日志失败：{e}")
    if event_key.startswith("C_SEARCH_"):
        shortid = event_key[len("C_SEARCH_"):]
        _PENDING_SEARCH[userid] = (shortid, time.monotonic() + _SELECT_TTL_SEC)
        return text_reply(f"🔍 请直接发要搜的关键词（在 {shortid} 最近 200 行日志里找）。")
    if event_key.startswith("C_ASK_"):
        rest = event_key[len("C_ASK_"):]
        action, _, shortid = rest.partition("_")
        action = action.lower()
        if action in ("start", "stop", "restart", "update") and shortid:
            try:
                c = resolve_container(shortid)
            except Exception as e:
                return text_reply(f"找不到容器：{e}")
            labels = {"start": "▶️ 启动容器", "stop": "⏹️ 停止容器",
                      "restart": "🔄 重启容器", "update": "⬆️ 更新容器"}
            detail = ("拉新镜像并重建，失败自动回滚旧容器。" if action == "update"
                      else f"目标：{container_display_name(c)}（{c['Id'][:12]}）")
            return ask_confirm("container", action, c["Id"],
                               f"{labels[action]} {container_display_name(c)}",
                               detail, userid)
        log("未知的容器操作按钮：", event_key, "来自", userid)
        return text_reply(HELP_TEXT)
    if event_key == "E_LIST":
        return _esxi_list_reply(userid)
    if event_key.startswith("E_DETAIL_"):
        vmid = event_key[len("E_DETAIL_"):]
        if not ESXI_HOST:
            return text_reply(ESXI_NOT_CONFIGURED_TEXT)
        try:
            vms = esxi_list_vms()
            for v in vms:
                if v["vmid"] == vmid:
                    return card_reply(build_vm_detail_card(v))
            return text_reply("这个 VM 现在找不到了，请重新点 ESXi VM。")
        except Exception as e:
            return text_reply(f"VM 详情读不到：{e}")
    if event_key.startswith("E_ASK_"):
        rest = event_key[len("E_ASK_"):]
        action, _, vmid = rest.partition("_")
        action = action.lower()
        if action in ("on", "off", "kill") and vmid:
            labels = {"on": "▶️ 开机", "off": "⏻ 优雅关机", "kill": "⚡ 强制断电"}
            return ask_confirm("vm", action, vmid,
                               f"{labels[action]} VM {vmid}",
                               "VM 电源操作，请确认。", userid)
        log("未知的 VM 电源按钮：", event_key, "来自", userid)
        return text_reply(HELP_TEXT)
    if event_key == "ALERT_ON":
        alerts_set_enabled(True)
        return text_reply("🔔 告警已开启。")
    if event_key == "ALERT_OFF":
        alerts_set_enabled(False)
        return text_reply("🔕 告警已关闭。")
    if event_key.startswith("U_ASK_"):
        name = event_key[len("U_ASK_"):]
        try:
            c = resolve_container(name)
        except Exception as e:
            return text_reply(f"找不到容器：{e}")
        return ask_confirm("container", "update", c["Id"],
                           f"⬆️ 更新容器 {container_display_name(c)}",
                           "拉新镜像并重建，失败自动回滚旧容器。", userid)
    if event_key == "SU_ASK":
        return _self_update_check_reply(userid)
    if event_key.startswith("CF_OK_"):
        token = event_key[len("CF_OK_"):]
        return execute_confirm(token, userid)
    if event_key.startswith("CF_NO_"):
        token = event_key[len("CF_NO_"):]
        with _PENDING_CONFIRM_LOCK:
            entry = _PENDING_CONFIRM.pop(token, None)
        if entry and entry.get("userid") == userid:
            return text_reply("已取消，没有执行任何操作。")
        return text_reply("这个确认已过期或不存在，没有执行任何操作。")
    log("未知的卡片按钮 key：", event_key, "来自", userid)
    return text_reply(HELP_TEXT)


def execute_confirm(token, userid):
    """执行一次已确认的操作：令牌无效/过期/不是本人 → 拒绝（不执行）。

    容器更新和重启 NAS 是慢活：先回“开始…”，后台线程跑完再把结果发给用户。
    """
    entry = take_confirm(token, userid)
    if entry is None:
        return text_reply("这个确认已过期（5 分钟）或不是你的操作，没有执行任何操作。请重新操作一次。")
    kind = entry.get("kind")
    action = entry.get("action")
    target = entry.get("target")
    label = entry.get("label", "操作")
    log("已确认，执行：", kind, action, target, "来自", userid)
    try:
        if kind == "container":
            if action == "update":
                update_container_async(target, userid)
                return text_reply(f"⬆️ 开始更新容器 {label}，拉镜像要一会儿，完成后我发结果给你。")
            c = container_action(target, action)
            verb = {"start": "已启动", "stop": "已停止", "restart": "已重启"}[action]
            return text_reply(f"✅ {verb}容器 {container_display_name(c)}。")
        if kind == "prune":
            count, reclaimed = prune_images()
            return text_reply(f"✅ 清理完成：清了 {count} 个悬空镜像，释放 {human_bytes(reclaimed)}。")
        if kind == "vm":
            esxi_vm_power(target, action)
            verb = {"on": "已开机", "off": "已下发优雅关机", "kill": "已强制断电"}[action]
            return text_reply(f"✅ VM {target} {verb}。")
        if kind == "nas":
            reboot_nas_async(userid)
            return text_reply("✅ 已确认，正在下发重启 NAS 的指令…")
        if kind == "selfupdate":
            ok, msg = install_staged_update()
            return text_reply(msg)
    except Exception as e:
        log("确认操作执行失败：", kind, action, target, type(e).__name__, str(e)[:200])
        return text_reply(f"执行失败：{e}。没有改动的部分请重新操作。")
    return text_reply("未知操作，没有执行任何操作。")


# ---------------- 自建应用主动发消息（gettoken + message/send） ----------------

def split_text_chunks(text, max_bytes=MAX_TEXT_BYTES):
    """按 2048 字节上限切分文本，优先在换行处断开，绝不在 UTF-8 字符中间断开。

    先按行切，再把超长的行按字节硬切（不引入额外换行），最后把小段
    贪心拼回接近上限的块。每个片段自带它后面的原始换行，拼接时原样还原。
    """
    pieces = []  # 每个片段已经包含它后面的原始换行（如果有）
    lines = text.split("\n")
    for i, line in enumerate(lines):
        suffix = "\n" if i < len(lines) - 1 else ""
        rest = line
        while len(rest.encode("utf-8")) > max_bytes:
            buf = ""
            for ch in rest:
                if len((buf + ch).encode("utf-8")) > max_bytes:
                    break
                buf += ch
            if not buf:  # 单个字符就超上限（理论上不会），硬切一个字符
                buf = rest[0]
            pieces.append(buf)
            rest = rest[len(buf):]
        if len((rest + suffix).encode("utf-8")) > max_bytes:
            pieces.append(rest)
            if suffix:
                pieces.append(suffix)
        else:
            pieces.append(rest + suffix)
    chunks = []
    cur = ""
    for piece in pieces:
        if cur and len((cur + piece).encode("utf-8")) > max_bytes:
            chunks.append(cur)
            cur = ""
        cur += piece
    if cur != "" or not chunks:
        chunks.append(cur)
    return chunks


class WeComAppClient:
    """自建应用发消息客户端：gettoken（带 2 小时缓存）+ message/send。

    注意：发消息的出口 IP 必须在企业可信 IP 列表里（管理后台手动加），
    否则 message/send 报 60020。这个检查在企微服务端做，代码绕不过。
    """

    TOKEN_EXPIRED = (42001, 40014, 41001)  # access_token 失效类错误码，重取一次再试

    def __init__(self, corpid=None, secret=None, agentid=None):
        self.corpid = corpid if corpid is not None else WECOM_CORPID
        self.secret = secret if secret is not None else WECOM_SECRET
        self.agentid = agentid if agentid is not None else WECOM_AGENTID
        self._token = None
        self._token_expires_at = 0.0
        self._lock = threading.Lock()

    def get_access_token(self):
        """取 access_token（缓存到过期前 60 秒）。只记成功/失败，不记 token 值。"""
        now = time.monotonic()
        with self._lock:
            if self._token and now < self._token_expires_at - 60:
                return self._token
        url = f"{WECOM_API_BASE}/cgi-bin/gettoken"
        resp = requests.get(url, params={"corpid": self.corpid, "corpsecret": self.secret},
                            timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if data.get("errcode") != 0:
            raise RuntimeError(f"gettoken 失败 errcode={data.get('errcode')}：{data.get('errmsg')}")
        token = data["access_token"]
        expires_in = int(data.get("expires_in") or 7200)
        with self._lock:
            self._token = token
            self._token_expires_at = time.monotonic() + expires_in
        log("gettoken 成功，有效期", expires_in, "秒")
        return token

    def _post_message_once(self, payload):
        token = self.get_access_token()
        resp = requests.post(f"{WECOM_API_BASE}/cgi-bin/message/send",
                             params={"access_token": token}, json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def _post_message(self, payload):
        """POST message/send 一次；token 失效时重取一次再发。返回服务端 JSON。"""
        data = self._post_message_once(payload)
        if data.get("errcode") in self.TOKEN_EXPIRED:
            # token 失效：清缓存重取一次，再发一遍
            log("access_token 疑似过期（errcode=", data.get("errcode"), "），重取后重试一次")
            with self._lock:
                self._token = None
            data = self._post_message_once(payload)
        return data

    def send_text(self, touser, content):
        """发一条文本给指定成员；超 2048 字节自动分多条。返回 (ok, 最后一次 errcode)。"""
        last_errcode = None
        for chunk in split_text_chunks(content):
            data = self._post_message({
                "touser": touser,
                "msgtype": "text",
                "agentid": self.agentid,
                "text": {"content": chunk},
                "safe": 0,
            })
            last_errcode = data.get("errcode")
            if last_errcode != 0:
                log("message/send 失败 errcode=", last_errcode,
                    "errmsg=", data.get("errmsg"))
                return False, last_errcode
        return True, last_errcode

    def send_template_card(self, touser, card):
        """发一张模板卡片给指定成员。返回 (ok, errcode)。"""
        data = self._post_message({
            "touser": touser,
            "msgtype": "template_card",
            "agentid": self.agentid,
            "template_card": card,
        })
        errcode = data.get("errcode")
        if errcode != 0:
            log("template_card 发送失败 errcode=", errcode,
                "errmsg=", data.get("errmsg"))
            return False, errcode
        return True, errcode

    def send_reply_message(self, touser, reply):
        """按回复对象发消息：文本走 send_text，卡片走 send_template_card。"""
        if isinstance(reply, str):  # 兼容旧的纯字符串调用
            return self.send_text(touser, reply)
        if reply.get("kind") == "template_card":
            return self.send_template_card(touser, reply["card"])
        return self.send_text(touser, reply.get("content", ""))

    def create_menu(self):
        """创建自定义菜单（menu/create）。先按官方限制校验 payload，不合规直接报错。

        返回服务端原始 JSON。
        """
        payload = build_menu_payload()
        err = validate_menu_payload(payload)
        if err:
            raise RuntimeError(f"菜单校验不通过：{err}")
        token = self.get_access_token()
        url = f"{WECOM_API_BASE}/cgi-bin/menu/create"
        resp = requests.post(url, params={"access_token": token, "agentid": self.agentid},
                             json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()


_APP_CLIENT = None
_APP_CLIENT_LOCK = threading.Lock()


def get_app_client():
    """单例的发消息客户端（测试可 monkeypatch 本函数）。"""
    global _APP_CLIENT
    if _APP_CLIENT is None:
        with _APP_CLIENT_LOCK:
            if _APP_CLIENT is None:
                _APP_CLIENT = WeComAppClient()
    return _APP_CLIENT


def send_reply(touser, reply):
    """后台线程里把答案发给用户。失败只记日志，绝不抛异常回调用方。"""
    try:
        ok, errcode = get_app_client().send_reply_message(touser, reply)
        if ok:
            kind = reply.get("kind") if isinstance(reply, dict) else "text"
            log("已回复", touser, "（", kind, "）")
        else:
            log("回复失败：", touser, "errcode=", errcode,
                "（60020 = 出口 IP 不在可信 IP 列表，见 README）")
    except Exception:
        log("回复异常：", traceback.format_exc(limit=3))


# ---------------- 后台处理（POST 里只排队，不做慢活） ----------------

def process_text_message(userid, content):
    """处理一条文本消息：白名单 → 路由 → 发回答案。"""
    if not is_owner(userid):
        if not OWNER_USERIDS:
            log(OWNER_EMPTY_HINT, "收到的 userid 是：", userid,
                "请把这个值填进 .env 的 OWNER_USERIDS 后重启容器。")
        else:
            log("非白名单用户，已拒绝：", userid)
        send_reply(userid, text_reply(REFUSAL_TEXT))
        return
    log("收到消息：", userid, "内容=", content[:80])
    try:
        answer = handle_text(content, userid)
    except Exception:
        log("处理消息异常：", traceback.format_exc(limit=3))
        answer = text_reply("抱歉，刚才处理出错了，稍后再试一次。")
    send_reply(userid, answer)


def process_menu_click(userid, event_key):
    """处理一次菜单点击：白名单 → 菜单路由 → 发回答案。"""
    if not is_owner(userid):
        if not OWNER_USERIDS:
            log(OWNER_EMPTY_HINT, "收到的 userid 是：", userid,
                "请把这个值填进 .env 的 OWNER_USERIDS 后重启容器。")
        else:
            log("非白名单用户，已拒绝：", userid)
        send_reply(userid, text_reply(REFUSAL_TEXT))
        return
    try:
        answer = route_menu_click(event_key, userid)
    except Exception:
        log("处理菜单点击异常：", traceback.format_exc(limit=3))
        answer = text_reply("抱歉，刚才处理出错了，稍后再试一次。")
    send_reply(userid, answer)


def process_card_click(userid, event_key):
    """处理一次卡片按钮点击：白名单 → 卡片路由 → 发回答案（新消息，不原地改卡）。"""
    if not is_owner(userid):
        if not OWNER_USERIDS:
            log(OWNER_EMPTY_HINT, "收到的 userid 是：", userid,
                "请把这个值填进 .env 的 OWNER_USERIDS 后重启容器。")
        else:
            log("非白名单用户，已拒绝：", userid)
        send_reply(userid, text_reply(REFUSAL_TEXT))
        return
    log("卡片按钮点击：", event_key, "来自", userid)
    try:
        answer = route_card_click(event_key, userid)
    except Exception:
        log("处理卡片点击异常：", traceback.format_exc(limit=3))
        answer = text_reply("抱歉，刚才处理出错了，稍后再试一次。")
    send_reply(userid, answer)


def process_callback_message(msg):
    """按解析后的消息分发到后台处理。msg 是 parse_inner_message 的结果。"""
    userid = msg.get("from_user", "")
    if msg.get("kind") == "text":
        process_text_message(userid, msg.get("content", ""))
    elif msg.get("kind") == "click":
        process_menu_click(userid, msg.get("event_key", ""))
    elif msg.get("kind") == "card_click":
        process_card_click(userid, msg.get("event_key", ""))
    else:
        log("暂不支持的消息类型：", msg.get("kind"), "来自", userid,
            "（图片/语音/文件等 v2 不处理）")


def dispatch_in_background(msg):
    """把活丢给后台线程，POST 处理立即返回。"""
    t = threading.Thread(target=process_callback_message, args=(msg,), daemon=True)
    t.start()
    return t


# ---------------- 回调服务器（Flask） ----------------

_CRYPTOR = None


def get_cryptor():
    """单例的 WXBizMsgCrypt（测试可 monkeypatch 本函数）。"""
    global _CRYPTOR
    if _CRYPTOR is None:
        _CRYPTOR = WXBizMsgCrypt(WECOM_TOKEN, WECOM_AESKEY, WECOM_CORPID)
    return _CRYPTOR


def create_app():
    app = Flask(__name__)

    @app.before_request
    def _log_every_request():
        # 请求级日志：任何 POST 到回调地址都会先记一行（解密之前）。
        # 用途：点了菜单/卡片却没反应时，看这行在不在——在，说明请求到了桥上，
        # 问题在解密/解析/路由；不在，说明企微服务器根本没把点击发过来。
        # 只记方法/路径/查询参数，不记请求体（密文，记了也没用）。
        log("收到 HTTP 请求：", request.method, request.path,
            "from=", request.remote_addr,
            "args=", {k: request.args.get(k, "")[:24] for k in request.args})

    @app.route("/health", methods=["GET"])
    def health():
        return "ok", 200

    @app.route("/wecom/callback", methods=["GET"])
    def verify_callback():
        """URL 有效性验证：验签 → 解密 echostr → 原样返回明文。"""
        msg_signature = request.args.get("msg_signature", "")
        timestamp = request.args.get("timestamp", "")
        nonce = request.args.get("nonce", "")
        echostr = request.args.get("echostr", "")
        try:
            echo = get_cryptor().verify_url(msg_signature, timestamp, nonce, echostr)
        except ValueError as e:
            log("URL 验证失败：", e)
            return "forbidden", 403
        log("URL 验证通过")
        return echo, 200

    @app.route("/wecom/callback", methods=["POST"])
    def handle_callback():
        """真实消息推送：验签/解密/解析/排重 → 丢后台线程 → 立即回 success。"""
        msg_signature = request.args.get("msg_signature", "")
        timestamp = request.args.get("timestamp", "")
        nonce = request.args.get("nonce", "")
        try:
            inner_xml = get_cryptor().decrypt_msg(
                request.get_data(as_text=True), msg_signature, timestamp, nonce)
            msg = parse_inner_message(inner_xml)
        except ValueError as e:
            log("回调处理失败：", e)
            return "forbidden", 403
        # 排重：文本按 MsgId，菜单点击按（用户，EventKey，时间戳），
        # 卡片按钮点击按（用户，EventKey，TaskId，时间戳）。
        if msg.get("kind") == "text":
            dedup_key = msg.get("msgid") or ""
        elif msg.get("kind") == "click":
            dedup_key = "click:%s:%s:%s" % (
                msg.get("from_user", ""), msg.get("event_key", ""), msg.get("create_time", ""))
        elif msg.get("kind") == "card_click":
            dedup_key = "cardclick:%s:%s:%s:%s" % (
                msg.get("from_user", ""), msg.get("event_key", ""),
                msg.get("task_id", ""), msg.get("create_time", ""))
        else:
            dedup_key = ""
        if dedup_key and DEDUP.is_duplicate(dedup_key):
            log("重复回调，已跳过：", dedup_key)
            return "success", 200
        dispatch_in_background(msg)
        # 关键：5 秒内必须回 success，慢活在后台线程做。
        return "success", 200

    return app


app = create_app()


def check_config():
    """启动前检查必填配置。缺失返回错误提示，否则返回 None。"""
    missing = []
    for name, value in (("WECOM_CORPID", WECOM_CORPID), ("WECOM_SECRET", WECOM_SECRET),
                        ("WECOM_AGENTID", WECOM_AGENTID), ("WECOM_TOKEN", WECOM_TOKEN),
                        ("WECOM_AESKEY", WECOM_AESKEY)):
        if not value:
            missing.append(name)
    if missing:
        return "缺少配置：" + "、".join(missing) + "。请在 NAS 上直接填好 .env 再启动。"
    if len(WECOM_AESKEY) != 43:
        return "WECOM_AESKEY 必须是 43 位字符（管理后台点“随机生成”得到的那个）。"
    return None


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "create-menu":
        err = check_config()
        if err:
            log("启动失败：", err)
            log("Secret 绝不要经过聊天发过来，在 NAS 上直接填 .env。")
            sys.exit(1)
        try:
            result = get_app_client().create_menu()
        except Exception as e:
            log("创建菜单失败：", type(e).__name__, str(e)[:200])
            sys.exit(1)
        log("创建菜单返回：", json.dumps(result, ensure_ascii=False))
        sys.exit(0 if result.get("errcode") == 0 else 1)
    err = check_config()
    if err:
        log("启动失败：", err)
        log("Secret 绝不要经过聊天发过来，在 NAS 上直接填 .env。")
        sys.exit(1)
    log(f"企微自建应用回调桥 v{VERSION} 启动：监听 0.0.0.0:{CALLBACK_PORT}，回调路径 /wecom/callback")
    log("CorpID / AgentId 已配置，Secret / Token / EncodingAESKey 已配置（只记长度，不记值）")
    if OWNER_USERIDS:
        log(f"白名单用户数：{len(OWNER_USERIDS)}")
    else:
        log("警告：OWNER_USERIDS 为空，在填好之前所有消息都会被拒绝。")
        log("首次收到消息时日志会打印对方 userid，把它填进 .env 的 OWNER_USERIDS 后重启。")
    if not LLM_API_KEY:
        log("提示：LLM_API_KEY 未配置，聊天功能不可用，本地查询不受影响。")
    if ESXI_HOST:
        log("ESXi 已配置（", ESXI_HOST, "），ESXi VM、重启 NAS 可用。")
    else:
        log("提示：ESXI_HOST 未配置，ESXi VM、重启 NAS 会回一句“未配置”。")
    if UPDATE_REPO:
        log("自我更新已配置（", UPDATE_REPO, "@", UPDATE_BRANCH, "）。")
    else:
        log("提示：UPDATE_REPO 未配置，菜单“检查更新”会回一句“未配置”。")
    threading.Thread(target=alert_loop, daemon=True).start()
    log(f"主动告警后台循环已启动（每 {ALERT_INTERVAL_SEC} 秒检查一次）")
    threading.Thread(target=image_check_loop, daemon=True).start()
    log(f"容器镜像更新检查后台循环已启动（每 {IMAGE_CHECK_INTERVAL_SEC} 秒检查一次）")
    app.run(host="0.0.0.0", port=CALLBACK_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
