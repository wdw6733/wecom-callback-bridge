#!/usr/bin/env python3
"""企微自建应用回调桥 v2.0。

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
  + button_list（每个按钮 {text, style, key}）+ task_id（每发一次唯一）。
  点按钮后回调推 template_card_event 事件，EventKey 就是按钮的 key，
  TaskId 是发卡片时填的 task_id。v2 收到点击后发一条新消息作答，
  不调 update_template_card 原地改卡。
- 自定义菜单：POST /cgi-bin/menu/create?access_token=..&agentid=..，
  一级最多 3 个按钮，子菜单最多 5 个、只允许一级子菜单。
"""

import base64
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import threading
import time
import traceback
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, request

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - 部署时 requirements.txt 会装好
    AES = None

VERSION = "2.0.0"

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
    "也可以直接聊天提问。"
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

HELP_TEXT = (
    f"你好，我是{BOT_NAME}。\n"
    "本地查询（直接发，或点底部菜单）：\n"
    "· 系统状态\n"
    "· 磁盘空间\n"
    "· 容器列表\n"
    "· 容器日志 <容器名>\n"
    "其他问题直接发给我聊天。\n"
    "重启/停止容器、重启 NAS 这类操作请去 Telegram 3 号机器人确认执行。"
)

# 菜单点击 → 等价的文字指令（走同一套 handle_text 路由）
MENU_KEY_TO_TEXT = {
    "MENU_STATUS": "系统状态",
    "MENU_CONTAINERS": "容器列表",
    "MENU_DISK": "磁盘空间",
    "MENU_HELP": "帮助",
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


def build_menu_payload():
    """自建应用自定义菜单（menu/create 的 body）。

    一级最多 3 个：系统状态 / 容器列表 / 更多（子菜单：磁盘空间、帮助）。
    子菜单只允许一级、最多 5 个。key 与 MENU_KEY_TO_TEXT 对应。
    """
    return {
        "button": [
            {"type": "click", "name": "系统状态", "key": "MENU_STATUS"},
            {"type": "click", "name": "容器列表", "key": "MENU_CONTAINERS"},
            {"name": "更多", "sub_button": [
                {"type": "click", "name": "磁盘空间", "key": "MENU_DISK"},
                {"type": "click", "name": "帮助", "key": "MENU_HELP"},
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


def _new_task_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _make_card(title, rows):
    """button_interaction 卡片：主标题 + 横向 key-value 行（最多 6 行）+ 4 个按钮。"""
    return {
        "card_type": "button_interaction",
        "source": {"desc": BOT_NAME, "desc_color": 0},
        "main_title": {"title": title, "desc": cst_now()},
        "horizontal_content_list": rows[:6],
        "button_list": CARD_BUTTONS,
        "task_id": _new_task_id("nas"),
    }


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
    return _make_card("NAS 状态", rows)


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

    优先级：(a) 只读本地查询 → (b) 破坏性操作回绝 → (c) 帮助 → (d) LLM 聊天。
    状态 / 磁盘 / 温度走模板卡片，容器列表走 markdown 短行，绝不发彩条文本块。
    """
    text = strip_mention(text)
    if not text:
        return text_reply(HELP_TEXT)
    lowered = text.lower().replace(" ", "").replace("　", "")
    try:
        if lowered in ("系统状态", "nas状态", "状态", "status"):
            return card_reply(build_status_card())
        if lowered in ("磁盘空间", "磁盘", "disk"):
            card = build_disk_card()
            if card is None:
                return text_reply("磁盘读不到，请稍后再试，或去 Telegram 3 号机器人查。")
            return card_reply(card)
        if lowered in ("温度", "temp", "temperature"):
            card = build_temp_card()
            if card is None:
                return text_reply(TEMP_UNAVAILABLE_TEXT)
            return card_reply(card)
        if lowered in ("容器列表", "容器", "containers"):
            return text_reply(fmt_containers_markdown())
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
    except Exception as e:
        log("本地查询失败：", type(e).__name__, str(e)[:200])
        return text_reply(f"本地查询失败：{e}。请稍后再试，或去 Telegram 3 号机器人查。")
    if is_destructive(text):
        log("破坏性操作请求已回绝（v2 不执行）：", userid, text[:80])
        return text_reply(DESTRUCTIVE_TEXT)
    if lowered in ("你好", "hi", "hello", "帮助", "help", "你能做什么", "功能", "菜单"):
        return text_reply(HELP_TEXT)
    return text_reply(chat_llm(text))


def route_menu_click(event_key, userid=""):
    """底部菜单点击 → 等价的文字指令 → 同一套路由。未知 key 返回帮助。"""
    text = MENU_KEY_TO_TEXT.get(event_key)
    if text is None:
        log("未知的菜单 EventKey：", event_key, "来自", userid)
        return text_reply(HELP_TEXT)
    log("菜单点击：", event_key, "→", text, "来自", userid)
    return handle_text(text, userid)


def route_card_click(event_key, userid=""):
    """卡片按钮点击 → 对应的卡片 / 文本。未知 key 返回帮助。"""
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
    if event_key == "CARD_MENU":
        return text_reply(HELP_TEXT)
    log("未知的卡片按钮 key：", event_key, "来自", userid)
    return text_reply(HELP_TEXT)


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
        """创建自定义菜单（menu/create）。返回服务端原始 JSON。"""
        token = self.get_access_token()
        url = f"{WECOM_API_BASE}/cgi-bin/menu/create"
        resp = requests.post(url, params={"access_token": token, "agentid": self.agentid},
                             json=build_menu_payload(), timeout=15)
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
    app.run(host="0.0.0.0", port=CALLBACK_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
