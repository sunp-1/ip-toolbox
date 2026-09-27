#!/usr/bin/env python3
"""
IP Toolbox (IP 工具箱) v3.0
═══════════════════════════════
  输入 → 一键处理 → 结果直接展示
  IP 清洗 | 名单匹配 | 去重查重 | 威胁情报

用法:
  python ip_tool.py                     # GUI
  python ip_tool.py -n input.txt        # 排除内网
  python ip_tool.py -r white.txt in.txt # 白名单过滤
  python ip_tool.py --dedup a.txt b.txt # 查重
"""

import argparse
import bisect
import csv
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from urllib.parse import urlparse

try:
    import openpyxl
    HAS_XL = True
except ImportError:
    HAS_XL = False

APP_NAME = "IP Toolbox"
VERSION = "3.0"
USER_AGENT = f"Mozilla/5.0 {APP_NAME}/{VERSION}"

# 域名 (含端口/末尾点) 判定: 用于区分「合法的非IP资产」和「写错的IP」
_DOMAIN_RE = re.compile(
    r'^(?:[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,}\.?$',
    re.ASCII)


# ═══════════════════════════════════════════
#  工具函数
# ═══════════════════════════════════════════

def extract_host(s):
    """从 URL / IP:port / 纯IP 中提取 host (保留CIDR)"""
    s = s.strip()
    if not s or s.startswith('#'):
        return None
    # 剥离 scheme: 不能只列 http/https —— ftp://10.0.0.1/pub 里 host 会被 `ftp:` 顶掉,
    # 于是「行内明明有 IP」的写法在情报查询和诊断里都变了样。任何 `xxx://` 都按 scheme 处理。
    m = re.match(r'^[A-Za-z][A-Za-z0-9+.\-]*://', s)
    had_scheme = bool(m) or s.startswith('//')
    if m:
        s = s[m.end():]
    elif s.startswith('//'):
        s = s[2:]
    # 剥离 query string
    s = s.split('?')[0]
    # 分离 host+port 和 CIDR/路径
    # 格式: [user[:pass]@]host[:port][/(cidr|path)]
    cidr_part = ''
    if '/' in s:
        slash_pos = s.index('/')
        host_part = s[:slash_pos]
        rest = s[slash_pos + 1:]
        # 判断 rest 是否是 CIDR 前缀 (0-32) 或子网掩码
        if rest.isdigit() and 0 <= int(rest) <= 32:
            cidr_part = '/' + rest
        elif rest.count('.') == 3:
            try:
                ipaddress.IPv4Address(rest)
                cidr_part = '/' + rest
            except Exception:
                pass
    else:
        host_part = s
    # URL 里的账号密码 (`https://admin:P@ss@10.0.0.1/`) 不是 host: 留着既查不到情报,
    # 又会把口令带到结果区。只在确实写了 scheme 时才剥 userinfo, 裸邮箱 `a@b.com` 不动。
    if had_scheme and '@' in host_part:
        host_part = host_part.rsplit('@', 1)[1]
    # 去端口 (但保留 IPv6)
    if host_part.count(':') == 1:
        hp, pp = host_part.rsplit(':', 1)
        if pp.isdigit():
            host_part = hp
    return host_part + cidr_part


def is_ip(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except:
        return False


def ip_sort_key(x):
    """
    排序键: 既能排 `1.1.1.1` 也能排 `10.0.0.0/8`。
    名单里两种混着很常见 —— `extract_ips_from_source` 对超过 256 个地址的段就是返回 CIDR
    字符串。以前有按钮直接用 `IPv4Address(x)` 当排序键, 撞上 '10.0.0.0/8' 就抛
    `Unexpected '/'`, Tkinter 回调当场断掉: 界面上不报错, 但那一条也没加进去。
    """
    try:
        s = str(x).strip()
        if '/' in s:
            return ipaddress.IPv4Network(s, strict=False).network_address
        host = extract_host(s)
        if host and is_ip(host):
            return ipaddress.IPv4Address(host)
    except Exception:
        pass
    return ipaddress.IPv4Address('0.0.0.0')


# 「内网」到底包括哪些段 —— 与 README「已知限制」一栏一字不差:
# RFC1918 + 回环 + 链路本地 + 广播/保留 + RFC5737 文档段; `100.64.0.0/10` (CGNAT) 按公网。
# 写成显式清单而不是直接问 Python 的 is_private, 有两个原因:
#   1) 各版本标准库对 `0.0.0.0/8`、`192.88.88.0/24` 这类段的归法不一样 (3.12 里
#      `192.88.88.1.is_private` 是 False), 而「哪些算内网」是用户照着做授权判定的口径,
#      不能随着 Python 版本变;
#   2) 「排除内网」和情报查询的「跳过内网」必须用同一份清单, 否则同一个 IP 在
#      一个按钮里是内网、在另一个里是公网, 省额度的勾选就会把内网资产发出去。
_INTERNAL_BLOCKS = tuple(
    ipaddress.IPv4Network(p) for p in (
        '0.0.0.0/8',            # 本机 / 「这个网络」
        '10.0.0.0/8',
        '127.0.0.0/8',          # 回环
        '169.254.0.0/16',       # 链路本地
        '172.16.0.0/12',
        '192.0.0.0/24',         # IETF 协议分配
        '192.0.2.0/24',         # RFC5737 文档段 (README 已注明会被判内网)
        '192.88.88.0/24',       # 6to4 中继 anycast
        '192.168.0.0/16',
        '198.18.0.0/15',        # 设备互测
        '198.51.100.0/24',
        '203.0.113.0/24',
        '240.0.0.0/4',          # 保留 + 255.255.255.255 广播
    )
)


def is_private(ip_str):
    """单个地址是否属于内网/保留段 (与「排除内网」同一份 _INTERNAL_BLOCKS 清单)"""
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except Exception:
        return False
    return any(ip in b for b in _INTERNAL_BLOCKS)


# ═══════════════════════════════════════════
#  通用输入读取 (txt/csv/xlsx/粘贴)
# ═══════════════════════════════════════════

# 探测顺序: utf-8-sig 必须在 utf-8 之前, 否则 BOM 会留在首行行首变成
# "\ufeff1.1.1.1" 这种脏 token (两者对无 BOM 文件等价)。
TEXT_ENCODINGS = ['utf-8-sig', 'utf-8', 'gbk', 'gb2312', 'latin-1']


def read_text_any_encoding(path, encodings=None):
    """
    按给定编码顺序读文本文件; 全部失败时用 utf-8 + errors='replace' 兜底,
    保证「脏字节」不会让调用方直接崩掉 (返回替换符而不是抛异常)。
    encodings 由调用方传入即可完全自定义; 默认 TEXT_ENCODINGS 沿用历史行为。
    """
    with open(path, 'rb') as f:
        data = f.read()
    # Excel「另存为 Unicode 文本 / CSV Unicode」是带 BOM 的 UTF-16。
    # 必须在按顺序试之前先嗅 BOM: 编码表里 latin-1 永远能解成功, 排后面等于永不生效。
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return data.decode('utf-16', errors='replace')
    if b'\x00' in data[:256]:
        # 无 BOM 的 UTF-16 (有些导出工具直接写 UTF-16LE): 字节流里几乎一半是 \x00。
        # 判据必须够严 (可打印 ASCII 占绝大多数) 才认, 否则中文 GBK 文件会被倒套成乱码。
        for enc in ('utf-16-le', 'utf-16-be'):
            try:
                t = data.decode(enc)
            except (UnicodeDecodeError, UnicodeError):
                continue
            if t and '\x00' not in t:
                printable = sum(1 for ch in t if 32 <= ord(ch) < 127 or ch in '\r\n\t')
                if printable >= len(t) * 0.85:
                    return t
    for enc in (encodings or TEXT_ENCODINGS):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode('utf-8', errors='replace')


# 范围分隔符: 除了半角 `-`, 中文清单里常见 `~`、全角 `～`/`－`、浪引号 `〜` (U+301C,
# 日文输入法打出来的那个, 和 `～` 是同一个意思)、破折号 `—/–`、
# 双减号笔误 `--`、把点写成两连的 `1.1.1.1..29`, 以及中文的「1.1.1.1 到 29」。
# 统一成 `-` 交给同一套范围分支处理, 不另开一条解析路径。
# 空白只允许空格, 不能含换行、也不能含制表符: 换行和 tab 都是「一条名单」的分界
# (read_lines 把 tab 当换行)。写成 `\s` 或 `[ \t]` 会把「1.1.1.1\n- 2.2.2.2」这种逐行带减号
# 的清单并成一条 1.1.1.1-2.2.2.2 (1600 万个 IP) —— 凭空放行整片。
_RANGE_SEP_RE = re.compile(r'(?<=[\d*])[ ]*(?:~|～|〜|－|–|—|到|至|\.{2,}|-{2,}|-(?=[ ]*[\d*]))[ ]*(?=[\d*])')
# 全角数字/句点/斜杠/冒号: 从 Excel、公众号、聊天截图里粘出来的清单全是这种
_FULLWIDTH_MAP = {ord(c): t for c, t in zip('０１２３４５６７８９．／：（）',
                                            '0123456789./:()')}
# 中文句号当点用: 中文输入法下打的 `10。0。0。1` 就是 `10.0.0.1`。
# 只认「四个段全靠句号隔开」这一种整条形状的, 不认 `10.0.0.1。10.0.0.2` 这种句尾标点 ——
# 后者换点会把两条名单粘成一条八段怪物 (识别不了 = 静默少两条)。
_CN_DOT_ADDR_RE = re.compile(r'(?<![\d.。])\d{1,3}(?:。\d{1,3}){3}(?![\d.。])')
# 不可见的排版字符: 网页/公众号/聊天软件复制时会夹带 (零宽空格、零宽连接符、BOM、
# 软连字符、双向控制符…)。它们没有可见含义, 留着只会让「10.0.零宽0.1」变成一条
# 「看不懂为什么识别不了」的写法错误 —— 先在归一化里清掉。
_INVISIBLE_MAP = {ord(c): None for c in
                  '\u200b\u200c\u200d\u2060\ufeff\u00ad'
                  '\u202a\u202b\u202c\u202d\u202e'}
# 各种「看得见的空格」统一到半角空格: 不换行空格(U+00A0, Excel/网页)、全角空格(U+3000,
# 中文清单)、窄/细/各类 Em 空格。原样留着的话, 导出的一行里其实藏着两个 IP,
# 而肉眼和普通脚本都只当它是一个字段。
_SPACE_MAP = {ord(c): ' ' for c in
              '\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005'
              '\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000'}
_FULLWIDTH_MAP.update(_INVISIBLE_MAP)
_FULLWIDTH_MAP.update(_SPACE_MAP)
# C0 控制字符 (NUL、SOH… DEL): 只会来自「把二进制/UTF-16 文件当文本读」这类解码事故,
# 肉眼看不见、复制出来还在。它们**换成空格**而不是删掉 —— 删掉会把 `10.0<NUL>0.1`
# 拼成 `10.00.1` 这种谁都没写过的地址; 换成空格则最多变成两个解析不出的片段,
# 会被未识别检查点名。制表/换行/回车保留: 它们是真正的字段与行分隔。
_CONTROL_MAP = {c: ' ' for c in range(0x20) if c not in (0x09, 0x0a, 0x0d)}
_CONTROL_MAP[0x7f] = ' '
_FULLWIDTH_MAP.update(_CONTROL_MAP)
# 结果区/导出文件专用的「只清杂质」映射: 只处理不可见字符和奇异空白,
# 不做括号剥离/全角标点转换 —— 那两步会改到 URL 的内容, 属于改数据。
_DISPLAY_MAP = dict(_INVISIBLE_MAP)
_DISPLAY_MAP.update(_SPACE_MAP)
_DISPLAY_MAP.update(_CONTROL_MAP)
_ASCII_LETTER_RE = re.compile(r'[A-Za-z]')
# `[1-30]` / `{1..30}` / `（1.1.1.1-30）`: nmap、bash 与中文清单最常见的三种包裹写法,
# 去掉括号后就是普通的末段范围。只删紧贴数字/星号的那一侧, 所以 URL 路径里的 `[id]` 不受影响。
_BRACKET_RE = re.compile(r'(?<!\d)[()\[\]{}](?=[\d\-*])|(?<=[\d\-*])[()\[\]{}](?![\d.])')
# 括号**整段包裹**的多值写法: `10.[3-7].2.1`、`10.{*}.2.3`、`10.10.[83/84/85].0`。
# 上面那条只删「后面不接点」的那一侧括号, 所以中间段带括号时会留下 `10.3-7].2.1`
# 这种半截串 —— 挖出来只剩 `10.3-7` (后两段凭空消失), `10.[*].2.3` 更会被截成 `10.*`
# 再当成「整段」: 256 个地址变成 1677 万个, 那是越界。所以先把「点后面一整对括号」剥掉。
_SEG_BRACKET_RE = re.compile(r'(?<=\.)[\[\{(]([^\[\]{}()\s]{1,24})[\]\})]')
# 混在文字里的网址: `see http://10.0.0.5/1 for detail`、`GET ftp://1.1.1.1/pub x`、
# 协议相对写法 `//cdn.example.com/a.js`。分词时整段摘出来, 免得把 `10.0.0.5/1`
# 单独捞出来当成「IP + 掩码」展开 (斜杠后面那是路径, 不是前缀)。
_URL_IN_TEXT_RE = re.compile(r'(?:[A-Za-z][A-Za-z0-9+.\-]*:)?//[^\s\'"<>，、；|]+')
# 掩码前后的空格: 右边只接「前缀数 (≤2 位)」或「点分掩码」时才算掩码写法
# 空白同样只允许空格/制表符: `\s` 会跨过换行, 把上一行的 IP 和下一行开头的 /24 并起来。
_MASK_SPACE_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t]*/[ \t]*'
                            r'(\d{1,2}(?![\d.])|\d{1,3}(?:\.\d{1,3}){3})')
# 以下三条只给「未识别检查」数段用, 不参与解析:
# 整串只由数字/点/通配符/范围连字符/枚举斜杠组成 (诊断里判定「这是段数问题而非文字」)
_NUMISH_SHAPE_RE = re.compile(r'^[\dxX*][\dxX*./\-]*$')
# 一个段的形状: 单值、范围 (`1-5`)、枚举 (`1/2/3`) 及其与通配符的混合
_SEG_SHAPE_RE = re.compile(r'^[\dxX*]+(?:[-/][\dxX*]+)*$')


def _has_leading_zero(text):
    """`010.1.1.1` / `10.0.0.01` / `10.0.0.01/24` 这种: 点分四段、某段带前导 0 (IPv4 里是八进制歧义写法)"""
    # 掩码尾巴先摘掉: `10.0.0.01/24` 带前导 0 的是第 4 段地址, 不是掩码。
    # 不摘的话这条只能落到「疑似 IP/网段写法有误」, 明明一句「写 10.0.0.1/24」就能说清。
    core = re.split(r'/', str(text).strip(), 1)[0]
    m = re.match(r'^(\d{1,4})(?:\.(\d{1,4})){3}$', core)
    if not m:
        return False
    return any(len(p) > 1 and p[0] == '0' for p in m.groups())
# 010.1.1.1 这种: 每段都允许带前导 0, 用来把「写法有误」说成具体原因
_LEADING_ZERO_RE = re.compile(r'^(?:0+\d{1,3}\.){3}0+\d{1,3}$')


def _is_contiguous_mask(text):
    """`255.255.255.0` 这类点分掩码: 二进制必须是一段连续 1 (255.255.0.255 非法)"""
    try:
        mask_int = int(ipaddress.IPv4Address(text))
    except Exception:
        return False
    inv = (~mask_int) & 0xFFFFFFFF
    return not (inv & (inv + 1))


def _close_mask_space(t):
    """
    只把「完整 IP + 空格 + 掩码」中间的空格去掉: `10.0.0.0 /24` → `10.0.0.0/24`。
    必须限定斜杠右边是前缀数或像掩码的点分串, 否则 `1.1.1.1 / 2.2.2.2` (用斜杠分隔两个 IP)
    会被并成 `1.1.1.1/2.2.2.2` —— 非法掩码 → 整行静默丢掉。
    以 `255.` 开头的非连续串 (255.255.0.255) 仍并: 那明显是写坏的掩码, 要按「写法有误」点名,
    不能让它拆成两个正常 IP 混进名单。
    """
    def repl(mo):
        rhs = mo.group(2)
        if '.' in rhs and not _is_contiguous_mask(rhs) and not rhs.startswith('255.'):
            return mo.group(0)
        return mo.group(1) + '/' + rhs

    return _MASK_SPACE_RE.sub(repl, t)


def _normalize_input_raw(text):
    """
    行级归一 (read_lines / _try_parse_networks / _nets_of_line / is_noise_line 共用同一口径):
      １０.０.０.１／24  → 10.0.0.1/24      全角字符
      192.168.1.[1-30]   → 192.168.1.1-30   nmap/bash 中括号
      （192.168.1.1~30）  → 192.168.1.1-30   中文清单的圆括号包裹
      1.1.1.1~29 / 到/至  → 1.1.1.1-29       范围分隔符
      10.0.0.1 - 10.0.0.5 → 10.0.0.1-10.0.0.5 两侧留空格的减号
      10.0.0.0 /24        → 10.0.0.0/24      掩码前的空格 (从表格/PDF 复制最常见)
      10.0.0.1[NBSP]2.2.2.2 → 10.0.0.1 2.2.2.2  不换行空格/全角空格等 → 半角空格
      10.[零宽]0.1      → 10.0.0.1          零宽字符/BOM/软连字符直接清掉
      10。0。0。1        → 10.0.0.1          中文输入法把点打成句号 (整条都是句号才换)
    只做「同一种意思的不同写法」的归一, 不补全、不放大任何范围;
    所有空白规则只认空格/制表符, 绝不跨换行 (跨行等于把两条名单并成一条巨型范围)。
    """
    t = str(text).translate(_FULLWIDTH_MAP)
    t = _CN_DOT_ADDR_RE.sub(lambda m: m.group(0).replace('。', '.'), t)
    # 括号里外留空格: `10.0.0.[ 1 - 10 ]` 与 `10.0.0.[1-10]` 是同一种意思, 先贴紧再剥括号。
    # 只吃空格/制表符, 不吃换行 (换行是两条名单条目)。
    t = re.sub(r'(?<=[()\[\]{}])[ \t]+|[ \t]+(?=[()\[\]{}])', '', t)
    t = _SEG_BRACKET_RE.sub(lambda m: m.group(1), t)
    t = _BRACKET_RE.sub('', t)
    # 范围两侧的空白只认**空格**, 不认制表符: `1.1.1.1<TAB>-<TAB>2.2.2.2` 里的 tab 是
    # 「一列一条」(read_lines 把它当换行), 归一层若把它当空格吃掉, 诊断层会看到 1684 万个 IP
    # 而名单里只有 2 个 —— 两层口径分裂, 提示语里的数量就成了假数字。
    t = re.sub(r'(?<=[\d*])(?:[ ]+-[ ]*|-[ ]+)(?=[\d*])', '-', t)   # 10.0.0.1 - 10.0.0.5 / 10.0.0.1- 5
    t = _RANGE_SEP_RE.sub('-', t)
    return _close_mask_space(t)


# 一行清单里同一个串会被反复归一/分词/解析: 解析、判定、诊断、输出四层各来一遍,
# 实测每行 197 次 _normalize_input、70 次 _try_parse_networks。2 万行就是几十秒白等,
# GUI 期间整个窗口像死掉。纯字符串 → 纯字符串的三层 (归一/分词/取网段) 全部加缓存。
# 只缓存短串: read_lines 会把整份文件当一个串丢进来, 那种「只用一次」的大串缓存起来
# 只是把内存翻倍, 所以按长度绕开缓存。
_CACHEABLE_LEN = 400


@lru_cache(maxsize=65536)
def _normalize_input_cached(text):
    return _normalize_input_raw(text)


def _normalize_input(text):
    """归一入口: 短串走缓存, 整段文本直接算 (见上面的 _CACHEABLE_LEN 说明)"""
    if type(text) is not str:
        text = str(text)
    if len(text) > _CACHEABLE_LEN:
        return _normalize_input_raw(text)
    return _normalize_input_cached(text)


def _read_source_raw(source, is_text=False, strict=False):
    """
    把「取原始文本」这一步单独抽出来: read_lines 与 read_lines_numbered 共用同一次读取,
    否则为了报对行号就得把文件读第二遍。
    返回未经切分的原始字符串; 读失败且 strict=False 时返回 None (调用方按空列表处理)。

    strict=True 时「读失败」不再退化成空列表。这不是洁癖: 名单被 Excel 独占、xlsx 其实是
    改了后缀的 xls、文件没权限 —— 这几种失败以前都返回 [], 于是 `-r 白名单` 变成
    「保留 0, 移除全部」、`-x 黑名单` 变成「一条都没排除」, 退出码还是 0,
    结果和文件内容完全相反却看起来一切正常。CLI 读名单必须走 strict。
    """
    def _fail(msg):
        if strict:
            raise RuntimeError(msg)
        return None

    if is_text:
        raw = source
    else:
        if not os.path.exists(source):
            return _fail(f'文件不存在 → {source}')
        if not os.path.isfile(source):
            # 传进来的是目录 (Windows 上 open() 抛 PermissionError, Linux 抛 IsADirectoryError):
            # 与「文件不存在」同样处理, 不让一个 traceback 打断整条命令。
            return _fail(f'这是目录不是文件 → {source}')
        ext = os.path.splitext(source)[1].lower()

        if ext == '.xlsx':
            if not HAS_XL:
                raise RuntimeError("需安装 openpyxl: pip install openpyxl")
            try:
                wb = openpyxl.load_workbook(source, read_only=True)
                ws = wb.active
                headers = [str(ws.cell(1, c).value or '') for c in range(1, ws.max_column + 1)]
                url_col = None
                for i, h in enumerate(headers):
                    if h.lower().strip() in ('url', 'ip', 'http_urls', 'host', 'address',
                                             '网址', 'ip地址'):
                        url_col = i + 1
                        break
                if url_col is None:
                    # 表头没认出来 → 首行其实是数据, 和 csv 分支同一口径按 A 列保留。
                    # 以前固定从第 2 行开始读, 一份「没有表头的单列 xlsx」会白丢第一条资产,
                    # 而这条丢失在界面上完全看不见。
                    url_col = 1
                    first_row = 1
                else:
                    first_row = 2
                lines = []
                for r in range(first_row, ws.max_row + 1):
                    v = ws.cell(r, url_col).value
                    if v is not None:
                        lines.append(str(v).strip())
                wb.close()
            except Exception as e:
                # 文件被 Excel 占用 / 损坏的 xlsx (其实是改了后缀的 xls) 都不该崩
                return _fail(f'读不出这个 xlsx ({type(e).__name__}: {e}) '
                             f'→ {source} (文件可能被占用, 或其实是改了后缀的 xls)')
            raw = '\n'.join(lines)

        elif ext == '.csv':
            # 编码必须走 read_text_any_encoding: Excel「另存为 CSV」默认是 GBK/GB2312,
            # 以前这里写死 utf-8-sig → 读一个中文 CSV 直接 UnicodeDecodeError 崩掉。
            try:
                text = read_text_any_encoding(source)
            except OSError as e:
                return _fail(f'读不了 {source} ({type(e).__name__}: '
                             f'{getattr(e, "strerror", None) or e})')
            reader = csv.reader(text.splitlines(True))
            try:
                hdr = next(reader)
            except StopIteration:
                return ''
            url_col = None
            for i, h in enumerate(hdr):
                if h and h.lower().strip() in ('url', 'ip', 'http_urls', 'host', 'address',
                                               '网址', 'ip地址'):
                    url_col = i
                    break
            lines = []
            if url_col is None:
                # 表头没认出来 → 首行其实是数据, 不能吞掉 (无表头单列导出很常见)
                if hdr and hdr[0].strip():
                    lines.append(hdr[0].strip())
            for row in reader:
                if url_col is not None:
                    # 认出列之后只认这一列。以前短行会回落到第 0 列, 于是
                    # `序号,ip` 两列表格里被 Excel 截断/漏填的那一行, 会把序号 1、2、3
                    # 当成资产读进来 —— 一个都不该出现在结果区里。
                    if len(row) > url_col:
                        v = row[url_col].strip()
                        if v:
                            lines.append(v)
                elif row and row[0].strip():
                    lines.append(row[0].strip())
            raw = '\n'.join(lines)

        else:
            try:
                raw = read_text_any_encoding(source)
            except OSError as e:
                # 独占锁 (Excel 打开着的 csv/txt、别的进程正在写) 时 os.access 会说「能读」,
                # 真正 open 才炸 —— 所以这道关必须在这里守, 不能只靠调用前的 access 预检。
                return _fail(f'读不了 {source} ({type(e).__name__}: '
                             f'{getattr(e, "strerror", None) or e})')

    return raw


def _entries_from_raw(raw):
    """原始文本 → 条目列表: 一行里的 `,，、;；|` 与制表符都算「写了几件事」, 拆成几条"""
    # 统一处理: 各种分隔符 → 换行
    raw = raw.replace('\r\n', '\n').replace('\r', '\n')   # 老式 MAC / 部分网络设备只给 \r
    # 制表符是「一列一条」, 和换行同义, 不是空格: `1.1.1.1<TAB>-<TAB>2.2.2.2` 不能拼成范围,
    # 否则 Excel 导出的「IP / 状态 / IP」三列里那个占位用的 `-` 会被读成一条 1684 万个地址的
    # 范围 —— 凭空放行整片, 是最危险的放大方向。归一必须排在这条之后 (归一规则也不跨制表符)。
    raw = raw.replace('\t', '\n')
    raw = raw.replace('、', '\n')
    raw = raw.replace('，', '\n')
    raw = raw.replace(',', '\n')
    raw = raw.replace(';', '\n')
    raw = raw.replace('；', '\n')   # 全角分号: 中文表格里最常见
    raw = raw.replace('|', '\n')
    # 范围的多种写法统一成半角连字符: 1.1.1.1~29 / ～ / － / – / — / .. / 到 / 至 / 1.1.1.1--29
    # 只在「数字 分隔符 数字」之间替换, 不动 URL 里的 `~user` 之类的路径
    raw = _normalize_input(raw)

    return [l.strip() for l in raw.split('\n') if l.strip() and not l.strip().startswith('#')]


def _numbered_from_raw(raw):
    """
    原始文本 → [(物理行号, 这一行的原文)]: 只丢空行与整行注释, **不**按 `,，、;；|`/制表符拆条。
    行号按用户看得见的那一行数: 一行里写三个地址时, 那一行就是「第 N 行」,
    而不是第 N、N+1、N+2 行。
    """
    raw = raw.replace('\r\n', '\n').replace('\r', '\n')
    out = []
    for i, one in enumerate(raw.split('\n'), 1):
        s = one.strip()
        if not s or s.startswith('#'):
            continue
        out.append((i, s))
    return out


def read_lines(source, is_text=False, strict=False):
    """
    统一输入: 文件路径 或 纯文本字符串.
    返回每行文本列表.
    支持: .txt .csv .xlsx  以及中英文逗号分隔
    """
    raw = _read_source_raw(source, is_text, strict)
    if raw is None:
        return []
    return _entries_from_raw(raw)


def read_lines_numbered(source, is_text=False, strict=False):
    """
    同 read_lines 的输入口径, 但返回 [(物理行号, 条目)] —— 一条 = 用户看见的**一整行**。
    为什么要有它: 「未识别检查」报的是「第 N 行」, 那个 N 必须是输入框/文件里真正的那一行。
    以前拿 read_lines 拆出来的条目从 1 起编号, 于是一行写三个地址
    (`8.8.8.8, 256.1.1.1, 9.9.9.9` 后面还有两行) 里的笔误被报成「第 2 行」,
    人翻到第 2 行看到的却是一行没写错的 `1.2.3.4` —— 提示指向错的那一行等于没有提示。
    逐物理行解析与整段解析结果一字不差 (实测 15 个刁串输入: 制表符、BOM/零宽、
    `1.1.1.1~29`、句中 URL、行内注释), 所以换一种编号方式不会改变任何判定。
    `.csv`/`.xlsx` 不走这条路: 那两条分支先按表头选列、再逐行取单元格,
    内容行数与文件里的物理行号本来就不对应 (一行可能有多个单元格、表头行整个跳过),
    硬套物理行号只会报出一个更错的行号 —— 所以退回「按条目从 1 起编号」。
    """
    if not is_text:
        ext = os.path.splitext(str(source))[1].lower()
        if ext in ('.csv', '.xlsx'):
            return list(enumerate(read_lines(source, is_text=is_text, strict=strict), 1))
    raw = _read_source_raw(source, is_text, strict)
    if raw is None:
        return []
    return _numbered_from_raw(raw)


def read_lines_with_numbers(source, is_text=False, strict=False):
    """
    一次读取返回 (条目列表, 与条目等长的物理行号): CLI 既拿条目建名单, 又要在
    「未识别检查」里报行号, 走两次 read_lines 等于把文件读两遍。
    条目仍然出自 `_entries_from_raw(整段原文)`, 和 read_lines 的结果一字不差 ——
    行号只是**贴在条目旁边的标签**, 不能因为换一种编号方式就动了数据本身。
    标签由「这一物理行拆出了几条」逐行展开得到; 万一两条展开路径长度不一致
    (整段归一与逐行归一分歧), 宁可退回旧的按条目下标编号, 也不报一个可能错位的行号。
    `.csv`/`.xlsx` 的物理行号本来就对不上 (见 read_lines_numbered), 直接按下标编号。
    """
    if not is_text:
        ext = os.path.splitext(str(source))[1].lower()
        if ext in ('.csv', '.xlsx'):
            lines = read_lines(source, is_text=is_text, strict=strict)
            return lines, list(range(1, len(lines) + 1))
    raw = _read_source_raw(source, is_text, strict)
    if raw is None:
        return [], []
    lines = _entries_from_raw(raw)
    nums = []
    for i, one in _numbered_from_raw(raw):
        nums.extend([i] * len(_entries_from_raw(one)))
    if len(nums) != len(lines):
        return lines, list(range(1, len(lines) + 1))
    return lines, nums


# ═══════════════════════════════════════════
#  白名单格式解析 (并归 → 扁平IP集合)
# ═══════════════════════════════════════════

def parse_to_ips(text_or_file, is_text=False):
    """展开所有IP (用于查看/编辑). 大量IP时会慢, 推荐用 parse_to_networks."""
    nets = parse_to_networks(text_or_file, is_text)
    ips = set()
    for n in nets:
        if n.num_addresses <= 65536:
            ips.update(str(ip) for ip in n)
        else:
            # 超大的跳过展开, 存CIDR表示
            ips.add(str(n))
    return ips


# 从混杂文本里捞「IP 形状」的片段: 以数字开头, 允许 . - / * x
_IP_LIKE_RE = re.compile(r'(?:^|[^\d])(\d+[\.\d\-\/\*xX]+(?:\.\d+[\.\d\-\/\*xX]*)*)',
                         re.IGNORECASE)

# CIDR 范围一行最多展开出多少个网段 (`10.0.0.0/24-10.1.0.0/24` = 257 个)。
# 超过就不展开、整行不进名单并点名: 一行清单不该有能力把进程挂死。
_CIDR_RANGE_NET_LIMIT = 65536

# 通配/范围叠在一行时, 一行最多展开出多少个组合 (`10.*.*.1-5` = 327680 个)。
# 与上面那条同为「一行不许把进程挂死」的上限, 区别是这里挡住的是逐值组合。
_RANGE_COMBO_LIMIT = 65536

# 两个端点各自带掩码的 CIDR 范围 (`10.1-3.0.0/16-10.5.0.0/16`)。
# 分隔符是「掩码后面那个 -」, 不是第一个 -: 端点自己含范围时第一个 - 在端点内部。
_CIDR_PAIR_RE = re.compile(r'^(.+?/\d{1,2})-(.+?/\d{1,2})$')


def _ip_run_is_hostname(text, start, end):
    """
    `[start, end)` 这段 IP 形状的字符, 是不是只是主机名的一截。
    两种边界: 后面紧跟 `.字母` (`1.1.1.1.example.com`)、前面紧跟 `字母/数字.` (`ns1.10.0.0.1`)。
    不判这个的话, 从文本里挖 IP 会把 `1.1.1.1.example.com` 挖成 1.1.1.1 ——
    一个谁都没写成 IP 的地址凭空进名单, 而它本来就是个域名。
    反过来 `v110.1.1.1`、`内网10.0.0.1` 这种「字母/汉字直接贴着数字」仍是既定口径: 算内嵌 IP。
    """
    tail = text[end:end + 2]
    if len(tail) == 2 and tail[0] == '.' and tail[1].isascii() and tail[1].isalpha():
        return True
    head = text[:start]
    if head.endswith('.'):
        prev = head[-2:-1]
        if prev and prev.isascii() and (prev.isalnum() or prev == '-'):
            return True
    # 五段以上的数字串贴在英文单词后面 (`ns1.10.0.0.1`、`host-10.0.0.0.1`):
    # 这种只能靠「笔误修复」才能变成 IP, 而修复方式有好几种读法 —— 猜哪一种都是越界。
    # 独立的五段写法 (10.230.9.0.24) 仍按既定规则收成 10.230.9.24, 前面没有贴着的单词。
    if head and head[-1].isascii() and (head[-1].isalnum() or head[-1] == '-') \
            and text[start:end].count('.') >= 4:
        return True
    return False


def _mine_ip_like(text):
    """
    行内提取 IP 形状片段。**分词与行内提取必须共用这一个正则**:
    以前 parse_to_networks 用模式捞片段 (会捞到 `10.0.0.0/24`),
    而 _nets_of_line 走 extract_host (只认 host, 行尾一带文字就把 /24 丢掉),
    于是 `10.0.0.0/24 (内网)` 这一行: 名单里进了 256 个 IP, 诊断却写「已按内嵌 IP
    10.0.0.0 识别」—— 多出来的 255 个就是越界。
    """
    out = []
    for m in _IP_LIKE_RE.finditer(str(text)):
        raw = m.group(1)
        # 片段尾部多吃掉的点不是内容 (`1.1.1.1.` 其实是 `1.1.1.1.example.com` 的前缀),
        # 边界判断必须从「真正的最后一个数字」之后往外看。
        match = raw.strip('.-/')
        if not match or not re.search(r'\d', match):
            continue
        start = m.start(1)
        text_s = str(text)
        # 冒号后面顶到片段开头的数字是**端口**, 不是地址的一段。
        # `10.0.0.1:80-10.0.0.5` 里 `80` 前面是冒号, 捞取时它正好成为一个新片段的开头,
        # 于是 `80-10.0.0.5` 被当成「第一段 80-10 的范围」→ 10.0.0.5…80.0.0.5,
        # 凭空多出 70 个谁都没写过的地址, 横跨 70 个 /8 (那是越界, 也是认错地址)。
        # 端口自身是纯数字, 去掉「端口-」这个头之后剩下的部分照常按 IP 解析。
        if text_s[start - 1:start] == ':':
            cut = re.match(r'^\d+-', match)
            if cut:
                match = match[cut.end():]
                start += cut.end()
                if not match or not re.search(r'\d', match):
                    continue
        if _ip_run_is_hostname(text_s, start, start + len(match)):
            continue
        # 片段被字母截断时把尾巴补回来。`_IP_LIKE_RE` 的字符类里没有字母 (`x/X` 是通配符除外),
        # 所以 `1.1.1.1/1abc` 只会捞到 `1.1.1.1/1` —— 掩码 `1abc` 被偷偷换成 `/1`,
        # 一行凭空变成 0.0.0.0/1 (2147483648 个 IP)。补回原文才能让「非法掩码」分支
        # 整条拒掉并说清错在哪。只在「斜杠+数字」后面接字母时补, 不影响域名/主机名判定。
        rest = text_s[start + len(match):]
        if re.search(r'/\d+$', match):
            glued = re.match(r'[A-Za-z][A-Za-z0-9]*', rest)
            if glued:
                match += glued.group(0)
        out.append(match)
    return out


def _tokens_of_line(line):
    """
    单行 → 待解析片段列表。**分词口径的唯一实现**: 建名单 (parse_to_networks)
    与行内判定 (_nets_of_line) 都走这里, 否则同一行会算出两个结果 ——
    名单里进了 10.0.0.0/24, 判定层却只认 10.0.0.0 一个 IP, 多出来的 255 个就是越界。
    这里自己先归一化一次: 归一化规则 (`~`→`-`、括号剥离、`到`→`-`) 直接决定
    「哪里算一个片段」。不归一就分词, `127.168.10.1~29` 会被 `~` 从中间劈成
    `127.168.10.1` + `29` 两段, 只有走 read_lines 的行才不会被劈 —— 同一个写法
    换个入口就是两个结果, 这种顺序依赖本身就是坑。归一化对真实写法是幂等的
    (30000 条随机真实风格行双次归一化零差异)。
    """
    s = line if type(line) is str else str(line)
    if len(s) > _CACHEABLE_LEN:
        return _tokens_of_line_raw(s)
    return list(_tokens_of_line_cached(s))


@lru_cache(maxsize=65536)
def _tokens_of_line_cached(line):
    # 缓存层返回 tuple, 对外仍是新 list: 调用方拿到的是独立副本,
    # 不会有人改了缓存里的东西影响下一行。
    return tuple(_tokens_of_line_raw(line))


def _tokens_of_line_raw(line):
    line = _normalize_input(str(line))
    line = re.sub(r'#.*$', '', line)
    tokens = []
    # 从混合文本中提取 IP-like 片段 (含中文/乱码混杂的情况)
    # 策略: 先按常见分隔符拆, 再从每段中用正则捞 IP 模式
    for p in re.split(r'[,，;；|、\t]+', line):
        p = p.strip()
        if not p:
            continue
        # URL 段整体保留, 交给 _try_parse_networks 的 URL 分支处理
        # (正则提取会把 http://1.2.3.4/x 拆成 1.2.3.4/x 这种坏token)
        # 以前只有「整段以 // 开头」才算 URL, 于是 `see http://10.0.0.5/1 for detail`
        # 这种把 URL 写在句中的行被挖出 `10.0.0.5/1` 当成 CIDR 展开 —— 一条网址
        # 变成 21 亿个地址 (越界), 而行首写同一条网址只算 1 个 IP。
        # 现在无论 URL 写在行的哪个位置, 都先整段摘出来, 剩下的文字再按 IP 模式挖。
        urls = _URL_IN_TEXT_RE.findall(p)
        if urls:
            tokens.extend(urls)
            rest = p
            for u in urls:
                rest = rest.replace(u, ' ', 1)
            p = rest.strip()
            if not p:
                continue
        if re.match(r'^(?:[\w]+:)?//', p, re.IGNORECASE):
            tokens.append(p)
            continue
        # 尝试从混杂文本中提取 IP 模式 (与 _nets_of_line 共用 _mine_ip_like)
        ip_patterns = _mine_ip_like(p)
        if ip_patterns:
            tokens.extend(ip_patterns)
        elif re.search(r'\d', p):
            tokens.append(p)
    return tokens


def parse_to_networks(text_or_file, is_text=False, strict=False):
    """
    通用解析器 — 返回 IPv4Network 列表 (不展开, 高效匹配).
    支持格式: 单IP / 末段范围 / 完整IP范围 / CIDR / CIDR范围 /
             通配符范围 / 单通配符 / 枚举段 / 中间段范围 / 子网掩码
    口径: 手写多值写法一律「按字面量展开」, 绝不补成更大的段 ——
         10.10.83/84/85.0 是 3 个 IP, 不是 3 个 C 段; 要整段请显式写掩码
         (10.10.83/84/85.0/24、10.1-5.0.0/16、10.10.83.* 或 10.10.83.0/24)。
         这类被收窄的写法会在「未识别检查」里点名, 不会静默。
    自动处理混合分隔符和纯文本标签.
    """
    raw_lines = read_lines(text_or_file, is_text, strict=strict)
    networks = []

    for line in raw_lines:
        for token in _tokens_of_line(line):
            networks.extend(_try_parse_networks(token))

    return networks


def _try_parse_networks(token):
    """尝试解析一个 token, 返回 IPv4Network 列表"""
    token = _normalize_input(token.strip())   # 全角字符 / `~` / `到` / 中括号 / 掩码前空格
    if not token:
        return []
    # 同一个 token 在解析/判定/诊断/输出四层里会被重复解析 (实测每行 70 次):
    # 归一之后按串缓存, 结果 tuple 出去再复制成 list, 调用方改不动缓存。
    if len(token) > _CACHEABLE_LEN:
        return _try_parse_networks_raw(token)
    return list(_try_parse_cached(token))


@lru_cache(maxsize=65536)
def _try_parse_cached(token):
    return tuple(_try_parse_networks_raw(token))


def _try_parse_networks_raw(token):
    """真正的解析 (token 已由入口归一化并去空)"""

    # 纯数字/纯文字 → 跳过
    if re.match(r'^[\d]+$', token) or re.match(r'^[^\d.]+$', token):
        return []

    # 常见笔误修复
    token = _fix_common_typos(token)

    # 字面量优先拒绝: 某一段写成 `2024` / `300` / `0x1` 时, 兜底正则的 `\d{1,3}` 会把
    # `1.1.1.2024` 截成 `1.1.1.202` —— 凭空造出一个谁都没写过的「合法 IP」并进名单,
    # 既不越界也不算收窄, 而是**认错地址**。这里整条拒掉, 由「未识别检查」点名第几段。
    if _bad_octet_literal(token):
        return []

    # 同理, 掩码尾部粘着字母 (`/1abc`) 或写成 4 位以上 (`/1234`) 时, 兜底正则的 `/\d{1,2}`
    # 会只取开头那 1 个数字: `1.1.1.1/1abc` 变成 `/1` → 归零成 0.0.0.0/1 (2147483648 个 IP)。
    # 一个手滑的字母把一行放行量放大到半张互联网 —— 这是越界, 也整条拒掉。
    if _bad_mask_literal(token):
        return []

    # `x` 通配符 → `*`
    token_normalized = token.replace('x', '*').replace('X', '*')

    # 五段及以上纯数字 (如 10.10.10.10.10) → 非法 IPv4, 直接拒绝
    # 否则会被后面的兜底正则误当成 10.10.10.10/10 这类超大网段
    if re.match(r'^\d{1,3}(\.\d{1,3}){4,}$', token_normalized):
        return []

    # 以通配符开头的整串 (如 `*.*.*.*`、`x.x.x.x`) → 一律不解析。
    # 分词阶段本来就捞不到这种 token (只捞数字开头的片段), 所以名单里它一条都不进;
    # 若这里还替它展开成 0.0.0.0/0, 就会出现「诊断说没识别、匹配却命中全网」的口径分裂。
    if token_normalized[:1] == '*':
        return []

    # URL → 提取host。`//10.0.0.5/x` 这种「省略 scheme 的协议相对 URL」和 `http://10.0.0.5/x`
    # 是同一个 host，浏览器认、工具也得认；否则同一条资产换个写法就静默不进名单。
    if re.match(r'^(?:[\w]+:)?//', token_normalized):
        host = extract_host(token_normalized)
        # 跟在 host 后面的 `/24` 在 URL 里是**路径**, 不是掩码: 资产是那台 10.0.0.0,
        # 替它扩成 256 个地址就是放大 (多算一个 IP 就等于越界一个 IP)。
        # host 本身照字面量交给同一套解析: `http://10.0.0.1-29/x` 与 `10.0.0.1-29` 同口径。
        if host:
            host = host.split('/')[0]
            sub = _try_parse_networks(host)
            if sub:
                return sub
        return []

    # 连续斜杠 = 掩码写法写坏了 (`10.0.0.1//24`)。只认第一段斜杠之前的地址,
    # 不拿 `24` 去凑一个谁都没写过的 IP: 旧实现在枚举分支里把它拆成
    # 10.0.0.1 + 10.0.0.24 两个 IP —— 多算一个 IP 就是越界一个 IP。
    if '//' in token_normalized:
        head = token_normalized.split('//')[0].rstrip('./')
        return [ipaddress.IPv4Network(head + '/32', strict=False)] if is_ip(head) else []

    # 1. 单IP
    if is_ip(token_normalized):
        return [ipaddress.IPv4Network(token_normalized + '/32', strict=False)]

    # 2. 子网掩码: x.x.x.x/255.x.x.x
    m = re.match(r'^(\d+\.\d+\.\d+\.\d+)/(\d+\.\d+\.\d+\.\d+)$', token_normalized)
    if m:
        try:
            ip_int = int(ipaddress.IPv4Address(m.group(1)))
            mask_int = int(ipaddress.IPv4Address(m.group(2)))
            # 掩码必须是连续1 (255.255.0.255 非法)
            # 不用 int.bit_count(): 该方法是 Python 3.10+, 而本工具声明支持 3.7+,
            # 旧版本会抛 AttributeError 并被 except 吞掉 → 掩码写法静默失效。
            inv = (~mask_int) & 0xFFFFFFFF
            if inv & (inv + 1):
                return []
            prefixlen = bin(mask_int).count('1')
            return [ipaddress.IPv4Network((ip_int, prefixlen), strict=False)]
        except Exception:
            pass

    # 3. 无 - 的 / 格式
    if '/' in token_normalized and '-' not in token_normalized:
        segs = token_normalized.split('.')
        # 3a. 枚举: 10.10.83/84/85/86/87.0 → 5 个 IP (逐字面量, 尾随 .0 不再当成 /24)
        #     要表达 C 段就写掩码: 10.10.83/84/85.0/24 → 3 个 /24
        #     末段本身枚举 (10.10.10.0/1/2) 同样是字面量 3 个 IP, 旧实现会静默丢掉 .1/.2
        enum_before = '/' in segs[0] or '/' in segs[1] or '/' in segs[2]
        if len(segs) == 4 and (enum_before or segs[3].count('/') >= 2):
            mask = None
            if enum_before and '/' in segs[3]:     # 末段自带掩码
                segs[3], mask = segs[3].split('/', 1)
            result = []
            seen = set()
            for i, seg in enumerate(segs):
                if '/' in seg:
                    for v in seg.split('/'):
                        ns = list(segs)
                        ns[i] = v
                        ip_s = '.'.join(ns)
                        if mask:
                            ip_s += '/' + mask
                        try:
                            n = ipaddress.IPv4Network(ip_s, strict=False)
                        except Exception:
                            continue
                        # 同一个值写两遍 (`10.0.0.1/24/24`) 不是两个地址: 名单里出现两次
                        # 就是结果区重复一行, 查重/去重还得再吃一遍。按网络号收一次。
                        key = str(n)
                        if key not in seen:
                            seen.add(key)
                            result.append(n)
                    break
            if result:
                return result

        # 3b. 标准 CIDR
        # 带 `*` 的写法不在这里当场放弃: `10.*.1/2.3` 的斜杠是**枚举分隔符**不是掩码,
        # 下面那句 `return []` 会把「通配段 + 枚举段」这种逐字面量能展开 512 个地址的写法
        # 静默吞成 0 个 —— 而 `10.*.1-5.0` (1280 个) 与 `10.1/2.3.4` 都走通了, 口径不一致。
        # 交给下面的通配分支逐字面量展开; 纯数字写法的非法前缀仍在这里拒绝。
        if '*' not in token_normalized:
            try:
                if '/' in token_normalized:
                    prefix_str = token_normalized.split('/')[1]
                    if not (prefix_str.isdigit() and 0 <= int(prefix_str) <= 32):
                        # 斜杠后面是**路径**而不是写坏的掩码时 (`10.0.0.5/x`、`/download`),
                        # 收 host 那一个地址: `x` 在本工具里同时是通配符, 于是这种写法
                        # 过去被当成非法前缀整条丢掉 —— 行里明明写了一个地址, 名单里一个都没有。
                        # `/24x`、`/1e5`、`/0x18` 仍以数字开头, 属于「掩码写坏了」, 照旧整条拒绝。
                        if re.match(r'^[A-Za-z][A-Za-z0-9+._\-]*$', prefix_str):
                            head = token_normalized.split('/', 1)[0]
                            return [ipaddress.IPv4Network(head, strict=False)]
                        return []
                return [ipaddress.IPv4Network(token_normalized, strict=False)]
            except Exception:
                pass

    # 4. 单通配符 (无 -): 192.168.1.* 或 10.*.*.*
    if '*' in token_normalized and '-' not in token_normalized:
        try:
            segs = token_normalized.split('.')
            while len(segs) < 4:
                segs.append('*')
            # 找通配段要看「段里有没有 *」而不是「整段等不等于 *」: `10.0.0.*/32`、`10.*.1/2.3`
            # 的段写成 `*/32`、`1/2`, 原来那句 `min(... if s == '*')` 直接 ValueError,
            # 整条分支被下面的 except 吞掉 → 明明能逐字面量展开的写法静默变成 0 个 IP。
            star_idx = next((i for i, s in enumerate(segs) if '*' in s), None)
            if star_idx is None:
                return []
            tail_fixed = any(s != '*' for s in segs[star_idx + 1:])
            has_mask = any('/' in s for s in segs)
            if len(segs) == 4 and (tail_fixed or has_mask):
                # 通配符后面还钉着写死的段 (`10.*.2.3`、`10.10.*.1`) → 只能逐字面量展开。
                # 下面那条「填 0 到填 255 拉一条区间」的老路子会把写死的段一起扫过去:
                # 10.0.2.3 … 10.255.2.3 之间还有 10.15.0.0 这类谁都没写过的地址,
                # 字面 256 个变成 1671 万个 —— 多算一个 IP 就等于越界一个 IP。
                # 带掩码的也不能拉平: 那条路会把掩码整段丢掉, `10.*.*.*/32` 拉平成 1 个 /24,
                # 而字面写的 1677 万个 /32 是整张 10/8 —— 少算一片同样是错。
                return _wildcard_to_networks(segs)
            lo = ipaddress.IPv4Address('.'.join(s if s != '*' else '0' for s in segs))
            hi = ipaddress.IPv4Address('.'.join(s if s != '*' else '255' for s in segs))
            return list(ipaddress.summarize_address_range(lo, hi))
        except Exception:
            pass

    # 5. 范围 (含 -)
    if '-' in token_normalized:
        # 5z. 中间段范围: 10.109.233-254.0 / 10.1-5.0.0 / 10-11.0.0.0
        segs = token_normalized.split('.')
        if len(segs) == 4:
            for i in range(3):  # 前3段
                if re.match(r'^(\d+)-(\d+)$', segs[i]):
                    result = _range_to_networks(segs, i)
                    if result:
                        return result

        parts = token_normalized.split('-', 1)
        left, right = parts[0].strip(), parts[1].strip()
        # 端点自己也写成范围的 CIDR 范围 (`10.1-3.0.0/16-10.5.0.0/16`):
        # 第一个 `-` 在左端内部, 上面那样切出来的 left=`10.1` 既不是网段也不是地址,
        # 于是 5c/5d/5e 全部落空, 兜底正则只捞出右端那一个网段 ——
        # 名单里 5 个 /16 静默变成 1 个 /16 (少放行 4 个段, 核对授权的人看不出来)。
        # 掩码后面的那个 `-` 才是两个端点之间的分隔符, 按它重切一次。
        mpair = _CIDR_PAIR_RE.match(token_normalized)
        if mpair:
            left, right = mpair.group(1), mpair.group(2)

        # 5a. 末段数字: 203.0.113.65-126 (允许逆序, 自动交换)
        if right.isdigit():
            try:
                segs = left.split('.')
                if len(segs) == 4:
                    a = ipaddress.IPv4Address(left)
                    b = ipaddress.IPv4Address('.'.join(segs[:3]) + '.' + right)
                    if int(a) > int(b):
                        a, b = b, a
                    return list(ipaddress.summarize_address_range(a, b))
            except Exception:
                pass

        # 5a2. 通配/枚举段 + 末段范围: 10.0.*.1-200 → 256 段 × 200 个 = 51200 个 IP (逐字面量)
        #      旧实现直接落到 5b, 把右端的 `200` 补成 `200.255.255.255`,
        #      于是一行清单悄悄变成 32 亿个地址 —— 多算一个 IP 就等于越界一个 IP。
        if right.isdigit() and ('*' in left) and '/' not in left and len(left.split('.')) == 4:
            segs = left.split('.')
            segs[3] = segs[3] + '-' + right
            result = _range_to_networks(segs, 3)
            if result:
                return result       # 展开量超上限时返回 [], 交给诊断点名而不是放大

        # 5b. 通配符范围: 10.9.0.*-10.9.22.*
        #     两端都必须写满四段才认; 缺段一律不补 (`200`、`*` 单独当右端都会补出天量范围)
        #     并且 `*` 只能成串写在末尾: 中间段的 `*` 一进范围就有两种完全不同的读法
        #     (`10.*.2.3-10.*.5.6`: 拉平 = 16712452 个, 逐段同值 = 197632 个, 差 84 倍),
        #     猜大就是越界 —— 所以这里不解析, 由「未识别检查」把两种量级都算给你看。
        if ('*' in left or '*' in right) and len(left.split('.')) == 4 \
                and len(right.split('.')) == 4 \
                and _star_tail_only(left.split('.')) and _star_tail_only(right.split('.')):
            try:
                def _w(s, hi):
                    segs = s.strip().split('.')
                    while len(segs) < 4:
                        segs.append('*')
                    return ipaddress.IPv4Address('.'.join(
                        '255' if (x == '*' and hi) else ('0' if x == '*' else x) for x in segs))
                a, b = _w(left, False), _w(right, True)
                if int(a) > int(b):
                    a, b = b, a
                return list(ipaddress.summarize_address_range(a, b))
            except Exception:
                pass

        # 5c. CIDR 范围: 10.230.70.0/24-10.230.77.0/24
        #     端点自己也可以是一段范围 (`10.1-3.0.0/16-10.5.0.0/16` = 5 个 /16),
        #     端点展不开时不能只留另一端 —— 那是把左半张名单静默丢掉。
        if '/' in left and '/' in right:
            ended = _cidr_range_ends(left, right)
            if ended:
                a, b, count, _swapped = ended
                if count > _CIDR_RANGE_NET_LIMIT:
                    # 端点写得再随意, 展开量也不能没上限:
                    # `255.255.255.255/32-0.0.0.0/32` 一交换就是 42 亿个 /32,
                    # 名单里这么一行就能把 GUI / CLI 整个挂死 (加这个上限之前真的会挂)。
                    # 整行不进名单, 由「未识别检查」点名请显式写 CIDR。
                    return []
                try:
                    nets = list(ipaddress.summarize_address_range(
                        a.network_address, b.broadcast_address))
                    result = []
                    for n in nets:
                        if n.prefixlen >= a.prefixlen:
                            result.append(n)
                        else:
                            result.extend(n.subnets(new_prefix=a.prefixlen))
                    return result
                except Exception:
                    pass

        # 5d. 完整IP范围: 198.51.100.0-198.51.110.0 → 精确覆盖 lo..hi (含两端)
        #     旧实现对「首尾都是 .0」的写法两端各扩成 /24, 结果比字面范围多出 255 个 IP
        #     (越界), 现在无论怎么收尾都只按写下的 lo/hi 展开。
        if '.' in right and len(right.split('.')) == 4:
            try:
                lo = ipaddress.IPv4Address(left)
                hi = ipaddress.IPv4Address(right)
                if int(lo) > int(hi):
                    lo, hi = hi, lo
                return list(ipaddress.summarize_address_range(lo, hi))
            except Exception:
                pass

        # 5e. 结尾重复段的缩写: 192.168.0.1-0.254 / 192.168.1.1-1.254 / 10.1.1.1-1.1.5
        #     只接受「右侧首段与左侧同位置重复」这一种写法 —— 补出来的高地址全是你写下的数字,
        #     不会像 `1.2.3.4-5.6` 那样被硬拼成 285 个 IP。补不出来的交给诊断点名。
        hi = _range_tail_complete(left, right)
        if hi is not None and int(hi) >= int(ipaddress.IPv4Address(left)):
            return list(ipaddress.summarize_address_range(
                ipaddress.IPv4Address(left), hi))

    # 6. 最后尝试: extract_host
    host = extract_host(token_normalized)
    if host and is_ip(host):
        return [ipaddress.IPv4Network(host + '/32', strict=False)]

    # 7. 从嵌入文字中提取IP (如 ip127.0.0.1, 服务器1.2.3.4, IP:10.0.0.1)
    #    边界必须和 _mine_ip_like 同一套:
    #      - 右边还跟着数字段 (`ns1.10.0.0.1` 里切出来的 1.10.0.0) → 那是五段串, 不是 IP;
    #      - 整串其实是主机名 (`1.1.1.1.example.com`、`1.1.168.192.in-addr.arpa`) → 不是 IP。
    #    少了这两条, 一个谁都没写成 IP 的地址会凭空进名单, 而它本来只是个域名。
    result = []
    for m in re.finditer(
            r'(?<![0-9.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d])'
            r'(?:/(\d{1,2})(?![\d.A-Za-z]))?',
            token_normalized):
        ip_str, prefix = m.group(1), m.group(2)
        if re.match(r'^\.\d', token_normalized[m.end(1):]):
            continue
        if _ip_run_is_hostname(token_normalized, m.start(1), m.end(1)):
            continue
        try:
            if prefix:
                result.append(ipaddress.IPv4Network(f'{ip_str}/{prefix}', strict=False))
            else:
                result.append(ipaddress.IPv4Network(ip_str + '/32', strict=False))
        except Exception:
            pass
    return result


def _range_tail_complete(left, right):
    """
    范围右侧写成「缩写尾巴」时补成完整 IP, 补不出来返回 None。
    只接受带锚点的重复写法: 右侧首段必须等于左侧同位置那一段 ——
      192.168.0.1-0.254   → 192.168.0.254  (锚点 0 == 左侧第三段 0)
      192.168.1.1-1.254   → 192.168.1.254
      10.1.1.1-1.1.5      → 10.1.1.5
    拒绝 1.2.3.4-5.6 这类无锚点写法: 那种只能靠猜, 猜出来的高地址会把范围放大几百倍。
    """
    lsegs, rsegs = left.split('.'), right.split('.')
    if len(lsegs) != 4 or not 1 < len(rsegs) < 4:
        return None
    if not all(s.isdigit() for s in lsegs + rsegs):
        return None
    anchor = 4 - len(rsegs)
    if rsegs[0] != lsegs[anchor]:
        return None
    try:
        return ipaddress.IPv4Address('.'.join(lsegs[:anchor] + rsegs))
    except Exception:
        return None


def _fix_common_typos(token):
    """修复常见笔误"""
    # .10.0.0.1 → 10.0.0.1 (表格里多点了一个句点)
    if token.startswith('.'):
        stripped = token.lstrip('.')
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', stripped):
            return stripped
    # 10.230.9.0.24 → 10.230.9.24 (多打了一个 .0)
    # 旧实现把它修成 10.230.9.0/24 (256 个 IP), 属于「猜大了」: 名单里写错一行就多放行一个 C 段。
    # 现在只按字面收成一个 IP, 并且「未识别检查」会点名这种五段写法, 想表达 C 段请写 10.230.9.0/24。
    m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3})\.0\.(\d{1,3})$', token)
    if m:
        fixed = m.group(1) + '.' + m.group(2)
        try:
            ipaddress.IPv4Address(fixed)
            return fixed
        except Exception:
            pass
    # 10230.17.0/24 → 10.230.17.0/24 (缺第一个点)
    # 只在「开头这一串本身就不是十进制 IP 段 (≥4 位且 >255)」时补点。
    # 少了这道判断, `203.0.113/24` 会被拆成 20.3.0.113 → 20.3.0.0/24:
    # 首段 203 明明合法, 这一行是「少写了一段」而不是「缺点」, 补点等于凭空造出一个
    # 谁都没写过的 C 段 (多算一个 IP 就等于越界一个 IP)。
    m = re.match(r'^(\d{2})(\d{2,})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$', token)
    if m and int(m.group(1) + m.group(2)) > 255:
        return (m.group(1) + '.' + m.group(2) + '.'
                + m.group(3) + '.' + m.group(4) + '/' + m.group(5))
    # 10.230.70.0/24-10.230.77.0/24 没有空格 → 已经是正确的
    return token


_HEXISH_OCTET_RE = re.compile(r'^\d+[xX][0-9a-fA-F]+$')
_PLAIN_OCTET_RE = re.compile(r'^(\d+|\d+[xX][0-9a-fA-F]+)$')


def _bad_octet_literal(token):
    """
    地址形状 token 里「不可能是十进制 IP 段」的第一段 → (第几段, 原文, 类别)，否则 None。
      - `1.1.1.2024` / `1.1.1.300` : 某段超出 0-255 (或写了 4 位以上)
      - `1.1.1.0x1`  / `0x7f.0.0.1`: 某段写成十六进制
    只处理「四段全是数字」的 token: `ip1.1.1.2024`、`1.1.1.2024-26`、`10.10.83/84/85.0`
    这些各有自己的分支, 不能在这里被说成整行未参与匹配。
    """
    core = re.split(r'[:/]', str(token).strip(), maxsplit=1)[0]
    segs = core.split('.')
    if len(segs) != 4 or not all(_PLAIN_OCTET_RE.match(g) for g in segs):
        return None
    for i, g in enumerate(segs, 1):
        if _HEXISH_OCTET_RE.match(g):
            return (i, g, 'hex')
        if len(g) > 3 or int(g) > 255:
            return (i, g, 'range')
    return None


def _bad_octet_reading(body):
    """把 _bad_octet_literal 的结论说成人话 (诊断区与 CLI stderr 共用)"""
    for tok in _tokens_of_line(body):
        core = tok
        if _SCHEME_RE.match(tok) or tok.startswith('//'):
            # URL 里被截出来的 host 才是要核对的对象: `http://1.1.1.2024/x`
            core = (extract_host(tok) or tok).split('/')[0]
        bad = _bad_octet_literal(core)
        if not bad:
            continue
        idx, seg, kind = bad
        # 同行其它写法照样会进名单, 所以只能说「这一段」没参与匹配
        scope = '这一段未参与匹配' if len(_tokens_of_line(body)) > 1 else '整行未参与匹配'
        if kind == 'hex':
            try:
                dec = int(seg, 16)
            except ValueError:
                dec = None
            if dec is not None and dec <= 255:
                return (f'第 {idx} 段 {seg} 是十六进制写法, {scope}; '
                        f'工具不替你换算, 要这个地址请写成十进制 {dec}')
            return (f'第 {idx} 段 {seg} 是十六进制写法, {scope}; IP 段请写成十进制 0-255')
        if len(seg) > 3:
            return (f'第 {idx} 段 {seg} 超出 0-255, {scope}; '
                    f'工具不会把 {seg} 截成 {seg[:3]} 当成一个合法 IP, 请检查笔误')
        return (f'第 {idx} 段 {seg} 超出 0-255, {scope}; '
                f'IP 段只能是 0-255, 请检查笔误')
    return None


def _bad_mask_literal(token):
    """
    「四段 IP + 一个明显不是掩码的斜杠尾巴」→ 返回那段尾巴, 否则 None。
      - `1.1.1.1/1abc`、`1.1.1.1/24x`、`1.1.1.1/1e5`、`1.1.1.1/0x18`: 数字开头却跟着字母
      - `1.1.1.1/-1`: 负数掩码
      兜底正则的 `/(\\d{1,2})` 会**只取开头那几个数字**, 于是 `/1abc` 被当成 `/1`,
      把 `1.1.1.1` 归零成 `0.0.0.0/1` —— 2147483648 个 IP。一个手滑的字母把一行放行量
      放大到半张互联网, 这是越界而不是收窄, 整条拒掉。
    以下形态不在此列, 各自有专门分支: 子网掩码 (`/255.255.255.0`)、枚举 (`/32/24`)、
    范围提示 (`/8-16`)、纯数字但超界 (`/33`, 由 `_bad_prefix_reason` 点名),
    以及斜杠后面是文字/路径的 (`1.2.3.4/nginx`, 走「行内噪声挖 IP」口径)。
    """
    m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/([^/]+)$', str(token).strip())
    if not m:
        return None
    tail = m.group(2)
    if re.match(r'^\d+$', tail):          # 纯数字交给 >32 / 掩码写法分支
        return None
    if re.match(r'^\d+[A-Za-z]', tail) or re.match(r'^[-+]\d', tail):
        return tail
    return None


def _bad_mask_reading(body):
    """把 _bad_mask_literal 的结论说成人话, 并算出「只取开头数字」会放大成多少 IP"""
    for tok in _tokens_of_line(body):
        tail = _bad_mask_literal(tok)
        if not tail:
            continue
        host = tok.split('/')[0]
        lead = re.match(r'\d+', tail)
        worst = ''
        if lead:
            p = int(lead.group(0)[:2])
            if p <= 32:
                try:
                    worst = ('; 工具也不会只取开头的 %s 当成 /%d —— 那会把 %s 归零成 %s (%d 个 IP)'
                             % (lead.group(0), p, host,
                                ipaddress.IPv4Network('%s/%d' % (host, p), strict=False),
                                ipaddress.IPv4Network('%s/%d' % (host, p), strict=False).num_addresses))
                except ValueError:
                    worst = ''
        scope = '这一段未参与匹配' if len(_tokens_of_line(body)) > 1 else '整行未参与匹配'
        return (f'CIDR 前缀 /{tail} 非法(掩码只能是 0-32 的十进制数字), {scope}{worst}, '
                f'要放行单个 IP 请把 /{tail} 删掉')
    return None


def _ambiguous_wildcard_range_reading(body):
    """
    范围两端都有「不在末尾的 `*`」(`10.*.2.3-10.*.5.6`) 时, 这一行裂成两种量级完全不同的读法:
      - 把两端的 `*` 分别填成 0 和 255 再拉平 → `10.0.2.3…10.255.5.6` = 16712452 个 IP
      - 两端的 `*` 当成同一段取同一个值逐段展开 → 只有 197632 个 IP
    差 84 倍, 哪一种都是猜, 而猜大就等于越界。分支 5b 已经不再解析这种写法,
    这里负责把两种量级都算给用户看, 并给出不会歧义的改写。
    """
    for tok in _tokens_of_line(body):
        if '-' not in tok or '*' not in tok:
            continue
        left, _, right = tok.partition('-')
        ls, rs = left.split('.'), right.split('.')
        if len(ls) != 4 or len(rs) != 4:
            continue
        if _star_tail_only(ls) and _star_tail_only(rs):
            continue                      # 末尾通配的范围是另一种口径, 正常解析
        if any(s not in ('*', 'x', 'X') and not s.isdigit() for s in ls + rs):
            continue                      # 段值本身有问题, 由「段值超出 0-255」那条点名
        star_l = {i for i, s in enumerate(ls) if s in ('*', 'x', 'X')}
        star_r = {i for i, s in enumerate(rs) if s in ('*', 'x', 'X')}

        def _flat(segs, fill):
            return '.'.join(fill if s in ('*', 'x', 'X') else s for s in segs)

        try:
            a = int(ipaddress.IPv4Address(_flat(ls, '0')))
            b = int(ipaddress.IPv4Address(_flat(rs, '255')))
        except ValueError:
            continue
        if a > b:
            a, b = b, a
        flat = b - a + 1
        lo_s, hi_s = _flat(ls, '0'), _flat(rs, '255')
        head = f'范围两端的通配符不在末尾 ({tok})'
        per = None
        if star_l == star_r and len(star_l) == 1:
            i = next(iter(star_l))
            per = 0
            for v in range(256):
                l2, r2 = list(ls), list(rs)
                l2[i] = r2[i] = str(v)
                try:
                    x = int(ipaddress.IPv4Address('.'.join(l2)))
                    y = int(ipaddress.IPv4Address('.'.join(r2)))
                except ValueError:
                    per = None
                    break
                per += abs(y - x) + 1
        if per is not None and per == flat:
            return (f'{head}: 两种读法在这里恰好都是 {flat} 个 IP, 但这一行仍然没有解析 —— '
                    f'量级要靠巧合说明写法本身没表达段; 整行未参与匹配, '
                    f'请写成具体范围 ({lo_s}-{hi_s}) 或显式掩码')
        if per is not None and per != flat:
            ratio = max(flat, per) / float(min(flat, per) or 1)
            return (f'{head}: 把两端的 * 分别填成 0 和 255 是 {flat} 个 IP, '
                    f'两端同一个段取同一个值逐段展开是 {per} 个 —— 差 {ratio:.4g} 倍, '
                    f'猜大就是越界; 整行未参与匹配, '
                    f'请改成单写法 ({left} 或 {right}) 或写成具体范围 ({lo_s}-{hi_s})')
        return (f'{head}: 拉平成 {lo_s}-{hi_s} 有 {flat} 个 IP, 但两端的 * 位置不同, '
                f'无法逐段配对, 量级只能靠猜, 猜大就是越界; 整行未参与匹配 —— '
                f'请改成单写法 ({left} 或 {right}) 或写成具体范围 ({lo_s}-{hi_s})')
    return None


def _octet_values(seg, enumerated):
    """
    一个段 → 它能取到的所有十进制值。
    枚举段 (`1-5` / `83/84/85`) 逐值展开, 其余按字面单值, `*`/`x` 是 0-255。
    没写在枚举位上的 `a-b` 一律拒绝 (返回 None), 不猜成大段。
    """
    parts = seg.split('/') if '/' in seg else [seg]
    vals = []
    for p in parts:
        m = re.match(r'^(\d+)-(\d+)$', p)
        if m and (enumerated or len(parts) > 1):
            lo, hi = int(m.group(1)), int(m.group(2))
            lo, hi = (lo, hi) if lo <= hi else (hi, lo)
            if hi > 255:
                return None
            vals.extend(range(lo, hi + 1))
        elif p in ('*', 'x', 'X'):
            vals.extend(range(256))
        else:
            try:
                v = int(p)
            except ValueError:
                return None
            if not 0 <= v <= 255:
                return None
            vals.append(v)
    return vals


def _mask_prefix_len(mask):
    """掩码写法 → 前缀长度。`16`、`/16`、`255.255.0.0` 都认; 认不出来返回 None。"""
    if mask is None:
        return None
    try:
        return ipaddress.IPv4Network('0.0.0.0/%s' % str(mask).lstrip('/'),
                                     strict=False).prefixlen
    except Exception:
        return None


def _range_to_networks(segs, enum_idx):
    """
    把「某一段写成范围/枚举」的四元组展开成 IP 列表 —— 按字面量展开, 不做任何放大:
      10.10.83-85.0     → 10.10.83.0 / 10.10.84.0 / 10.10.85.0   (3 个 IP)
      10.1-5.0.0        → 10.1.0.0 … 10.5.0.0                     (5 个 IP)
      10.109.233-254.0  → 22 个 IP
      10.1-5.0.0/16     → 5 个 /16  (想要大范围必须显式写掩码)
    旧实现把枚举段之后的 0 当通配 (10.1-5.0.0 → 5 个 /16, 32.7 万个 IP,
    还超出字面写的 10.5.0.0), 对「核对授权 scope」是危险的过度包含, 现按字面 IP 展开。
    """
    segs = list(segs)
    mask = None
    if '/' in segs[3]:
        segs[3], mask = segs[3].rsplit('/', 1)
    per_octet = []
    for j, seg in enumerate(segs):
        vals = _octet_values(seg, j == enum_idx)
        if vals is None:
            return []
        per_octet.append(vals)
    # 带掩码时只有前 ceil(前缀/8) 段会留在网络号里, 后面的段全是主机位:
    # 逐值展开必然吐出成堆一模一样的网段 (`10.*.1-200.0/16` 的 51200 个组合其实
    # 只有 256 个 /16), 结果区会被同一行刷屏。主机位取一个代表值就够了。
    prefix = _mask_prefix_len(mask)
    if prefix is not None:
        sig = -(-prefix // 8)
        per_octet = [v[:1] if j >= sig else v for j, v in enumerate(per_octet)]
    total = 1
    for v in per_octet:
        total *= len(v)
    if total > _RANGE_COMBO_LIMIT:  # 通配 + 大范围的组合不展开, 留给后面的分支与提示处理
        return []
    combos = [()]
    for vals in per_octet:
        combos = [c + (v,) for c in combos for v in vals]
    out = []
    seen = set()
    for c in combos:
        ip_s = '.'.join(str(x) for x in c) + ('/' + mask if mask else '')
        try:
            net = ipaddress.IPv4Network(ip_s, strict=False)
        except Exception:
            return []
        # 前缀不是整段边界时 (`/20`) 也会撞出重复网段, 按「同一个网络号只留一份」收
        key = str(net)
        if key in seen:
            continue
        seen.add(key)
        out.append(net)
    return out



def _masked_octet_range_nets(token):
    """
    范围端点自己就是「四段里有一段写成 a-b + 掩码」(`10.1-3.0.0/16`) → 网段列表, 否则 None。
    这种端点 `IPv4Network()` 直接抛异常, 以前 CIDR 范围分支 (5c) 会整条放弃,
    于是兜底正则只捞出右端那一个网段: `10.1-3.0.0/16-10.5.0.0/16` 本意是 5 个 /16,
    结果名单里只有 1 个 —— 左端 3 个 /16 静默消失, 核对授权范围的人会以为名单是对的。
    端点先各自按字面量展开, 再取两端之间 (与 5c 原逻辑同一口径, 不越过写下的端点)。
    """
    segs = str(token).split('.')
    if len(segs) != 4 or '/' not in token:
        return None
    for i in range(3):                   # 末段的 a-b 是另一种写法, 由 5a/5c 原路径管
        if re.match(r'^\d+-\d+$', segs[i]):
            return _range_to_networks(segs, i) or None
    return None


def _cidr_range_ends(left, right):
    """
    CIDR 范围的两个端点 → (低端网段, 高端网段, 按低端掩码展开会有多少个网段); 不是这种写法返回 None。
    端点自己写成「某段是范围 + 掩码」(`10.1-3.0.0/16`) 时先各自展开再取并集区间;
    任一端展不开就返回 None —— 绝不只留另一端 (那等于把名单的另一半静默丢掉)。
    解析分支 5c 与「未识别检查」共用这里, 保证提示里的量级和名单里的量级必然一致。
    """
    def _ends(side):
        try:
            return [ipaddress.IPv4Network(side, strict=False)]
        except Exception:
            return _masked_octet_range_nets(side)
    lo_ends, hi_ends = _ends(left), _ends(right)
    if not lo_ends or not hi_ends:
        return None
    try:
        a = min(lo_ends, key=lambda n: int(n.network_address))
        b = max(hi_ends, key=lambda n: int(n.broadcast_address))
        swapped = int(a.network_address) > int(b.network_address)
        if swapped:
            a, b = b, a
        step = 1 << (32 - a.prefixlen)
        span = int(b.broadcast_address) - int(a.network_address) + 1
        # 向上取整: 一行展开出多少个网段; swapped = 两端写反了 (交换后才覆盖那一大片)
        return a, b, -(-span // step), swapped
    except Exception:
        return None


def _star_tail_only(segs):
    """
    这一行的通配符是不是「只在末尾」: `10.*.*.*`、`10.9.0.*` 是 (`*` 之后全是 `*`);
    `10.*.2.3` 不是 (星号后面还钉着写死的段)。
    单写法时这不是问题 —— `10.*.2.3` 的读法唯一 (256 个); 一旦进**范围**两端就裂成两种读法,
    见 _ambiguous_wildcard_range_reading。
    """
    idx = [i for i, s in enumerate(segs) if str(s).strip() in ('*', 'x', 'X')]
    if not idx:
        return True
    return all(str(segs[i]).strip() in ('*', 'x', 'X') for i in range(idx[0], len(segs)))


def _wildcard_to_networks(segs):
    """
    通配符**不在末尾**时的逐字面量展开 (`10.*.2.3` → 256 个, 不是 1671 万个)。
    与中间段范围同一口径: 只有写 `*` 的那一段在 0-255 之间动, 其余段一字不动,
    也就是 `10.*.2.3` 与 `10.0-255.2.3` 必须给出完全相同的点集。
    掩码照字面写在末尾 (`10.*.2.3/24` → 256 个 /24), 不替用户放大。
    """
    segs = list(segs)
    mask = None
    if '/' in segs[3]:
        segs[3], mask = segs[3].rsplit('/', 1)
    per_octet = []
    for seg in segs:
        vals = _octet_values(seg, True)
        if vals is None:
            return []
        per_octet.append(vals)
    # 掩码落在哪一段之后, 后面那些段就全是主机位 (`10.*.*.0/8` 的两个 `*` 都在主机位)。
    # 以前这里照组合数展开再 collapse: 1677 万个组合先算完再并成一个 /8,
    # 一行 `10.0.*.*/16` 单行 0.36 秒, 而 `10.*.*.*/8` 因为组合数超上限直接返回 0 个 ——
    # 同一个意思写成 /8 就静默不认。与 `_range_to_networks` 同口径: 主机位取一个代表值,
    # 展开出来的**地址集合**与逐组合展开后 collapse 完全一致, 只是不再空转。
    prefix = _mask_prefix_len(mask)
    if prefix is not None:
        sig = -(-prefix // 8)
        per_octet = [v[:1] if j >= sig else v for j, v in enumerate(per_octet)]
    total = 1
    for v in per_octet:
        total *= len(v)
    if total > _RANGE_COMBO_LIMIT:  # 与 _range_to_networks 同上限: 超了就不展开, 交给诊断点名
        return []
    combos = [()]
    for vals in per_octet:
        combos = [c + (v,) for c in combos for v in vals]
    pts = []
    for c in combos:
        ip_s = '.'.join(str(x) for x in c) + ('/' + mask if mask else '')
        try:
            pts.append(ipaddress.IPv4Network(ip_s, strict=False))
        except Exception:
            return []
    return list(ipaddress.collapse_addresses(pts))


def ip_in_networks(ip, networks):
    """检查IP是否在network列表中"""
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return any(ip_obj in n for n in networks)
    except Exception:
        return False


def _ip_intervals(nets):
    """
    把一组网段并成「互不相交、也不相邻」的整数区间 [(lo, hi), ...] (按 lo 升序)。

    点集与 ipaddress.collapse_addresses 完全一致, 但只做排序 + 一次线性扫描:
    collapse_addresses 要为每个结果段再构造一个 IPv4Network 对象, 实测 2 万个段
    要 0.30 秒, 而这里 0.02～0.05 秒。结果区每次操作都要算一遍「覆盖多少个 IP」,
    半秒花在统计上不值。相邻区间也一并 (lo == 前段 hi+1), 这样条数最少,
    正好给 _NetIndex 做二分用。
    """
    spans = []
    for n in nets:
        lo = int(n.network_address)
        spans.append((lo, lo + getattr(n, 'num_addresses', 1) - 1))
    spans.sort()
    out = []
    for lo, hi in spans:
        if out and lo <= out[-1][1] + 1:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return out


class _NetIndex:
    """
    名单段索引: 先把段并成不相交区间 (_ip_intervals 保持点集不变, 只是相邻段合并),
    再用二分查找回答「[lo,hi] 是否与任一区间相交」→ O(log M) 取代逐段线性比较。
    相交 ⟺ 区间起点 ≤ lo 的那一段覆盖到 lo, 或起点落在 (lo,hi] 里的第一段。
    """
    __slots__ = ('starts', 'ends')

    def __init__(self, networks):
        # 容忍传入字符串写法 (如直接从文件拿的段), 统一转成 IPv4Network 再并区间
        nets = []
        for x in networks:
            if isinstance(x, ipaddress.IPv4Network):
                nets.append(x)
            else:
                nets.extend(n for n in _try_parse_networks(str(x).strip())
                            if isinstance(n, ipaddress.IPv4Network))
        merged = _ip_intervals(nets)
        self.starts = [lo for lo, _hi in merged]
        self.ends = [hi for _lo, hi in merged]

    def overlaps_any(self, lo, hi):
        i = bisect.bisect_right(self.starts, lo) - 1
        if i >= 0 and self.ends[i] >= lo:
            return True
        k = i + 1
        return k < len(self.starts) and self.starts[k] <= hi

    def __len__(self):
        return len(self.starts)


def _nets_of_line(line):
    """
    行 → 网段列表。**与建名单走同一条流水线** (read_lines 归一 + _tokens_of_line 分词),
    这样「判定层看到的行」和「名单里装的内容」永远一致。
    以前这里走 extract_host, 它只认 host: `10.0.0.0/24 (内网)` 名单里有 256 个 IP,
    行内却只算 10.0.0.0 一个 —— 差出来的 255 个就是没人认领的越界。
    """
    s = line if type(line) is str else str(line)
    if len(s) > _CACHEABLE_LEN:
        return _nets_of_line_raw(s)
    return list(_nets_of_line_cached(s))


@lru_cache(maxsize=65536)
def _nets_of_line_cached(line):
    # 缓存里存 tuple, 对外给新 list; IPv4Network 本身不可变, 共享实例是安全的。
    return tuple(_nets_of_line_raw(line))


def _nets_of_line_raw(line):
    nets = []
    for one in read_lines(line, is_text=True):
        for token in _tokens_of_line(one):
            nets.extend(_try_parse_networks(token))
    return nets


def _is_clean_ip_line(body):
    """
    整行只由 IP/网段/分隔符组成, 或是带协议头的 URL、合法域名 —— 不需要「从文字里挖 IP」。
    三条反例都是这一轮补的, 因为它们让「同一句话两种结论」:
      1) `xxxxx 10.0.0.5` —— `_CLEAN_LINE_RE` 的字符表里有 x/X (为了认 `10.10.83.x`),
         于是整串垃圾 x 被当成通配段、整行算干净行原样输出; 换成 `备注 10.0.0.5`
         却只输出 IP。x 只有**单独占一段**才是通配符。
      2) `file:///C:/.../10.0.0.5/x` —— 本地路径不是资产, 把目录结构原样抄进结果区
         等于把这台机器的路径交给下一个拿导出文件的人。
      3) `/var/log/10.0.0.5.log` 这类两段以上的斜杠路径, 同上。
    """
    b = _normalize_input(body)               # `1.1.1.1~29` 是正常范围, 不算噪声行
    if _PATH_SCHEME_RE.match(b) or _WIN_PATH_RE.match(b) or _UNC_PATH_RE.match(b):
        return False
    if (not _SCHEME_RE.match(b) and not b.startswith('//') and _DIR_PATH_RE.match(b)):
        return False
    # 一行写了几件「各自本来就是地址/域名」的事 (`10.0.0.5 http://a.example.com`):
    # 以前只看行首那一个 token —— 同一个写法把域名写在前面算干净行、写在后面就成了噪声行,
    # 换个顺序就换一种输出、结果区行数也跟着变。逐 token 判, 顺序就无所谓了。
    parts = b.split()
    if len(parts) > 1 and all(_is_clean_ip_line(p) for p in parts):
        return True
    if _SCHEME_RE.match(b) or _DOMAIN_RE.match(b):
        return True
    if not _CLEAN_LINE_RE.match(b):
        return False
    if not re.search(r'\d', b):
        # 一个数字都没有的串不是地址: `xxxxx` 是垃圾文字, 不是通配段。
        # 通配符只有在 `10.10.83.x` 这种「有地址形状」的串里才成立 ——
        # 逐 token 判干净行时, 少了这条守卫, `xxxxx 10.0.0.5` 会被整体放行成干净行。
        return False
    # 把合法的通配段 (`x` 单独一段) 摘掉后, 行里不该再有 x/X —— 有就是垃圾文字
    return not re.search(r'[xX]', _WILD_SEG_RE.sub('', b))


def _is_path_line(line):
    """
    整行是本地路径 / 共享目录 / `file://` 地址 —— 它指向这台机器的磁盘, 不是网络资产。
    判据必须与 `_is_clean_ip_line` 里那三条路径分支一字不差: 那是「这一行不是地址」唯一的
    判据来源, 两处各写一套就会分裂 —— 判定层说它是路径、输出层把它当干净行原样抄进结果区,
    于是 `C:\\logs\\10.0.0.5.txt` 连同目录结构一起被导出, 本机环境信息泄露给下一个拿文件的人
    (README 承诺的正是「结果区只出现资产, 不出现本机路径」)。
    唯一要往外拨的是「域名带路径」(`example.com/a/b/c`): `_DIR_PATH_RE` 也认它, 但那行的
    主体是域名 —— 域名是资产, 按路径处理会让用户写下的一条资产在结果区里凭空消失。
    """
    s0 = str(line)
    if '/' not in s0 and '\\' not in s0 and ':' not in s0:
        return False            # 快速出口: 路径写法至少带一个斜杠或盘符冒号, 纯 IP 行不必多归一一次
    b = _normalize_input(s0)
    if _PATH_SCHEME_RE.match(b) or _WIN_PATH_RE.match(b) or _UNC_PATH_RE.match(b):
        return True
    if not _SCHEME_RE.match(b) and not b.startswith('//') and _DIR_PATH_RE.match(b):
        return not _DOMAIN_RE.match(b.lstrip('/').split('/')[0])
    return False


def is_noise_line(line, nets=None):
    """
    「从一串乱码里挖出了 IP」的行, 如 sadhsajgd127.0.0.1、v110.1.1.1。
    这类行的 IP 是猜出来的: 复制时串行、正则没切干净、日志粘连都会造出这种串。
    拿它去做名单判定, 等于让一条脏数据伪装成干净 IP 混进结果, 所以不参与匹配。
    `nets` 是调用方已经解析过的结果 (判定层每行本来就要解析一次):
    传进来就复用, 不为同一个字符串再跑一遍分词 —— 2 万行名单匹配本来贴着 2 秒预算。
    """
    body = _normalize_input(re.sub(r'#.*$', '', str(line)).strip())
    if not body or _is_clean_ip_line(body):
        return False
    if nets is not None:
        return bool(nets)
    return bool(_nets_of_line(body))


def split_noise_lines(lines):
    """把噪声行摘出来: 返回 (可原样输出的行, 噪声行)"""
    clean, noise = [], []
    for line in lines:
        (noise if is_noise_line(line) else clean).append(line)
    return clean, noise


def _display_line(line, nets=None):
    """
    干净行写进结果区/导出文件时的写法: 只去杂质, 不改数据。
      1) 删掉不可见字符 (零宽、BOM、软连字符、双向控制符), Unicode 空白折成一个普通空格 ——
         从网页/聊天工具复制来的 `10.0.0.1[NBSP]2.2.2.2` 导出后不该带着那个怪字符;
      2) 纯 IP 写法里的全角标点 (`１０．０．０．１`、`10.0.0.1：8080`) 归一成半角,
         否则导出的是别的工具读不了的假数据。
    两条护栏: 行里有英文字母 (URL/域名/路径) 时不做第 2 步 —— `_normalize_input` 会吃掉
    括号等内容, 那是改数据不是清杂质; 且归一前后解析出的地址集合必须一字不差。
    """
    s = str(line).translate(_DISPLAY_MAP)
    # 账号口令先剥掉: `https://admin:P@ssw0rd@10.0.0.5/` 里资产是那个 host,
    # 口令既不是资产也不能进结果区/导出文件 (名单存储走的也是这条)。
    s = _URL_USERINFO_RE.sub(lambda m: m.group(1), s)
    if nets is None:
        nets = _nets_of_line(s)
    if not nets or _ASCII_LETTER_RE.search(s):
        return s
    cand = _normalize_input(s)
    if cand == s:
        return s                      # 归一化没动这一行, 不必再解析一遍来验证「集合相同」
    if cand and '\n' not in cand and _nets_of_line(cand) == nets:
        return cand
    return s


def _line_forms_and_nets(line, nets=None):
    """
    一行 → [(输出条目, 这一条目对应的网段)]。判定与输出必须说同一件事。

    旧实现在这里下了「整行一个结论」: `aaa10.0.0.1 8.8.8.8` 只要行里有一个地址在名单里,
    行里**所有**地址都被报成「在白名单中」—— 8.8.8.8 明明谁都没授权, 却在结果区里
    顶着"已授权"的身份出现, 拿去开防火墙就是凭空放行; 而同一份数据走 CLI
    (先 normalize_lines 再判定) 给出的却是相反结论。GUI 与 CLI 必须同一条口径。

    拆不拆按「这一行写了几件事」定, 与存进名单时 (`_clean_ip_text`) 同一条规则:
      一行一件事 (`10.0.0.0/24`、`10.10.83/84/85.0`、`1.1.1.1-1.1.1.5`) → 保持你自己的写法,
        整行按「与名单有交集」判定 (README 承诺的口径);
      一行写了几件事 (`10.0.0.1 8.8.8.8`) 或整行夹着文字 → 逐条拆开, 逐条判定、逐条输出。
    路径行 (`C:\\logs\\10.0.0.5.txt`、`/var/log/x.log`、`file://...`) 走「只输出内嵌 IP」那条:
    目录结构不是资产, 原样抄进结果区等于把这台机器的环境交给下一个拿导出文件的人;
    行内一个地址都没写出时输出**空列表** —— 造一行「资产」等于把这一行的 0 个 IP 变成 1 个。
    这一行不会静默消失: 「未识别检查」里 `_path_line_reading` 会说清它为什么没收。
    `nets` 由调用方传入 (名单匹配每行本来就要解析一次), 同一行不重复解析三遍。
    """
    if nets is None:
        nets = _nets_of_line(line)
    groups, order = {}, []
    for n in nets:
        t = format_network(n)
        if t not in groups:
            groups[t] = []
            order.append(t)
        groups[t].append(n)
    if _is_path_line(line):
        return [(t, groups[t]) for t in order]
    noise = bool(nets) and is_noise_line(line, nets=nets)
    if len(order) > 1 and (noise or len(_tokens_of_line(line)) > 1):
        return [(t, groups[t]) for t in order]
    if noise and order:
        return [(t, groups[t]) for t in order]
    return [(_display_line(line, nets), list(nets))]


def _line_display_forms(line, nets=None):
    """
    一行 → 应该出现在结果区里的形式 (见 _line_forms_and_nets)。
    干净行 (IP / 网段 / URL / 域名) 输出「同一份数据」的干净写法, URL 与域名信息不丢;
    噪声行 (整行夹着无关文字, 如 `node "x.mjs" --port 19016 127.0.0.1`) 只输出挖出的 IP。
    理由: 结果区要复制/导出成资产清单, 把整条命令行、本地路径抄进去既没用也泄露环境信息,
    和「提取IP」按钮的口径也不一致。
    """
    return [f for f, _ in _line_forms_and_nets(line, nets)]


def normalize_lines(lines):
    """结果区统一出口: 噪声行归一为内嵌 IP, 其余原样保留"""
    out = []
    for line in lines:
        out.extend(_line_display_forms(line))
    return out


def check_overlap(lines, networks):
    """
    检查输入行中有多少IP在networks中 (支持 单IP/CIDR/范围/枚举).
    判据: 行对应的网段与名单有交集即算"在" (如 0.0.0.0/16 在 0.0.0.0/16 名单中).
    域名/无法解析 → 视为不在.
    噪声行按内嵌 IP 参与判定, 但输出的是那个 IP 而不是原始脏行 (见 _line_display_forms)。
    一行写了几个独立地址时**逐条判定** (见 _line_forms_and_nets): 命中与否跟着条目走,
    不再让行里那一个在名单里的地址把其余地址一起报成"已授权"。
    """
    idx = _NetIndex(networks)
    in_set, not_in = [], []
    for line in lines:
        # 同一行的解析结果直接交给输出清洗, 不再为这一行重复分词第二遍
        for form, ns in _line_forms_and_nets(line):
            hit = False
            for a in ns:
                lo = int(a.network_address)
                if idx.overlaps_any(lo, int(a.broadcast_address)):
                    hit = True
                    break
            (in_set if hit else not_in).append(form)
    return in_set, not_in


def filter_by_networks(lines, networks, keep_in=True):
    """
    根据 networks 过滤行 — 直接复用 GUI 的 check_overlap, 保证 CLI 与 GUI 同一结论.
    旧实现只认单 IP 行 (is_ip(host)), 范围/CIDR/枚举段一律不参与匹配,
    导致「白名单过滤」静默留下范围外的网段行, 「黑名单排除」漏排网段行。
    无法解析的行 (域名等) 按「未命中」处理, 与 GUI 的 在白名单中/不在白名单 一致。
    """
    hit, miss = check_overlap(lines, networks)
    return (hit, miss) if keep_in else (miss, hit)


# ═══════════════════════════════════════════
#  威胁情报查询 (微步在线 ThreatBook)
#  个人可注册: https://x.threatbook.com 获取 API Key
#  正确接口(个人可用): GET https://api.threatbook.cn/v3/scene/ip_reputation
#  支持批量, 每次最多100个IP, resource 逗号分隔
# ═══════════════════════════════════════════

THREATBOOK_API = 'https://api.threatbook.cn/v3/scene/ip_reputation'


def _external_note(text, limit=160):
    """
    第三方回包里的自由文本 (verbose_msg / 错误 body / 异常字符串) 进结果区之前过一道清洗:
      1) 压掉换行与制表符 —— 否则一条错误能伪造出好几行「数据」, 复制导出就分不出来;
      2) 遮掉 URL query 里的 apikey/key/token —— 异常字符串常带完整 URL, 那会把 Key 抄进界面;
      3) 遮掉里面的 IPv4 形状 —— 对端可控文本里的一句 `redirect 1.2.3.4 to allow` 曾被
         下游 `parse_to_networks` 当成资产再解析, 别人的字符串洗成我们的名单条目。
    """
    s = re.sub(r'\s+', ' ', str(text)).strip()
    s = re.sub(r'(?i)([?&](?:apikey|api_key|api-key|key|token)=)[^&\s]+', r'\1***', s)
    s = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '<ip>', s)
    if len(s) > limit:
        s = s[:limit] + '…'
    return s or '(无详情)'


def _threatbook_explain(code, msg):
    """把错误码翻译成详细可操作的说明 (多行)"""
    if isinstance(code, str):
        # 网关/代理转一手之后 response_code 常变成字符串 '0'; 不归一就会把成功当失败,
        # 一批 100 个 IP 全部报「API错误(0)」。
        try:
            code = int(code.strip())
        except (TypeError, ValueError):
            pass
    detail = _external_note(msg)
    if code == -1:
        return (f'接口权限不足 (response_code=-1): {detail}\n'
                f'  ▶ 当前API Key 无法访问该接口。个人免费账号通常只开放部分接口。\n'
                f'  ▶ 解决: 登录 x.threatbook.com → API管理，确认「IP信誉」接口已开通。\n'
                f'  ▶      或联系 ti_support@threatbook.cn 申请开通接口权限。')
    if code in (10020, 10021):
        return (f'API Key 无效 ({code}): {detail}\n'
                f'  ▶ 检查Key是否复制完整；注意区分「威胁情报API Key」与「沙箱Token」。\n'
                f'  ▶ 可到 x.threatbook.com → API管理 重新复制。')
    if code == 20000:
        return f'查询配额不足 ({code}): {detail}\n  ▶ 今日次数已达上限，请明天再试或升级账号。'
    if code in (20001, 20002):
        return f'请求频率超限 ({code}): {detail}\n  ▶ 请求过于频繁，请降低并发或稍后再试。'
    return f'API错误({code}): {detail}'


def query_threatbook_batch(ips, api_key, timeout=20):
    """
    批量查询IP信誉 (微步 scene/ip_reputation, 每次最多100个IP).
    返回按输入顺序排列的 [(ip, info_dict_or_None, error_str_or_None)] 列表.
    """
    results = []
    if not ips:
        return results
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        try:
            params = urllib.parse.urlencode(
                {'apikey': api_key, 'resource': ','.join(batch), 'lang': 'zh'})
            url = f'{THREATBOOK_API}?{params}'
            req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode('utf-8', errors='replace'))

            code = data.get('response_code')
            if isinstance(code, str):
                try:
                    code = int(code.strip())
                except (TypeError, ValueError):
                    pass
            if code != 0:
                err = _threatbook_explain(code, data.get('verbose_msg') or '')
                for ip in batch:
                    results.append((ip, None, err))
                continue

            batch_data = data.get('data') or {}
            for ip in batch:
                if ip in batch_data and isinstance(batch_data[ip], dict):
                    results.append((ip, batch_data[ip], None))
                else:
                    results.append((ip, None, '无该IP的情报数据'))
        except Exception as e:
            # 异常字符串可能带完整 URL (含 apikey) 或对端回包原文, 一律清洗后再进结果区
            err = f'请求失败: {_external_note(e)}'
            for ip in batch:
                results.append((ip, None, err))
    return results


# ═══════════════════════════════════════════
#  威胁情报查询 (AbuseIPDB) — 个人免费 1000次/天
#  注册: https://www.abuseipdb.com → API → 创建 key
#  接口: GET https://api.abuseipdb.com/api/v2/check (Header: Key)
# ═══════════════════════════════════════════

ABUSEIPDB_API = 'https://api.abuseipdb.com/api/v2/check'


def query_abuseipdb_ip(ip, api_key, timeout=20):
    """查询单个IP的滥用信誉. 返回: (ip, info_dict_or_None, error_str_or_None)"""
    try:
        params = urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''})
        url = f'{ABUSEIPDB_API}?{params}'
        req = urllib.request.Request(url, headers={
            'User-Agent': USER_AGENT,
            'Key': api_key,
            'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8', errors='replace'))
        d = data.get('data') or {}
        return (ip, d, None)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8', errors='replace')
        except Exception:
            body = ''
        hint = ''
        if e.code == 401:
            hint = ' (API Key 无效)'
        elif e.code == 429:
            hint = ' (触发频率限制)'
        # body 是对端原文: 清洗前它能把 `redirect 1.2.3.4 to allow-list` 写成一整行
        # 「数据」进结果区, 复制/导出即落盘, 再喂回解析层就变成一条凭空多出来的名单。
        return (ip, None, f'HTTP {e.code}{hint}: {_external_note(body)}')
    except Exception as e:
        return (ip, None, f'请求失败: {_external_note(e)}')


def build_abuseipdb_detail(info):
    """
    生成 AbuseIPDB 详细展示.
    返回: (verdict, lines)  verdict: 'clean' / 'suspicious' / 'malicious'
    """
    try:
        score = int(info.get('abuseConfidenceScore') or 0)
    except Exception:
        score = 0
    if score <= 0:
        verdict, level = 'clean', '良好'
    elif score < 25:
        verdict, level = 'suspicious', '低风险'
    elif score < 50:
        verdict, level = 'suspicious', '中风险'
    elif score < 75:
        verdict, level = 'malicious', '高风险'
    else:
        verdict, level = 'malicious', '严重恶意'

    total_reports = info.get('totalReports') or 0
    country = info.get('countryCode') or ''
    isp = info.get('isp') or ''
    domain = info.get('domain') or ''
    usage = info.get('usageType') or ''
    hostnames = info.get('hostnames') or []
    last = info.get('lastReportedAt') or ''
    whitelisted = info.get('isWhitelisted')

    lines = []
    lines.append(f'  恶意置信度: {score}/100 ({level})')
    lines.append(f'  举报次数  : {total_reports}')
    if usage:
        lines.append(f'  用途类型  : {usage}')
    if isp:
        lines.append(f'  ISP     : {isp} {("(" + domain + ")") if domain else ""}'.rstrip())
    if country:
        lines.append(f'  国家     : {country}')
    if hostnames:
        lines.append(f'  主机名   : {", ".join(str(x) for x in hostnames[:5])}')
    if last:
        lines.append(f'  最近举报  : {last}')
    if whitelisted is not None:
        lines.append(f'  服务商白名单: {"是" if whitelisted else "否"}')
    return verdict, lines


# ═══════════════════════════════════════════
#  批量查询分发
# ═══════════════════════════════════════════

def query_batch(ips, api_key, source='threatbook', max_workers=5):
    """批量查询. 返回按输入顺序排列的结果 [(ip, info, error)]"""
    results = []
    if not ips:
        return results
    if source == 'abuseipdb':
        # 逐IP并发查询
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(query_abuseipdb_ip, ip, api_key): ip for ip in ips}
            for fut in as_completed(futures):
                results.append(fut.result())
        order = {ip: i for i, ip in enumerate(ips)}
        results.sort(key=lambda r: order.get(r[0], 0))
        return results
    # 微步: 使用批量接口 (一次最多100个IP)
    return query_threatbook_batch(ips, api_key)


# 微步威胁类型关键词 (与"威胁类型全集"对应, 用于判定恶意)
# 注意: 信誉接口的 judgments 包含 白名单/CDN服务器/网关 等良性标签, 不能全部视为恶意
# 权威判定字段是 is_malicious (布尔值)


def _malicious_flag(value):
    """
    把 is_malicious 归一成 True / False / None。
    接口文档里它是布尔, 但经过代理、缓存或别的语言转一手之后常变成 `1` / `'true'` / `'False'`。
    以前只认 `is True` / `is False`, 于是「明确说恶意」的回包掉进关键词兜底 ——
    一个恶意 IP 在界面上显示成绿色「良好」, 是情报层最坏的一种错。
    """
    if value is None or value is True or value is False:
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ('true', '1', 'yes', 'y', 'malicious'):
            return True
        if s in ('false', '0', 'no', 'n', 'clean'):
            return False
    return None


def _remote_label(value):
    """对端可控的标签/文本: 压掉换行 (一条标签不能伪造出好几行结果), 遮掉 IPv4 形状
    (标签里本不该有地址, 留着就能把别人的地址洗进我们的导出)。"""
    s = re.sub(r'\s+', ' ', str(value)).strip()
    return re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '<ip>', s)


def classify_threatbook_verdict(info):
    """
    根据微步 IP信誉接口的 is_malicious 字段判定.
    is_malicious 为权威字段; 缺失时再用 severity/judgments 关键词兜底.
    返回: 'clean' / 'suspicious' / 'malicious'
    """
    is_mal = _malicious_flag(info.get('is_malicious'))
    if is_mal is True:
        return 'malicious'
    if is_mal is False:
        return 'clean'

    # is_malicious 缺失时兜底判断
    severity = _remote_label(info.get('severity') or '')
    labels = ' '.join(_remote_label(j) for j in (info.get('judgments') or []))
    for kw in ('恶意', '高危', '勒索', '挖矿', '木马', '僵尸', '远控', '钓鱼', '扫描攻击'):
        if kw in severity or kw in labels:
            return 'malicious'
    for kw in ('可疑', '风险', '中危'):
        if kw in severity:
            return 'suspicious'
    return 'clean'


def build_threatbook_detail(info):
    """
    从微步 IP信誉接口 情报信息生成详细的多行展示.
    返回: (verdict, lines)
    verdict: 'clean' / 'suspicious' / 'malicious'
    """
    verdict = classify_threatbook_verdict(info)

    is_mal = _malicious_flag(info.get('is_malicious'))
    severity = info.get('severity') or ''
    # 不同接口/版本里 severity 既可能是字符串("高") 也可能是数组(["高危","中危"])
    if isinstance(severity, (list, tuple)):
        severity = ' / '.join(_remote_label(x) for x in severity if x)
    else:
        severity = _remote_label(severity)
    confidence = _remote_label(info.get('confidence_level') or '')

    judgments = [_remote_label(j) for j in (info.get('judgments') or [])]
    # tags_classes 是对象数组: [{"tags": [...], "tags_type": ...}]
    tags_list = []
    for tc in (info.get('tags_classes') or []):
        if isinstance(tc, dict):
            tags_list += [_remote_label(t) for t in (tc.get('tags') or [])]

    basic = info.get('basic') or {}
    loc = basic.get('location') or {}
    carrier = _remote_label(basic.get('carrier') or '')
    location = ' '.join(_remote_label(x) for x in
                        [loc.get('country', ''), loc.get('province', ''), loc.get('city', '')]).strip()
    asn = info.get('asn') or {}
    scene = _remote_label(info.get('scene') or '')
    update_time = _remote_label(info.get('update_time') or '')
    permalink = info.get('permalink') or ''

    lines = []
    mal_str = '是' if is_mal else ('未知' if is_mal is None else '否')
    lines.append(f'  是否恶意 : {mal_str}    严重程度: {severity or "-"}    可信度: {confidence or "-"}')
    lines.append(f'  威胁类型 : {" / ".join(judgments) if judgments else "-"}')
    lines.append(f'  攻击团伙 : {" / ".join(tags_list) if tags_list else "-"}')
    if location:
        lines.append(f'  位置     : {location} {carrier}'.rstrip())
    elif carrier:
        lines.append(f'  运营商   : {carrier}')
    if asn:
        asn_num = asn.get('number', '')
        asn_info = asn.get('info', '')
        asn_rank = asn.get('rank', '')
        lines.append(f'  ASN     : AS{asn_num} {asn_info} (风险值{asn_rank})')
    if scene:
        lines.append(f'  应用场景 : {scene}')
    if update_time:
        lines.append(f'  更新时间 : {update_time}')
    if permalink:
        lines.append(f'  情报页   : {permalink}')
    return verdict, lines


def extract_single_ips(source, is_text=False):
    """提取单个IP (不展开CIDR, 用于威胁情报查询), 支持嵌入文字如 ip127.0.0.1"""
    ips = set()
    for line in read_lines(source, is_text):
        host = extract_host(line)
        if host and is_ip(host):
            ips.add(host)
            continue
        # 从嵌入文字中提取单个IPv4 (如 ip127.0.0.1)
        # `(?![\d])` 是必须的: 少了它, `1.1.1.2024` 会被截成 `1.1.1.202` 拿去查情报
        for m in re.finditer(r'(?<![0-9.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d])', line):
            ip = m.group(1)
            if is_ip(ip):
                ips.add(ip)
    return ips


def _ips_total(nets):
    """一组网段覆盖的去重 IP 数 (不相交区间的长度和)"""
    return sum(hi - lo + 1 for lo, hi in _ip_intervals(nets))


def _ips_intersection_total(nets_a, nets_b):
    """
    两组网段的交集 IP 数。两侧都先并成不相交区间, 再双指针扫一遍 → O((M+N) log(M+N))。
    不能逐 IP 展开: 两份 /8 名单求交要遍历 3355 万个地址, CLI 会当场卡住。
    """
    ra = _ip_intervals(nets_a)
    rb = _ip_intervals(nets_b)
    i = j = total = 0
    while i < len(ra) and j < len(rb):
        lo = max(ra[i][0], rb[j][0])
        hi = min(ra[i][1], rb[j][1])
        if lo <= hi:
            total += hi - lo + 1
        if ra[i][1] < rb[j][1]:       # 谁的右端先到就推进谁, 区间不相交所以不会漏
            i += 1
        else:
            j += 1
    return total


def count_expanded_ips(source, is_text=False):
    """
    计算源文本展开后的去重IP总数 (用于结果框统计).
    单IP=1, CIDR/范围/通配符 按其 num_addresses 累加, 重叠段只算一次.
    注: 对超大范围(如 /0) 为保护性能仍按段返回, 不逐IP展开.
    """
    nets = parse_to_networks(source, is_text)
    # 并成不相交区间再累加 = 去重 IP 总数 (重叠段只算一次)。
    # (旧实现手写线性扫描的包含判断, 2 万行要 3 分钟, 会把 GUI 卡死;
    #  换成 collapse_addresses 后仍要 0.30 秒 —— 它给每个结果段再造一个对象,
    #  改走 _ip_intervals 的排序扫描后 2 万个段约 0.02 秒)
    return _ips_total(nets)


def find_overlapping_networks(source, is_text=False):
    """
    找出所有行的重叠部分 (返回去重后的交集网段列表, 按IP排序).
    两行有交集时, 输出两者共同覆盖的那个网段 (对齐网段相交 ⟹ 一含另一, 交集=较深者).
    如 0.0.0.0 + 0.0.0.0/16 → [0.0.0.0/32]; 10.0.0.0/8 + 10.0.0.0/16 → [10.0.0.0/16].
    域名/无法解析的行不参与.
    """
    raw_lines = read_lines(source, is_text)
    lines_of = {}                     # net -> {出现该段的行号}
    for idx, line in enumerate(raw_lines):
        nets = _nets_of_line(line)      # 与建名单/判定同一口径, 见 dedup_by_network 的说明
        for n in nets:
            lines_of.setdefault(n, set()).add(idx)

    # 按 (起始IP, 前缀长度) 排序后单次扫描求「每个段的祖先行集合」,
    # O(n log n) 取代原先逐对比较的 O(n²)。栈里留下的必然是当前段的祖先:
    # 起点都不大于当前段, 终点又不小于当前段, 对齐网段 ⟹ 一定包含当前段。
    overlaps = set()
    stack = []                        # [(段末整数, 该段及其祖先覆盖的行号并集)]
    for n in sorted(lines_of, key=lambda x: (int(x.network_address), x.prefixlen)):
        start = int(n.network_address)
        end = start + n.num_addresses - 1
        while stack and stack[-1][0] < end:
            stack.pop()
        anc_lines = stack[-1][1] if stack else set()
        own = lines_of[n]
        # 旧的两两写法: 有交集时把「较深」的那个段计入结果 ——
        # 即本段被别的行的段包住, 或同一整段出现在两行以上。
        if len(own) > 1 or (anc_lines - own):
            overlaps.add(n)
        stack.append((end, anc_lines | own))
    return sorted(overlaps, key=lambda n: (int(n.network_address), n.prefixlen))


def format_network(n):
    """网段 → 紧凑文本: 单IP 去 /32, 网段保留 /prefix"""
    if n.num_addresses == 1:
        return str(n.network_address)
    return str(n)


_BAD_PREFIX_RE = re.compile(r'/(\d+)(?![\d.])')


def _bad_prefix_reason(s, partial=False):
    """
    掩码笔误: `1.1.1.1/33` 这种前缀 >32 的写法。
    口径: 这类行**整行不参与匹配**, 名单里一个 IP 都不会进。
    过去提示写「实际只按主机 IP 识别」—— 那是假话: 用户以为放行了一台机器,
    其实一台都没放行。子网掩码写法 (/255.255.255.0) 与枚举写法 (10.10.83/84/85.0) 不算错。
    """
    m = _BAD_PREFIX_RE.search(s) if s.count('/') == 1 else None
    if m and int(m.group(1)) > 32:
        if partial:
            return (f'CIDR 前缀 /{m.group(1)} 非法(>32), 这一片段未参与匹配; '
                    f'同行其他写法仍按字面量识别')
        return (f'CIDR 前缀 /{m.group(1)} 非法(>32), 整行未参与匹配; '
                f'要放行单个 IP 请把 /{m.group(1)} 删掉')
    return None


# 通配段: `x`/`X` 只有**单独占一段**时才是通配符 (`10.10.83.x`、`x.x.x.x`)。
# `_CLEAN_LINE_RE` 的字符表里带着 x/X, 所以还要靠这条把 `xxxxx 10.0.0.5` 那种垃圾串挑出来。
_WILD_SEG_RE = re.compile(r'(?:(?<=^)|(?<=[.,;/\-]))[xX]+(?=[.,;/\-]|$)')
# 本地路径写法: 指向的是这台机器的磁盘, 不是网络资产, 一律不进结果区原文
_PATH_SCHEME_RE = re.compile(r'^(?:file|jar|zip|apk):', re.IGNORECASE)
_WIN_PATH_RE = re.compile(r'^[A-Za-z]:[\\/]')
_UNC_PATH_RE = re.compile(r'^\\\\[^\\]+\\')
# 两段以上的斜杠路径 (`/var/log/10.0.0.5.log`): 首段必须是字母词, 否则
# `10.0.0.0/24-10.0.0.5.0/24` 这种合法范围会被当成路径 (它首段是数字, 且本来就带掩码)。
_DIR_PATH_RE = re.compile(r'^/?[A-Za-z][\w.+*\-]*(?:/[\w.+*\-]+){2,}$')
# URL 里的账号口令 (`https://admin:P@ssw0rd@10.0.0.5/`): 判定看的是 host,
# 口令跟着整行进结果区和导出文件, 等于把密码交给下一个拿到清单的人。
_URL_USERINFO_RE = re.compile(r'^([A-Za-z][A-Za-z0-9+.\-]*://)[^/?#\s]*@')

_CLEAN_LINE_RE = re.compile(r'^[0-9.,\-/\*xX:;，、；\s]+$')
_SCHEME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.\-]*://')


def _glued_bracket_fragments(body):
    """
    挑出「括号直接贴在数字后面」的片段 (`1.1.1[1-3]`、`10[1,3].1.1`), 返回去重后的原文。
    这种写法有两种完全相反的读法 —— `[1-3]` 是新的一段, 还是接在前一段后面的数字?
    (`1.1.1.1~3` 还是 `1.1.11/12/13`)。猜哪一种都是在替用户写他没写的地址, 所以不认,
    但必须点名 (以前只报一句「疑似写法有误」, 用户不知道错在哪、也不知道该怎么改)。
    带 `.` 的 `192.168.1.[1-30]` 不在此列 —— 那是支持的末段范围写法。
    """
    s = _normalize_input(body)
    found = []
    # 闭合括号可能已被归一化去掉 (`1.1.1[1-3` ), 所以右括号写成可选
    for m in re.finditer(r'(?<=[0-9])([\[{])([0-9.,\-~*xX]+)[\]}]?', s):
        content = m.group(2).rstrip('.,')
        if '-' not in content and ',' not in content:
            continue                    # 单值 `[8]` 没有范围歧义, 不当这类处理
        frag = m.group(1) + content + (']' if m.group(1) == '[' else '}')
        if frag not in found:
            found.append(frag)
    return found


def _glued_bracket_hint(frags, lead=''):
    """把 _glued_bracket_fragments 的结果说成人话 (诊断区 / stderr 共用)"""
    return (lead + '%s 有歧义: 括号贴在前一段数字后面, 是新起一段还是接上去? 无法照字面量确定, 未参与匹配。'
            '末段范围请写 1.1.1.[1-3] 或 1.1.1.1-3; 中间段请写 192.168.1-30.5'
            % '、'.join(frags[:3]))


_REVERSED_OCTET_RE = re.compile(r'^(\d{1,3})-(\d{1,3})$')


def _reversed_octet_reading(s, nets):
    """
    「前大后小」的范围写在**非末段**时 (80-10.0.0.5 / 10.90-10.0.0):
    _octet_values 会交换两端, 这一段就变成 10~80 —— 点集没有越出你写下的两个端点,
    但一行凭空跨了 71 个 /8。与末段范围「写反照样识别 + 必须点名」同一口径:
    末段那种写法由 _literal_reading_note 的范围分支管, 这里补上前面几段。
    """
    if not nets:
        return None
    segs = s.split('.')
    if len(segs) != 4:
        return None
    for i, seg in enumerate(segs):
        m = _REVERSED_OCTET_RE.match(seg)
        if not m:
            continue
        hi, lo = int(m.group(1)), int(m.group(2))
        if lo >= hi or hi > 255:
            continue                      # 正序范围 / 超出 0-255 由别的规则点名
        fixed = list(segs)
        fixed[i] = '%d-%d' % (lo, hi)
        got = '、'.join(format_network(n) for n in nets[:3]) + ('…' if len(nets) > 3 else '')
        tot = sum(n.num_addresses for n in nets)
        return (f'第 {i + 1} 段 {seg} 写反了 ({m.group(1)} 在 {m.group(2)} 后面), '
                f'已按 {lo}~{hi} 这一段识别 ({got}, 共 {tot} 个 IP); '
                f'本意不是这一段的话请改成 {".".join(fixed)}')
    return None


def _oversized_octet_in_range(body):
    """
    范围/枚举写法里某一段超出 0-255 (`10.0.0.256-1`、`10.1-300.0.0`、`1-300.1.1.1`):
    这种行整条展不开, 以前只有一句「疑似 IP/网段写法有误」—— 不说是哪一段,
    人就找不到那个多打了一位的数字。四段全是数字的行由 _bad_octet_literal 管,
    这里补「段里带范围/枚举」的这一类。
    """
    toks = _tokens_of_line(body)
    for tok in toks:
        segs = tok.split('.')
        if len(segs) < 3 or len(segs) > 5:
            continue
        for i, seg in enumerate(segs, 1):
            for p in re.split(r'[-/]', seg):
                if not (re.match(r'^\d+$', p) and int(p) > 255):
                    continue            # 只点名「超出 0-255 的纯数字」
                scope = ('这一段未参与匹配' if len(toks) > 1 else '整行未参与匹配')
                return (f'第 {i} 段 {p} 超出 0-255, {scope}; '
                        f'IP 段只能是 0-255, 工具不会把它截短当成别的地址, 请检查笔误')
    return None


def _cidr_range_overflow_reading(body):
    """
    CIDR 范围一行要展开的网段数超过 _CIDR_RANGE_NET_LIMIT (`255.255.255.255/32-0.0.0.0/32`
    是 42 亿个 /32): 解析分支为了不挂死整行不放行, 这里必须说清「为什么一行没进名单」,
    而不是丢一句「疑似写法有误」。
    """
    for tok in _tokens_of_line(body):
        if '-' not in tok:
            continue
        mpair = _CIDR_PAIR_RE.match(tok)
        if not mpair:
            continue
        ended = _cidr_range_ends(mpair.group(1), mpair.group(2))
        if not ended:
            continue
        a, b, count, _swapped = ended
        if count <= _CIDR_RANGE_NET_LIMIT:
            continue
        return (f'范围 {tok} 按 /{a.prefixlen} 展开是 {count} 个网段, 超过一行 '
                f'{_CIDR_RANGE_NET_LIMIT} 段的上限, 整行未参与匹配 (否则会在这里挂死); '
                f'要放行整片请拆成几行显式 CIDR, 要整张互联网请写 0.0.0.0/0')
    return None


def _cidr_pair_reason(body, nets):
    """
    CIDR 范围写法的两种「一行凭空变成一大片」:
      1) 两端写反 (`20.1.0.0/16-10.5.0.0/16`): 交换后覆盖 167575552 个 IP ——
         量级和 `255.255.255.255-0.0.0.0` 一样危险, 照旧识别但必须点名;
      2) 有一端展不开 (`10.1-300.0.0/16-10.5.0.0/16`: 左端有非法段):
         范围分支整条落空, 兜底正则却还能捞出右端那一个网段 ——
         名单凭空少了一大片, 以前一声不吭。这里说清「哪一端、现在只剩多少」。
    非法前缀 (`/33`) 不在这里管: 由「非法前缀」那条规则单独点名 (类别也不同)。
    """
    for tok in _tokens_of_line(body):
        mpair = _CIDR_PAIR_RE.match(tok)
        if not mpair:
            continue
        left, right = mpair.group(1), mpair.group(2)
        if any(int(p) > 32 for p in re.findall(r'/(\d+)', left + ' ' + right)):
            continue
        ended = _cidr_range_ends(left, right)
        if ended:
            if ended[3] and nets:
                return (f'范围两端写反了 ({left} 在 {right} 后面), {_taken_phrase(nets)}; '
                        f'本意不是这一大片的话请把两端按从小到大写')
            continue
        why = f'范围 {tok} 的端点 ({left} / {right}) 不是可展开的网段'
        if not nets:
            return why + ', 整行未参与匹配; 请把两端写成 x.x.x.x/掩码'
        return why + f', 整条范围没有展开, {_taken_phrase(nets)}; 请把两端写成 x.x.x.x/掩码'
    return None


def _segment_combo_widths(segs):
    """
    四元组每一段按字面量有几个取值 (`*` = 256, `1-5` = 5, `83/84/85` = 3, 其余 = 1)。
    出现不认识的写法返回 None (交给别的规则去解释, 不猜)。
    """
    widths = []
    for seg in segs:
        s = seg.split('/')[0]
        if s in ('*', 'x', 'X'):
            widths.append(256)
            continue
        m = re.match(r'^(\d{1,3})-(\d{1,3})$', s)
        if m:
            lo, hi = sorted((int(m.group(1)), int(m.group(2))))
            if hi > 255:
                return None
            widths.append(hi - lo + 1)
            continue
        parts = s.split('/')
        if len(parts) > 1 and all(re.match(r'^\d{1,3}$', p) and int(p) <= 255
                                  for p in parts):
            widths.append(len(parts))
            continue
        if re.match(r'^\d{1,3}$', s) and int(s) <= 255:
            widths.append(1)
            continue
        return None
    return widths


def _not_in_list_phrase(nets):
    """
    「这一条没进名单」有两种情形, 不能用同一句话: 整行什么都没识别出来,
    和行里其余部分照常进了名单、只有这一写法落空。说反了就是假话。
    """
    if not nets:
        return '整行未参与匹配'
    return f'这一写法没有进名单, {_taken_phrase(nets)}'


def _combo_cap_reading(body, nets=None):
    """
    通配符和范围叠在同一行 (`10.*.*.1-5` = 327680 个地址、`*.*.1-5.0` 同理):
    `_range_to_networks` 的逐值组合上限把它挡下了 —— 不挡就是几十万个对象,
    GUI 直接卡住。不收是对的, 但丢一句「疑似写法有误」等于什么也没说:
    这里点名是哪一行、按字面量是多少个、上限是多少。
    纯通配 (`10.*.*.*`) 不在这里管 —— 那条走网段分支, 本来就能收成 10.0.0.0/8。
    """
    # 分词会把 `*.*.1-5.0` 开头那截丢掉 (分词只捞数字开头的片段), 所以整行也要当一种形状看一次
    toks = list(_tokens_of_line(_normalize_input(body)))
    joined = str(body).strip()
    if joined and joined not in toks:
        toks.append(joined)
    for tok in toks:
        low = tok.lower()
        if '-' not in tok:
            continue
        segs = tok.split('/')[0].split('.')
        if len(segs) != 4:
            continue
        widths = _segment_combo_widths(segs)
        if not widths:
            continue
        total = 1
        for w in widths:
            total *= w
        if total <= _RANGE_COMBO_LIMIT or _nets_of_line(tok):
            continue
        # 通配叠范围 (`10.*.*.1-5`) 和多段都写范围 (`1-255.1-255.1-255.1-255`) 是同一件事:
        # 逐值组合爆到上限以外。以前只认前者, 后者落回「疑似写法有误」。
        head = segs[0]
        advice = (f'本意是整段请写显式网段 (如 {head}.0.0.0/8)' if re.match(r'^\d{1,3}$', head)
                  else '本意是整段请写显式网段, 如 0.0.0.0/0')
        label = ('多段同时写范围' if sum(1 for w in widths if w > 1) >= 2
                 and not any(c in low for c in ('*', 'x')) else '通配符和范围叠在一行')
        return (f'{label} ({tok}) 按字面量要展开 {total} 个地址, '
                f'超过一行 {_RANGE_COMBO_LIMIT} 个的上限, {_not_in_list_phrase(nets)} '
                f'(否则会在这里卡死); {advice}, 只要其中一部分请把范围写小或拆成几行')
    return None


def _multi_value_seg_reading(body, nets=None):
    """
    两段以上同时写多值 (`10.1-2.1-2.1-2`、`1-255.1-255.1-255.1-255`、`10.1/2.3/4.5.6` 这类):
    解析层的口径是「一次只让一段写多值, 其余段写死」—— 多段范围叠在一起有两种完全不同的读法
    (逐值配对 / 笛卡尔组合), 量级差几十倍, 猜大就是越界, 所以整条不展开。
    不展开可以, 静默不行: 过去这些行只有一句「疑似 IP/网段写法有误」,
    看的人不知道自己写的是哪种量级, 也不知道该改哪一段。
    """
    toks = list(_tokens_of_line(_normalize_input(body)))
    joined = str(body).strip()
    if joined and joined not in toks:
        toks.append(joined)
    for tok in toks:
        segs = tok.split('/')[0].split('.')
        if len(segs) != 4:
            continue
        widths = _segment_combo_widths(segs)
        if not widths:
            continue
        multi = sum(1 for w in widths if w > 1)
        if multi < 2 or _nets_of_line(tok):
            continue
        total = 1
        for w in widths:
            total *= w
        over = ('按字面量组合是 %s 个地址, 超过一行 %d 个的上限' % (format(total, ','), _RANGE_COMBO_LIMIT)
                if total > _RANGE_COMBO_LIMIT else
                '逐值组合是 %s 个地址' % format(total, ','))
        return (f'{tok} 有 {multi} 段同时写了范围/枚举/通配, 现在的口径是一次只让一段写多值, '
                f'其余段写死 ({over}, 另一种读法是逐段同值配对, 量级差得远, 猜大就是越界); '
                f'{_not_in_list_phrase(nets)} —— 想要哪一段就写死其余段, 或拆成几行')
    return None


def _star_mask_clash_reading(body, nets=None):
    """
    通配段与掩码冲突 (`10.0.0.*/32`): `10.0.0.*` 字面是 256 个地址, `/32` 字面只有 1 个,
    两种读法差 256 倍。解析层不猜 (所以名单里它是空的), 但必须把两个量级都摆出来,
    否则「写了掩码却没进名单」和「写了通配却没进名单」看起来一样。
    通配段落在网络位 (`10.*.0.0/24`) 不属于冲突 —— 那种照常展开, 不会走到这里。
    """
    toks = list(_tokens_of_line(_normalize_input(body)))
    joined = str(body).strip()
    if joined and joined not in toks:
        toks.append(joined)
    for tok in toks:
        if '*' not in tok.lower().replace('x', '*'):
            continue
        head, _, tail = tok.partition('/')
        prefix = _mask_prefix_len(tail) if tail else None
        if prefix is None:
            continue
        segs = head.split('.')
        if len(segs) != 4:
            continue
        star_idx = next((i for i, g in enumerate(segs)
                         if g.strip().lower() in ('*', 'x')), None)
        if star_idx is None or star_idx < -(-prefix // 8) or _nets_of_line(tok):
            continue
        literal = ['0' if i == star_idx else (g if re.match(r'^\d{1,3}$', g) else '0')
                   for i, g in enumerate(segs)]
        wide = '%s/%d' % ('.'.join(literal), 8 * star_idx)
        return (f'{tok} 里 `*` 那一段字面是 256 个地址, 掩码 {tail} 字面只有 '
                f'{2 ** (32 - prefix)} 个 —— 两种读法差 {256 // max(2 ** (32 - prefix), 1)} 倍, '
                f'猜大就是越界, 没有替你选一种, {_not_in_list_phrase(nets)}; '
                f'要那 256 个请写 {wide}, 要 1 个请把 * 换成具体数字')
    return None


def _five_segment_reading(body, nets=None):
    """
    `1.2.3.4.5` / `10.0.0.1.2`: 段数超过 4, 根本不是 IPv4。
    过去只回「疑似 IP/网段写法有误」, 而这类写法十有八九是版本号、日期或多写了一段,
    点名有几段才看得出来该删哪一段 (不猜、不截: 截成 4 段等于凭空放行一个没人写过的地址)。
    已经被别的规则吃下的五段 (`10.0.0.0.1` 那种按单个 IP 识别的) 不在这里说,
    否则会出现「名单里有这条, 提示却说整行没进名单」的假话。
    """
    for tok in _tokens_of_line(_normalize_input(body)):
        if not re.match(r'^\d{1,3}(?:\.\d{1,3}){4,}$', tok):
            continue
        if _nets_of_line(tok):
            continue
        n = tok.count('.') + 1
        return (f'{tok} 有 {n} 段, IPv4 只有 4 段, {_not_in_list_phrase(nets)}; '
                f'这更像版本号/日期或多打了一段, 要写 IP 请删掉多余的一段')
    return None


def _ip_space_mask_reading(s, nets):
    """
    `10.0.0.1 255.255.255.0` —— ifconfig、路由表、网络设备导出里的「IP 空格 掩码」老写法。
    工具**不**把它并成 /24: 并了就等于凭空多出 254 个没人写下的地址 (`多算一个就是越界一个`)。
    但 255.255.255.0 显然不是谁的主机地址, 所以必须说清它被当成第 2 个字面 IP 收了,
    并给出「要整段该写什么」。
    """
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})[ \t]+'
                 r'(25[05]\.\d{1,3}\.\d{1,3}\.\d{1,3})$', s.strip())
    if not m:
        return None
    host, mask = m.group(1), m.group(2)
    if mask == '255.255.255.255':
        return None
    if not _is_contiguous_mask(mask):
        # 形似掩码却不是连续掩码 (`255.255.0.255`): 当掩码用会算出谁都没写过的网段,
        # 当地址用又明显不像谁的 IP —— 两种读法都得让人看一眼, 所以照字面收 2 个 IP 并点名。
        return (f'{host} {mask} 里的 {mask} 形似掩码却不是合法掩码 (二进制不连续), '
                f'没有当成掩码用, {mask} 按字面量识别为第 2 个 IP ({_taken_phrase(nets)}); '
                f'要写掩码请改成连续的, 如 255.255.0.0')
    try:
        net = ipaddress.IPv4Network('%s/%s' % (host, mask), strict=False)
    except Exception:
        return None
    return (f'{host} {mask} 是「IP 空格 掩码」的老写法 (ifconfig/路由表常见), '
            f'没有替你并成网段, {mask} 按字面量识别为第 2 个 IP ({_taken_phrase(nets)}); '
            f'要这一片请写 {net}')


def _range_endpoint_taken(left, tail, nets):
    """
    范围右端 (允许粘着 `:端口`) 去掉端口后**确实在名单里** → True。
    判断「范围到底展没展开」得看实际解析结果, 不能只看字符串形状:
    `10.0.0.1-5:80` 的右端是 `5:80`, 形状判据认不出来, 于是把一行已经完整识别成
    5 个 IP 的名单报成「右端没有被识别成范围」—— 误报会引导人去改一行本来正确的名单。
    """
    core = re.match(r'^(\d{1,3}(?:\.\d{1,3}){0,3})(?::\d+)?$', str(tail))
    if not core or not nets:
        return False
    r = core.group(1)
    try:
        if len(r.split('.')) == 1:
            end = ipaddress.IPv4Address(left.rsplit('.', 1)[0] + '.' + r)
        else:
            end = ipaddress.IPv4Address(r)
    except Exception:
        return False
    return any(end in n for n in nets)


def _brief(text, limit=18):
    """
    提示语里要复述用户写下的那一串。狂敲出来的 300 位数字也是「只有 1 段」,
    但把 300 位原样打印进诊断区/AI 窗口等于刷屏 —— 复述用截断, 截断只影响好看与否,
    不影响判定 (判定用的仍是完整字符串)。
    """
    t = str(text)
    return t if len(t) <= limit else t[:limit] + '…'


def _strip_mask_tail(s):
    """
    摘掉末尾掩码, 只给「数段数」的诊断用。枚举本身也用斜杠 (`10.1/2/3.0/24` 里有三个斜杠), 所以:
    点分掩码一律摘 (`10.0.0.1/255.0.255.0` 的掩码虽然非法, 写法上仍是掩码, 摘掉才能让
    「掩码不连续」那条规则说清毛病, 而不是数出 7 段地址让人以为多点了几段);
    1-2 位数字的尾巴要前面已经出现过斜杠、或地址已经写到 3 段才摘 —— 否则 `10.1/2` 会被摘成
    `10.1`, 把「末段枚举没写全」说成「段数不够」。
    """
    s = str(s)
    core, sep, tail = s.rpartition('/')
    if not sep:
        return s
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', tail):
        return core
    if re.match(r'^\d{1,2}$', tail) and ('/' in core or core.count('.') >= 2):
        return core
    return s


def _segment_count_note(core, nets=None, mask=''):
    """
    单个形状 → 「段数不对」的说法; 不是这种情形返回 None 交给别的规则解释。
    `core` 是已经摘掉末尾掩码、末尾点的字符串; `mask` 是摘掉的那截掩码 (要还回提示语里)。
    """
    segs = core.split('.')
    if len(segs) == 4 or not segs[0]:
        return None
    # 长度看段里每个值: `1/2/3` 整串 5 个字符, 但每个枚举值都是 1 位, 属于正常段
    if any(len(v) > 3 for g in segs for v in re.split(r'[-/]', g)):
        return None            # `2024.1.15` 那种带超界段的由 _oversized_octet_in_range 说
    if not all(_SEG_SHAPE_RE.match(g) for g in segs):
        return None
    n = len(segs)
    phrase = _not_in_list_phrase(nets)
    core = _brief(core)
    if n == 1:
        return (f'{core} 只有 1 段数字, IPv4 地址要写满 4 段 (整数形式的地址不识别); '
                f'{phrase}, 请写成 4 段点分形式')
    if n > 4:
        return (f'{core} 点分有 {n} 段, IPv4 只有 4 段; {phrase}, '
                f'多出来的段既不是掩码也不是地址, 请检查是否多打了点')
    head = (f'{core} 点分只有 {n} 段' if not mask
            else f'{core} 的掩码 {mask} 之前只有 {n} 段')
    return (f'{head}, IPv4 地址要写满 4 段; {phrase}, '
            f'补齐请写成 {core}.' + '<第 %d 段>%s' % (n + 1, mask))


def _segment_count_reading(body, nets=None):
    """
    点分段数**不是 4 段**的写法 (`10`、`10.0`、`10.0.0`、`10.1/2/3.0`、`2130706433`、
    `10.*.1-5:80` 里的 `10.*.1-5`): 与「有 N 段」那条纯数字写法对称, 把原因说成「段数不对」,
    而不是丢一句「疑似 IP/网段写法有误」让人自己猜哪里错。
    只处理纯 IP 形状 (段里允许 `*`/`x`/`-`/枚举斜杠)。
    带 `.` 的分词片段也要单独看一次: 行里混着端口 (`10.*.1-5:80`) 时整行形状认不出来,
    但 `10.*.1-5` 这一段确实是少写了一段 —— 只看不带点的裸数字 (`80`) 会把端口说成段数错误。
    """
    def seg_count(sh):
        core = _strip_mask_tail(sh)
        # 摘掉的尾巴要还回去: `1.*.*/8` 的毛病是「掩码前面只写了 3 段」,
        # 只说「1.*.* 少一段」会让人照着提示补成 1.*.*.0/8 以外的东西。
        return _segment_count_note(core.rstrip('.'), nets, sh[len(core):])

    s = str(body).strip()
    if s and _NUMISH_SHAPE_RE.match(s):
        if re.match(r'^\d+$', s):      # 纯一串数字 (`2130706433` 这种整数形式的 IP)
            return (f'{_brief(s)} 只有 1 段数字, IPv4 地址要写满 4 段 (整数形式的地址不识别); '
                    f'{_not_in_list_phrase(nets)}, 请写成 4 段点分形式')
        note = seg_count(s)
        if note:
            return note
    for tok in _tokens_of_line(_normalize_input(s)):
        if '.' not in tok or not _NUMISH_SHAPE_RE.match(tok):
            continue
        note = seg_count(tok)
        if note:
            return note
    return None


def _spaced_dots_reading(body):
    """
    点号两侧带空格的地址 (`10 . 0 . 0 . 1`, 从 PDF、表格、OCR 文本里粘出来常见):
    分词按空格切开, 四段变成四个孤立的数字, 谁也拼不成地址 —— 所以整行什么都不进名单。
    这里不替你并 (`1. 2. 3. 4` 也可能是排到一半的序号, 并了就是凭空放行一个地址),
    只把「去掉空格后长这样」摊出来让你自己看一眼。
    """
    s = str(body).strip()
    if '.' not in s or (' ' not in s and '\t' not in s):
        return None
    tight = re.sub(r'[ \t]*\.[ \t]*', '.', s)
    if tight == s or not _NUMISH_SHAPE_RE.match(tight):
        return None
    if len(_strip_mask_tail(tight).rstrip('.').split('.')) != 4:
        return None
    return (f'地址段之间打了空格 ({_brief(s)}): 分词按空格切开, 四段成了四个孤立数字, '
            f'整行未参与匹配; 去掉点号两侧的空格写成 {_brief(tight)} 才是地址')


def _bare_fragment_reading(body, nets=None):
    """
    只剩半截的写法 (`:80`、`80:`、`~5`): 光秃秃的端口或范围的一端, 没有地址也没有左端可补。
    以前落到「疑似 IP/网段写法有误」, 看的人不知道自己是漏了地址还是漏了端口。
    """
    s = str(body).strip()
    m = re.match(r'^[:：][ \t]*(\d{1,5})$', s) or re.match(r'^(\d{1,5})[ \t]*[:：]$', s)
    if m:
        return (f'{s} 只有端口号 {m.group(1)} 没有地址, {_not_in_list_phrase(nets)}; '
                f'端口要跟在地址后面, 如 10.0.0.1:{m.group(1)}')
    m = re.match(r'^[-~～〜–][ \t]*(\d{1,3})$', s)
    if m:
        return (f'{s} 只有范围的右端 {m.group(1)}, 左边没有地址, 无从确定范围从哪开始; '
                f'{_not_in_list_phrase(nets)}, 请写成 10.0.0.1-{m.group(1)} 这样带左端的形式')
    return None


def _noncontig_mask_reading(body):
    """
    斜杠写成不连续掩码 (`10.0.0.1/255.0.255.0`): 这种掩码既不能当网段 (算出来的段谁都没写过),
    也认不出是别的意思, 所以整条不解析 —— 但必须点名是**掩码不连续**, 而不是笼统的「写法有误」。
    """
    m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,3}(?:\.\d{1,3}){3})$',
                 str(body).strip())
    if not m:
        return None
    mask = m.group(2)
    try:
        int(ipaddress.IPv4Address(mask))
    except Exception:
        return None         # 连地址都不是 (如 999.999.999.999), 由别的规则说
    if _is_contiguous_mask(mask):
        return None
    return (f'斜杠后的 {mask} 形似掩码却不是合法掩码 (二进制不是连续 1), 没有当成掩码用, '
            f'整行未参与匹配; 掩码要连续, 如 255.255.0.0 (/16)、255.255.255.0 (/24)')


def _star_led_reading(body):
    """
    `*` 开头的写法 (`*.*.0.0/8`、`*.*.*.*`): 分词阶段只捞数字开头的片段, 所以这种行
    一条都不会进名单。以前只有「全通配」和「超上限」两种情况有说法, 其余落到笼统提示;
    这里统一说清: 通配符要写在数字段后面, 想表达整段直接写 CIDR。
    """
    s = str(body).strip()
    if s[:1] not in ('*', 'x', 'X') or not re.search(r'\d', s):
        return None
    return (f'以 * 开头的写法 ({s}) 没有进名单: 分词只捞数字开头的片段, '
            f'通配符请写在数字段后面 (如 10.*.2.3), 要整段直接写 CIDR (如 0.0.0.0/8)')


def _fix_form(cand, base_nets=None):
    """
    提示语里「照着写就对」的那个例子必须先自己跑一遍解析。
    只收得到名单、且比这一行现在收得更多的写法才配出现在提示里:
    `10.0.0.1/24-*` 过去建议「要末段范围请写 10.0.0.1-*」, 而那种写法自己也只收 1 个 IP ——
    用户照抄完名单一个字都没多, 一句提醒于是变成第二条错误名单 (工具自己教的错写法)。
    验不过返回 None, 由调用方退回「不含具体写法」的说法。
    """
    s = str(cand).strip()
    if not s or '<' in s or '\n' in s:
        return None
    try:
        got = _nets_of_line(s)
    except Exception:
        return None
    if not got or not re.search(r'\d+\.\d', s):
        return None
    if base_nets is not None and _ips_total(got) <= _ips_total(base_nets):
        return None
    return s


def _zero_padded_endpoints(token):
    """
    写法里带前导 0 的数字端点 (`10.1.2.3-07` 的 `07`、`10.3-010.2.1` 的 `010`)。
    只看范围写法 (`-` 在里面): 裸地址那种 (`010.1.1.1`) 早由 `_leading_zero_reading` 管,
    两边各说各的才不会把「一个地址没进名单」和「一段范围没展开」混成同一句话。
    """
    out = []
    if '-' not in token:
        return out
    for seg in token.split('.'):
        for num in re.findall(r'\d+', seg):
            if len(num) > 1 and num[0] == '0' and num not in out:
                out.append(num)
    return out


def _swap_endpoint(token, mapping):
    """把写法里指定的那几个数字换成给定值 (只在「前后都不是数字」的位置换, 免得动了别的段)"""
    out = token
    for num, repl in mapping.items():
        out = re.sub(r'(?<!\d)' + re.escape(num) + r'(?!\d)', repl, out, count=1)
    return out


def _leading_zero_endpoint_note(token, nets):
    """
    范围的**端点**写成带前导 0 的数字 (`10.1.2.3-07`、`10.3-07.2.1`、`127.168.10.03-127.168.10.7`)。
    口径与裸地址那条完全一致: `010` 照十进制是 10、照八进制是 8, 猜哪一种都是替用户凭空放行
    一个他没写下的地址, 所以端点既不换算、也不放大 —— 展开量一个字都不改。
    但「不换算」不等于「不用说」: `10.1.2.3-07` 现在只进 1 个 IP, 写的人以为放行了一段,
    少收的那些在名单里完全看不出来; `10.3-010.2.1` 反过来收了 8 个, 而八进制读法是 6 个。
    所以这里把「这一行实际进了几个」和「另一种读法会是几个」并排列出来, 让人自己核对。
    """
    zeros = _zero_padded_endpoints(token)
    if not zeros:
        return None
    tn = _try_parse_networks(token) or nets
    if not tn:
        return None
    dec_map = {z: str(int(z, 10)) for z in zeros}
    dec = _swap_endpoint(token, dec_map)
    bits = []
    fix = _fix_form(dec, tn)
    if fix:
        _, ftot = _net_reading(_nets_of_line(fix))
        _, tot = _net_reading(tn)
        bits.append(f'去掉前导 0 写成 {fix} 才是 {ftot} 个 IP, 这一行现在只有 {tot} 个 '
                    f'(差出来的 {ftot - tot} 个在名单里看不出来)')
    oct_map = {}
    for z in zeros:
        try:
            v = int(z, 8)
        except ValueError:
            continue                    # 08/09 不是八进制数, 只有十进制这一种读法
        if str(v) != str(int(z, 10)):
            oct_map[z] = str(v)
    if oct_map:
        on = _nets_of_line(_swap_endpoint(token, oct_map))
        if on:
            _, otot = _net_reading(on)
            bits.append('若那是八进制 (%s), 这一行应是 %d 个 IP'
                        % ('、'.join('%s=%d' % (k, int(k, 8)) for k in oct_map), otot))
    if not bits:
        bits.append(f'两种读法在这里同值 ({dec} 那个数就是端点), 0 多半是多打的, '
                    f'请确认这一段没多写')
    return (f'{token} 的范围端点 {"、".join(zeros)} 带前导 0, 八进制有歧义故不换算端点, '
            f'按字面量识别: {_taken_phrase(tn)}; ' + '; '.join(bits))


def _near_full_range_note(token, nets):
    """
    末段范围写成「几乎整段」(`10.0.0.1-254`、`10.0.0.1-255`、`10.0.0.0-254`):
    展开照旧按字面量, 一个地址都不多、一个都不少; 要说的只是命名不对称 ——
    同一份名单里 `10.0.1-254.0` (末段忘了写) 会被「尾随 .0 的多值写法」点名,
    而这种只差首尾两个地址的写法却完全静默, 看的人以为 `x.y.z.1-254` 就是整段。
    正好写满 0-255 的不说: 那一行就是整段, 没有要核对的东西。
    """
    m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$', token)
    if not m:
        return None
    head, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
    if hi > 255 or lo > 255 or hi <= lo or lo > 1 or hi < 254 or (lo, hi) == (0, 255):
        return None
    tn = _try_parse_networks(token)
    if not tn:
        return None
    shown, tot = _net_reading(tn)
    missing = ['%s.%d' % (head, x) for x in (0, 255) if not lo <= x <= hi]
    whole = _fix_form('%s.0/24' % head, tn)
    tail = (f'要整段请写 {whole}' if whole else '要整段请写显式掩码')
    return (f'{token} 按字面量识别为 {tot} 个 IP ({shown}), 不是整段: '
            f'行里没写 {"、".join(missing)} 这 {len(missing)} 个; {tail}')


def _range_endpoint_note(text):
    """
    范围**端点**本身的毛病 (左端超出 0-255 / 右端超出 0-255 / 结尾缩写补全 / 两端写反)。
    这几条只认整体锚定的形状 (`^ip-ip$`), 串里有逗号、制表符就匹配不上, 所以
    既可以在整行上跑, 也可以在单个写法上跑, 结果一样。
    """
    s = str(text)
    # 范围**左端**写成超出 0-255 的数字 (`256-10.0.0.1`、`8080-10.0.0.1`、`2024-1.0.0.0`):
    # 左端不是合法段, 范围展不开; 右端那个地址是你照写的, 所以仍按它识别 ——
    # 但绝不能静默, 和「右端超出 0-255 时现只按左侧识别」是对称的同一条口径。
    mleft = re.match(r'^(\d{1,6})-(\d{1,3}(?:\.\d{1,3}){3})$', s)
    if mleft and int(mleft.group(1)) > 255:
        return (f'范围左端 {mleft.group(1)} 超出 0-255, 不是合法地址, 范围没有展开; '
                f'现只按右侧 {mleft.group(2)} 识别 1 个 IP, 请检查笔误')
    # 范围写法的两端: 补全的要说明补成了什么, 补不了/越界的必须点名, 绝不静默按单个 IP 算
    m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}(?:\.\d{1,3}){0,3})$', s)
    if m:
        left, right = m.group(1), m.group(2)
        rsegs = right.split('.')
        if any(int(x) > 255 for x in left.split('.')):
            return f'范围左侧 {left} 不是合法 IP, 整行未参与匹配; 请检查笔误'
        over = [x for x in rsegs if int(x) > 255]
        if over:
            return ('范围右端 %s 有超出 0-255 的段 (%s), 不是合法地址; '
                    '现只按左侧 %s 识别, 请检查笔误' % (right, '、'.join(over), left))
        if len(rsegs) not in (1, 4):        # 2/3 段 = 缩写尾巴, 要补全才能算
            lo = ipaddress.IPv4Address(left)
            hi = _range_tail_complete(left, right)
            if hi is not None and int(hi) >= int(lo):
                return (f'范围结尾 {right} 是左侧的缩写, 已补成 {hi} '
                        f'(共 {int(hi) - int(lo) + 1} 个 IP, 锚点相同才敢补); 请确认没补错')
            return (f'范围结尾 {right} 既不是末段数字也不是完整 IP, 与左侧各段也不重复, '
                    f'无法按字面补全; 现只按左侧 {lo} 识别, 要写范围请写成 {left}-<完整IP>')
        # 两端写反 (`198.51.100.10-198.51.100.5`): 行为照旧取两端之间这一段
        # (不会越出写下的端点), 但 `255.255.255.255-0.0.0.0` 一交换就是整张互联网,
        # 这种量级绝不能静默 —— 必须点名说清变成了多少个 IP。
        if len(rsegs) == 1:
            e2 = left.rsplit('.', 1)[0] + '.' + right
        else:
            e2 = right
        try:
            a = ipaddress.IPv4Address(left)
            b = ipaddress.IPv4Address(e2)
        except Exception:
            a = b = None
        if a is not None and b is not None and int(b) < int(a):
            return (f'范围两端写反了 ({left} 在 {e2} 后面), 已按 {b}~{a} 这一段识别 '
                    f'(共 {int(a) - int(b) + 1} 个 IP); 本意不是这一段的话请把 -{right} 删掉')
    return None


def _literal_token_note(token, nets):
    """
    单个写法 (一行被分隔符切出来的一条) 的范围形状检查。
    必须逐写法跑而不是拿整行跑: `127.168.10.1~29,10.0.0.1~5` 是两条各自展开正常的范围,
    整行套形状正则会把第一条的右端读成 `29,10.0.0.1-5` 这种谁都没写过的串, 于是报出
    「右端没有被识别成范围」的假点名 —— 假报错和静默一样有害, 人会回头去改一条没写错的名单。
    `nets` 是整行解析结果, 只在写法自己解析不出东西时才拿来兜底说数量。
    """
    s = str(token)
    re_note = _range_endpoint_note(s)
    if re_note:
        return re_note
    lz = _leading_zero_endpoint_note(s, nets)
    if lz:
        return lz
    m2 = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^\-]*)-(.+)$', s)
    if m2:
        left, extra, tail = m2.group(1), m2.group(2), m2.group(3)
        tnet = _nets_of_line(s) or nets
        # 只处理左端写成「IP / IP+掩码(前缀数或点分掩码) / IP:端口」紧跟范围的三种形;
        # 其余 (逗号分隔多 IP、整行含文字) 不由这条规则管, 免得误报。
        shaped = (extra == '' or re.match(r'^/\d{1,2}$', extra)
                  or re.match(r'^:\d+$', extra)
                  or re.match(r'^/\d{1,3}(\.\d{1,3}){3}$', extra))
        port_range = extra.startswith(':')                  # `1.2.3.4:80-443` 是端口范围
        pm_l = re.match(r'^/(\d+)$', extra)
        pm_r = re.search(r'/(\d+)(?![\d.])', tail)
        bad_l = bool(pm_l) and int(pm_l.group(1)) > 32
        bad_r = bool(pm_r) and int(pm_r.group(1)) > 32
        # `10.0.0.0/24-10.0.5.0/24` 是正常 CIDR 范围; 前缀写错 (33) 就不算了
        cidr_range = extra.startswith('/') and '/' in tail and not (bad_l or bad_r)
        # 左端干净 + 右端是末段数字/点分地址 → 范围分支真的吃下了它, 不用提示。
        # 右端只是粘了端口 (`10.0.0.1-5:80`) 时范围同样已经展开 (5 个 IP 一个不缺),
        # 光看字符串形状认不出来, 会把一行正确的名单报成「右端没被识别成范围」——
        # 所以再拿实际解析结果验一次: 右端那个地址真在名单里就不提示。
        endpoint_ok = (extra == '' and (re.match(r'^\d{1,3}$', tail)
                                        or re.match(r'^\d{1,3}(\.\d{1,3}){1,3}$', tail))) \
            or _range_endpoint_taken(left, tail, tnet)
        if shaped and not port_range and not cidr_range and not endpoint_ok:
            # 提示里的数量必须照实报: 右端带掩码时行内还会顺带捞出整段 (见 _nets_of_line),
            # 写死「算 1 个 IP」等于把越界的 255 个藏起来。
            taken = _taken_phrase(tnet)
            if bad_l or bad_r:
                which = tail if bad_r else left + extra
                return (f'范围端点 {which} 的 CIDR 前缀 /{(pm_r or pm_l).group(1)} 非法(>32), '
                        f'整个范围没展开, {taken}; 请检查掩码写法')
            num = tail.split('/')[0]
            if extra:
                # 修法要「照抄就对」: `{left}{extra}` 是「只放行左端那一整段」,
                # `{left}-{num}` 是「末段范围」, 两条都先拿去解析一遍;
                # 解析不出东西 (或和这一行现在收得一样少) 的那条不写出来 ——
                # 工具给一个收不进名单的修法, 等于亲手教人写出第二条错误名单。
                bits = []
                w = _fix_form(left + extra)
                if w:
                    _, wt = _net_reading(_nets_of_line(w))
                    bits.append(f'要整段请写 {w} ({wt} 个 IP)')
                r = _fix_form('%s-%s' % (left, num), tnet)
                if r:
                    _, rt = _net_reading(_nets_of_line(r))
                    bits.append(f'要末段范围请写 {r} ({rt} 个 IP)')
                if not bits:
                    bits.append('请把范围写成两端都满四段的形式, 端点上不要再叠掩码或通配符')
                return (f'范围写法 {s} 的左端带着 {extra}, 范围没有展开, '
                        f'{taken}; ' + ', '.join(bits))
            ex_tail = _fix_form('%s-%s' % (left, num), tnet)
            ex_full = None
            if re.match(r'^\d{1,3}$', num):
                ex_full = _fix_form('%s-%s' % (left, left.rsplit('.', 1)[0] + '.' + num), tnet)
            how = ' 或 '.join(x for x in (ex_tail, ex_full) if x)
            if how:
                return (f'范围写法只认出了行内写法, 右端 {tail} 没有被识别成范围, '
                        f'{taken}; 请写成 {how}, 要整段请写显式掩码')
            return (f'范围写法只认出了行内写法, 右端 {tail} 没有被识别成范围, '
                    f'{taken}; 请把两端都写成完整地址 (10.0.0.1-10.0.0.255 这种), '
                    f'右端不要再叠通配符或掩码, 要整段请写显式掩码')
    tn = _nets_of_line(s) or nets
    got = '、'.join(format_network(n) for n in tn[:3]) + ('…' if len(tn) > 3 else '')
    # 完整 IP 后面还跟着第二个斜杠 (`1.1.1.1/24/25`、`8.8.8.8/1/2/3`): 走的是「末段枚举」分支,
    # 展开出来的每个地址都是你写下的数字, 点集没有凭空放大; 但 `/24` 长得就是掩码,
    # 静默按 3 个 IP 收会让白名单少一片 —— 必须说清它不是 /24 网段。
    m4 = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})/(\d{1,3})/(\d{1,3}'
                  r'(?:/\d{1,3})*)$', s)
    if m4:
        p = int(m4.group(3))
        tail_hint = (f'想放行整段请写 {m4.group(1)}.0/{p}' if p <= 32
                     else f'/{m4.group(3)} 也不是合法前缀, 想写网段请把掩码写成 0-32')
        return (f'{s} 按字面量识别为 {len(tn)} 个 IP ({got}) —— 斜杠出现在完整 IP 之后, '
                f'走的是「末段枚举」而不是掩码, 不是 /{m4.group(3)} 网段; {tail_hint}')
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.0\.\d{1,3}$', s):
        head = s[:s.rindex('.0.')]
        return f'五段写法按单个 IP {got} 识别, 未扩成网段; 若想写 C 段请写 {head}.0/24'
    if (s.endswith('.0') and len(tn) > 1
            and all(n.prefixlen == 32 for n in tn)
            and re.search(r'\d+\s*[/-]\s*\d+', s)):
        # 建议的掩码按「哪一段写了多值」定: 第 1/2/3 段范围 → 补 /8//16//24 才是整段。
        # 「照抄就对」的例子只在整行只剩一段多值、其余段全是写死数字时才给:
        # `10.*.0/1.0` 行尾拼上 /24 得到 `10.*.0/1.0/24`, 那是「通配叠枚举再叠掩码」的
        # 第三种形状, 收 131072 个地址 —— 原行 512 个的 256 倍。
        # 提示自己给出的修法若比原行多收, 等于工具教人越界。
        segs_h = s.split('.')
        multi = ([i for i in range(3)
                  if re.match(r'^\d+(?:-\d+|/\d+)+$', segs_h[i])]
                 if len(segs_h) == 4 else [])
        others_fixed = all(re.match(r'^\d{1,3}$', sg)
                           for i, sg in enumerate(segs_h) if i not in multi)
        if len(multi) == 1 and others_fixed:
            hint = f'要整段请写显式掩码, 如 {s}/{8 * (multi[0] + 1)}'
        else:
            hint = ('要整段请把多值那一段逐值写成各自带掩码的网段, 或拆成几行 '
                    '(在行尾直接补掩码会成另一种写法, 收的地址和这一行不一样多)')
        return (f'手写范围按字面量识别为 {len(tn)} 个 IP ({got}), 未自动扩成整段; {hint}')
    nf = _near_full_range_note(s, tn)
    if nf:
        return nf
    return None


def _literal_reading_note(body):
    """
    手写范围/枚举/五段写法按「字面量」收窄时, 说明它到底变成了什么。
    只挑最容易被误会的两类: 结尾写成 .0 的多值写法 (以前会被当成 C 段), 以及五段笔误。
    """
    s = _normalize_input(body)
    # 端点本身越界/缩写/写反: 整体锚定的形状, 整行跑一次即可 (单写法行与逐写法跑结果相同,
    # 而这里必须跑在「一个网段都没解析出来」之前 —— 那种行也要说清为什么是 0 个)。
    head_note = _range_endpoint_note(s)
    if head_note:
        return head_note
    nets = _nets_of_line(s)
    if not nets:
        return None
    fs = _five_segment_reading(s, nets) or _combo_cap_reading(s, nets)
    if fs:
        return fs
    for tok in _tokens_of_line(s):
        rv = _reversed_octet_reading(tok, nets)
        if rv:
            return rv
    cp = _cidr_pair_reason(s, nets)
    if cp:
        return cp
    im = _ip_space_mask_reading(s, nets)
    if im:
        return im
    # 斜杠写法不完整: `10.0.0.1/` (掩码没写) 与 `10.0.0.1//24` (连续斜杠笔误)。
    # 两者都只按斜杠前那个地址收 1 个 IP, 不猜掩码; 但必须说明, 否则名单少放行一片。
    # URL 里 `//` 和结尾的 `/` 都是正常写法 —— 协议头写在行中间 (`10.0.0.5 http://a.com`)
    # 也一样正常, 所以这里必须 search 而不是 match。
    # 提示语只引用真正出问题的那个**片段**: 以前整行带 URL 时会建议
    # 「如 10.0.0.5 http:/24」这种谁也用不了的写法, 等于把一句提醒变成第二条错误名单。
    if (not re.search(r'[A-Za-z][A-Za-z0-9+.\-]*://', s)
            and not re.search(r'(?:^|\s)//', s)):
        cand = None
        for tok in _tokens_of_line(s):
            if '//' in tok or tok.endswith('/'):
                cand = tok
                break
        if cand is None and ('//' in s or re.search(r'/[/\s]*$', s)):
            # 分词会把结尾那个孤零零的 `/` 丢掉 (`10.0.0.1/` → token 是 `10.0.0.1`),
            # 这时能拿到的最诚实的串就是整行, 不能因为片段里没斜杠就静默。
            cand = s
        if cand is not None:
            head = cand.split('/')[0]
            hint = (f'要放行整段请把掩码写全, 如 {head}/24'
                    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', head)
                    else '要放行整段请把地址与掩码写全, 如 10.0.0.0/24')
            return f'斜杠写法不完整 ({cand}) 没有当成网段, {_taken_phrase(nets)}; {hint}'
    # 兜底点名: 写法里明明有范围, 结果却只剩左端这一个 IP —— 说明右端没被认出来。
    # 以前这类行 (10.0.0.0-255/24、10.0.0.1-*、10.0.0.1/24-255、10.0.0.1/33-10.0.0.5/33) 全静默,
    # 名单写错了也看不出来, 等于把白名单悄悄缩成一个 IP。
    m3 = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-$', s)
    if m3:
        return (f'范围右端是空的 ({s}), 现只按 {m3.group(1)} 算 1 个 IP; '
                f'请删掉结尾的 - 或写成 {m3.group(1)}-<末段数字>')
    # 剩下的形状检查逐**写法**跑, 不拿整行去套: 一行写两条范围时
    # (`127.168.10.1~29,10.0.0.1~5`) 整行套正则会把第一条的右端读成 `29,10.0.0.1-5`,
    # 于是报出一句根本没发生的「右端没有被识别成范围」—— 假点名和静默一样有害,
    # 用户会回头去改一条本来没写错的名单 (而那条改完还是这个结果)。
    for tok in (_tokens_of_line(s) or [s]):
        note = _literal_token_note(tok, nets)
        if note:
            return note
    return None


def _huge_mask_reason(body):
    """
    `1.1.1.1/0`、`10.1.1.1/4` 这种「地址 + 极小前缀」: 掩码把你写下的地址整个归零,
    一个笔误就是 4294967296 个地址 —— 这是本工具唯一还能「一行放大到全网」的入口。
    前缀是照写的, 所以这一行照常参与匹配 (和「按字面量收窄」一样只是写法提示),
    但必须点名说清变成了多少 IP。
    除 `/0~/8` 外也管「写了一个地址 + 比 C 段还大的掩码」(`10.1.1.77/16`):
    那位 `77` 是白写的, 一归零就是 65536 个。`x.x.x.x/24` 这类「点 + C 段」是
    「这台机器所在网段」的常见顺手写法, 量级只有一个数量级, 不点名, 免得淹没真正要看的行。
    跳过 `0.0.0.0/0`、`10.0.0.0/8` 这类本来就写在网络地址上的行: 那是显式表达, 不是笔误。
    """
    for tok in _tokens_of_line(body):
        m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$', tok)
        if m:
            host, pfx = m.group(1), int(m.group(2))
            label = f'前缀 /{pfx}'
        else:
            # 子网掩码写法同样是掩码: `10.0.0.5/0.0.0.0` 就是 `/0` → 整张互联网,
            # `10.0.0.5/255.0.0.0` 就是 `/8` → 1677 万个。过去只查 `/N` 写法, 掩码写法静默。
            m2 = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', tok)
            if not m2:
                continue
            host = m2.group(1)
            try:
                pfx = ipaddress.IPv4Network('0.0.0.0/' + m2.group(2)).prefixlen
            except ValueError:
                continue
            label = f'掩码 /{m2.group(2)} (即 /{pfx})'
        if pfx > 23:
            continue
        try:
            net = ipaddress.IPv4Network('%s/%d' % (host, pfx), strict=False)
        except ValueError:
            continue
        if int(ipaddress.IPv4Address(host)) == int(net.network_address):
            continue
        if pfx <= 8:
            share = 100.0 * net.num_addresses / (2 ** 32)
            return (f'{label} 把 {host} 归零成 {net} ({net.num_addresses} 个 IP, '
                    f'占整张 IPv4 的 {share:.4g}%), 不是你写下的那个地址; '
                    f'这一行照常参与匹配, 请确认掩码没写错')
        return (f'{label} 把 {host} 归零成 {net} ({net.num_addresses} 个 IP, '
                f'比你写下的那一个地址多 {net.num_addresses - 1} 个), '
                f'这一行照常参与匹配; 只要这一个 IP 请写 /32')
    return None


def _net_reading(nets):
    """
    行实际被识别成了什么: 返回 (例子串, 进名单的 IP 数)。
    数量按**并集**算, 不是逐段求和: `10.0.0.1-10.0.0.5/28` 展开是 5 个互相重叠的 /28,
    求和得 17, 而真正进名单的只有 16 个 —— 提示报 17 就是虚报, 人拿去对账永远对不上。
    段数很多时也一样按并集报: 以前为了省时间, 超过 200 段就直接求和,
    于是重叠越多报得越离谱 (300 个相同的 /24 会说成 76800 个)。并成区间只要排序 +
    一次扫描 (_ip_intervals), 65536 段实测 0.18 秒, 没有省这个时间的必要。
    """
    shown = '、'.join(format_network(n) for n in nets[:3]) + ('…' if len(nets) > 3 else '')
    return shown, _ips_total(nets)


def _noise_reading(nets):
    """
    脏行提示必须报出**真实展开量**。以前不管行内是 `10.0.0.0/24` 还是 `10.0.0.1`,
    提示一律写「已按内嵌 IP xxx 识别」, 于是名单里悄悄进了 256 个 IP 而人只看到 1 个。
    """
    shown, tot = _net_reading(nets)
    if tot == len(nets):
        return f'整行含文字，已按内嵌 IP {shown} 识别，请确认没挖错'
    return (f'整行含文字，已按行内写法 {shown} 识别 (共 {tot} 个 IP)，'
            f'请确认挖出来的就是你要的那几个')


def _taken_phrase(nets):
    """提示语里的「这一行实际进了多少 IP」—— 一律按真实网段算, 不写死数字"""
    shown, tot = _net_reading(nets)
    if tot == 1:
        return f'现只按 {shown} 算 1 个 IP'
    return f'现按行内写法 {shown} 识别 (共 {tot} 个 IP)'


def _leading_zero_reading(body):
    """
    `010.1.1.1` / `10.0.0.01/24`: 把「哪一串带前导 0」和「按十进制读是多少」点名。
    仍然不替你改 (`010` 既可能是手滑多打个 0, 也可能是八进制的 8, 猜哪个都是凭空放行),
    但给个可对照的字面形式比举一个跟本行无关的例子有用。
    """
    for tok in _tokens_of_line(_normalize_input(body)):
        core, sep, tail = tok.partition('/')
        segs = core.split('.')
        if len(segs) != 4 or not all(re.match(r'^\d+$', g) for g in segs):
            continue
        if not any(len(g) > 1 and g[0] == '0' for g in segs):
            continue
        fixed = '.'.join(g.lstrip('0') or '0' for g in segs)
        return (f'{tok} 段里有前导 0, 八进制有歧义故不识别; '
                f'按十进制读像 {fixed}{sep}{tail}, 但没替你换成它 —— 请确认后重写')
    return None


def _star_after_slash_reading(body):
    """
    斜杠后写的是通配符而不是掩码 (`10.0.0.0/*`、`192.168.1.0/x`):
    两种读法差 8 个数量级 —— `10.0.0.0/*` 既像「整个 C 段」(那该写 10.0.0.*),
    也像「掩码那一栏忘了填」(那按 /32 收只覆盖一个地址)。不猜, 但要说是哪一种个都不给。
    """
    s = _normalize_input(str(body)).strip()
    m = re.search(r'/([*xX])$', s)
    if not m or not re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s[:m.start()]):
        return None
    head = s[:m.start()]
    return (f'{s} 斜杠后面是通配符不是掩码, 整行未参与匹配; '
            f'想放行整段请写 {head.rsplit(".", 1)[0]}.* 或 {head}/24, '
            f'只想放行这一个地址请把斜杠和 {m.group(1)} 一起删掉')


def _path_line_reading(body):
    """
    整行是文件路径 / 共享目录 / file:// 地址时, 说清「这一行不是资产地址」。
    路径里的 `10.0.0.5` 是目录名或文件名, 不收集是对的; 但以前只有一句
    「疑似 IP/网段写法有误」—— 人会反复去改那个地址, 而它本来就没写错,
    该行压根不该进名单。这一条把「为什么不收」和「怎么才收」一次说清。
    """
    s = str(body).strip()
    if _SCHEME_RE.match(s) and not _PATH_SCHEME_RE.match(s):
        return None          # 正常的 http:// 之类是 URL, 由 URL 分支管
    if _PATH_SCHEME_RE.match(s):
        kind = 'file:// 本地路径'
    elif _WIN_PATH_RE.match(s):
        kind = 'Windows 文件路径'
    elif _UNC_PATH_RE.match(s):
        kind = 'UNC 共享路径'
    elif _DIR_PATH_RE.match(s):
        kind = '多级目录路径'
    else:
        return None
    return (f'这一行是{kind}, 不是资产地址: 路径里的四段数字是目录名/文件名, '
            f'整行未参与匹配; 真要放行那个地址, 请把它单独写成一行 (如 10.0.0.5)')


def _userinfo_stripped_reading(body):
    """URL 带账号口令时说一句: 判定看 host, 口令不会跟着进结果区/导出文件。
    提示语本身也不能复述口令 —— 那句话同样会显示在结果区里。"""
    s = str(body).strip()
    m = _URL_USERINFO_RE.match(s)
    if not m:
        return None
    stripped = _URL_USERINFO_RE.sub(lambda mm: mm.group(1), s)
    return (f'这一行是带账号口令的 URL, 口令已从结果区和导出文件里剥掉, '
            f'按 {stripped} 识别; 账号口令不是资产, 请把它从清单里删掉, '
            f'留在里面只会泄露给下一个拿到清单的人')


# 一个片段「像是想写地址」: 段与段之间有确切的点 (`10.0.0/24`、`203.0.113`、`1.*.2`)。
# 纯数字 (`80`、`24`) 不算 —— 那是端口或 URL 路径, 本来就不该进名单, 点名只会淹没真消息。
_ADDRISH_RE = re.compile(r'\d\.\d|\d\.\*|\*\.\d')

# 但「纯数字自成一条」是另一回事: read_lines 只按硬分隔符 (逗号/顿号/分号/竖号/制表符) 切条,
# 所以切出来一段只剩数字 (`10.0.0.1，30` 里的 `30`), 就是名单里少了一条, 而不是地址后面跟了端口。
# 空格不算: 既有口径里 `10.0.0.1 80` 是「地址 + 备注/端口」, 逐条点名会把备注列全拖进核对区。
_TAIL_NUMBER_RE = re.compile(r'^(\d{1,3})(?:[ \t]*[-~][ \t]*(\d{1,3}))?$')


def _ipish_failure_chain(body, nets=None):
    """
    「这一写法为什么没进名单」的原因生成链。find_unrecognized 的整行分支和
    `_dropped_fragment_reason` 的片段分支共用同一条链, 免得同一个写法在两处给出不同的说法
    (口径分裂时, 人按其中一句去改, 改完还是不收)。
    """
    return (_cidr_range_overflow_reading(body)
            or _combo_cap_reading(body)
            or _five_segment_reading(body)
            # `*` 开头要在数段之前说: 分词会把开头的 `*` 丢掉, 剩下
            # `0.0/8` 这种半截, 数出来的是「段数不够」而不是「通配符写错了位置」。
            or _star_led_reading(body)
            # 路径行要在数段之前说: `C:\data\10.0.0.5.log` 数出来的是「段数不对/写法有误」,
            # 而真正的原因是「这一行根本不是地址」。
            or _path_line_reading(body)
            or _spaced_dots_reading(body)
            or _bare_fragment_reading(body, nets)
            # 段数不够要先于「非法前缀」: `1.1.1/2` 的 `/2` 合法但只有 3 段,
            # 说成前缀问题会让人以为补齐第 4 段就行。
            or _segment_count_reading(body, nets)
            or _star_after_slash_reading(body)
            or _noncontig_mask_reading(body)
            or _multi_value_seg_reading(body, nets)
            or _star_mask_clash_reading(body, nets)
            or _cidr_pair_reason(body, nets)
            or _oversized_octet_in_range(body)
            or '疑似 IP/网段写法有误')


def _bare_tail_number_reading(frag, nets, head='', with_count=True):
    """
    `10.0.0.1，30` / `10.0.0.1、999`: 硬分隔符切出来的一条只剩一个数字。
    它既可能是端口/序号, 也可能是漏写了前三段的地址末段 —— 替它补成 `10.0.0.30`
    就是凭空放行一个没人写全的地址 (多算一个 IP 就等于越界一个 IP), 不补又静默少收一个:
    过去这里一个字都不说, 名单里 1 个 IP、清单上写了 2 条, 核对授权的人看不出差额。
    所以只点名、不换算, 并且把「没当成哪个地址」写清楚, 由人决定那串数字是什么。
    `head` 是同一行里最近一条写全四段的地址的前三段 —— 有它才谈得上「补成哪个地址」,
    没有它就只是「一个孤立的数字」, 不许拿 0.0.0.x 或上一行的前缀去凑。
    """
    m = _TAIL_NUMBER_RE.match(str(frag).strip())
    if not m:
        return None
    lo, hi = m.group(1), m.group(2)
    tail = ('; ' + _taken_phrase(nets)) if nets and with_count else ''

    def _full(seg):
        # 前导 0 的段换成十进制就是替人做了八进制/十进制的选择, 不给例子
        if not head or len(seg) > 1 and seg[0] == '0' or int(seg) > 255:
            return None
        return '%s.%s' % (head, seg)

    if hi is None:
        if len(lo) > 1 and lo[0] == '0':
            return (f'分隔符右侧只剩一个数字 {lo}, 带前导 0 时连它是十进制还是八进制都说不准, '
                    f'没当成任何地址的末段{tail}; 要收那个地址请单独成行把四段写全')
        if int(lo) > 255:
            return (f'分隔符右侧只剩一个数字 {lo}, 一段地址最大是 255, 它当不成任何一段, '
                    f'没当成任何地址{tail}; 那若是端口或序号请删掉, 若是指某个地址请写全四段')
        fix = _full(lo)
        if fix:
            return (f'分隔符右侧只剩一个数字 {lo}, 没当成 {fix}: 一个裸数字既可能是端口/序号, '
                    f'也可能是漏写了前三段的地址末段, 补成哪个都是凭空放行一个没人写全的地址'
                    f'{tail}; 要收它请单独成行写 {fix}')
        return (f'分隔符右侧只剩一个数字 {lo}, 没当成任何地址 (左边没有写全四段的地址可参照)'
                f'{tail}; 要收它请单独成行把四段写全')
    a, b = _full(lo), _full(hi)
    if a and b:
        return (f'分隔符右侧只剩 {lo}-{hi} 两个没有前缀的数字, 没当成 {a}-{b}: 末段范围补不出前三段, '
                f'凭空放大成一段就是把没人写过的地址放进名单{tail}; 要收这段请写完整两端 {a}-{b}')
    return (f'分隔符右侧只剩 {lo}-{hi} 两个没有前缀的数字, 没当成任何地址 (左边没有写全四段的地址可参照)'
            f'{tail}; 要收这段请把范围两端各自写成完整四段')


def _dropped_fragment_reason(body, nets, already=''):
    """
    同一行里「写了却没进名单」的片段。
    `10.0.0/24,10.0.1.0/24` 里前一条是三段 CIDR, 按既定口径整条不收 (不补点、不造段);
    可名单侧照旧收了后一条, 于是前一条既不在名单里也没被点名 —— 单写 `10.0.0/24` 时
    「未识别检查」会说要补齐第 4 段, 混在一行里写就完全没人说。
    少放行一个 /24 和凭空放行一个 /24 一样危险, 核对授权的人从名单里看不出来。
    `already` 是本行已经说出去的那半句: 里面已经点过名的片段不再重复一遍,
    否则同一句话会出现两次, 而其中一次还带着说反了的「整行未参与匹配」。
    """
    s = str(body)
    if not re.search(r'[ \t,，、;；|]', s):
        return None                 # 单写法行: 整行分支本来就会把它整个说清
    subs = read_lines(s, is_text=True)
    lost = []                       # [(片段, 专用说明或 None: None 走通用链)]
    seen = set()
    head = ''                       # 最近一条写全四段的地址前三段 (给裸数字当参照)
    bare_done = False               # 全行数量只报一次, 免得每段裸数字后面都跟一句
    for sub in subs:
        if not sub.strip():
            continue
        one = sub.strip()
        if _TAIL_NUMBER_RE.match(one):
            # 整条只剩一个数字: 它两边都是硬分隔符 (read_lines 就是按这些切开的),
            # 所以是「少了一条名单」而不是「地址后面跟了个端口」—— 后者 (`10.0.0.1 80`)
            # 切不出独立的一条, 不会被点名。
            if one not in seen and one not in already:
                seen.add(one)
                lost.append((one, _bare_tail_number_reading(one, nets, head,
                                                          with_count=not bare_done)))
                bare_done = True
            continue
        if _nets_of_line(sub):
            toks = _tokens_of_line(sub)
            for t in toks:
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', t) \
                        and all(int(g) <= 255 for g in t.split('.')):
                    head = t.rsplit('.', 1)[0]
            if len(toks) < 2:
                continue
            cand = [t for t in toks if not _try_parse_networks(t)]
        else:
            cand = [sub]
        for frag in cand:
            f = str(frag).strip()
            if not f or f in seen or f in already or not _ADDRISH_RE.search(f):
                continue
            seen.add(f)
            lost.append((f, None))
    # 落在两条名单之间的孤立分隔符: `1.1.1.1<TAB>-<TAB>2.2.2.2` 里 tab 是「一列一条」,
    # 所以这一行不会拼成范围 (那是 1684 万个地址的凭空放行方向)。不拼是对的,
    # 但「没拼」这件事过去一个字都不说 —— 名单里 2 个地址, 看的人以为自己写了范围。
    seps = [x.strip() for x in subs
            if re.match(r'^[-~～〜–－—]{1,2}$', x.strip())]
    seps = [x for x in seps if x not in already]
    if not lost and not seps:
        return None
    bits = []
    for f, why in lost[:3]:
        if why is None:
            why = (_bad_octet_reading(f) or _bad_mask_reading(f)
                   or _ambiguous_wildcard_range_reading(f)
                   or _ipish_failure_chain(f, nets))
        bits.append(f'{f} —— {why}')
    if seps and nets:
        tot = sum(n.num_addresses for n in nets)
        bits.append('%d 个范围分隔符落在两条名单之间 (制表符按「一列一条」切), '
                    '范围没有拼起来, 这一行现按 %d 个 IP 算; '
                    '要写范围请把中间的制表符换成空格' % (len(seps), tot))
    n_lost = len(lost) + (1 if seps and nets else 0)
    more = f'; 另有 %d 处同类写法' % (n_lost - 3) if n_lost > 3 else ''
    return ('同行还有 %d 处写法没进名单: %s%s' % (n_lost, '; '.join(bits), more))


def find_unrecognized(lines):
    """
    挑出「需要人工确认」的行, 返回 [(原始行, 原因)]。注释行与空行跳过。
    八类 (见 unrec_kind):
      1) 无法识别 —— 解析不出 IP 也不是合法域名 (笔误 256.1.1.1 / IPv6 / 垃圾文本 / 全通配 /
         段值超出 0-255), 这类行不参与名单匹配;
      2) 非法前缀 —— 1.1.1.1/33 这类掩码笔误, 整行不参与匹配 (不是"按单个 IP 识别");
      3) 整行含噪声 —— sadhsajgd127.0.0.1 / v110.1.1.1, IP 是从乱码里挖出来的,
         按挖出的那个地址参与判定, 但结果区只输出那个地址而不是原始脏行;
      4) 按字面量收窄 —— 10.10.83/84/85.0 只算 3 个 IP, 不替谁扩成 C 段;
      5) 范围结尾缩写 —— 192.168.0.1-0.254 补成 192.168.0.254, 补出来要人看一眼;
      6) 范围两端写反 —— 198.51.100.10-198.51.100.5 仍按两端之间识别,
         但 255.255.255.255-0.0.0.0 一交换就是整张网, 必须说清变成了多少个 IP;
      7) 覆盖过大 —— 1.1.1.1/0 这类「地址 + 极小前缀」, 掩码把写下的地址归零成整张互联网,
         照常参与匹配, 但量级必须说清。
      8) 同行有写法未进名单 —— `10.0.0/24,10.0.1.0/24` 里前一条按口径不收, 后一条照常进了
         名单; 单写那一条时会被点名, 混在一行写过去是静默少一片, 所以照样要点名。
    这些过去全部静默, 名单写错、资产被误认都看不出来。
    """
    out = []
    for raw in lines:
        s = str(raw).strip()
        # 与 read_lines 同口径: 先把 `~`/`～`/`–`/`..`/`到` 这类范围写法归一成 `-`,
        # 否则 `127.168.10.1~29` 会被当成「整行含噪声」, 而它其实是正常范围
        body = _normalize_input(re.sub(r'#.*$', '', s).strip())
        if not body or body.startswith('#'):
            continue
        # 以 `*` 开头的写法在分词阶段就被丢掉 (分词只捞数字开头的片段), 所以必须在这里点名,
        # 否则「诊断说识别了、名单里却没有这一条」——`*.*.*.*` 尤其危险, 它字面等于整张网。
        segs0 = body.split('.')
        if (body == '*'
                or (len(segs0) >= 2 and segs0[0] in ('*', 'x', 'X')
                    and all(re.match(r'^(\d{1,3}|[*xX])$', g) for g in segs0))):
            # 首段就是通配符 (`*.*.*.*` / `x.x.x.x` / `*.1.2.3`): 名单里它一条都不会进
            if not re.search(r'\d', body):
                out.append((s, '全通配写法没有替你放大 (字面等于整张互联网); '
                               '要放行全网请显式写 0.0.0.0/0, 这行未参与匹配'))
            else:
                out.append((s, _combo_cap_reading(body) or _star_led_reading(body)
                            or '以 * 开头的写法未参与匹配; 通配符请写在数字段上, 如 10.*.2.3'))
            continue
        # 行内到底识别成什么, 一律走 _nets_of_line —— 它和建名单是同一条流水线,
        # 所以提示语里的数量与名单里真正装进去的数量必然一致 (不会少报越界)。
        # 但在那之前先把「段值超出 0-255 / 十六进制段」单独点名:
        # 这类行过去会被兜底正则截成另一个合法 IP (1.1.1.2024 → 1.1.1.202), 既不报错也不越界,
        # 只是**认错了一个地址**, 白名单里等于凭空放行一个没人写过的 IP。
        bad_oct = _bad_octet_reading(body)
        if bad_oct:
            out.append((s, bad_oct))
            continue
        # 掩码尾部粘字母 (`/1abc`) 与负数掩码 (`/-1`) 同属「掩码写得不是数字」:
        # 不点名的话 `/1abc` 会被读成 `/1` —— 一行放行半张互联网。
        bad_mask = _bad_mask_reading(body)
        if bad_mask:
            out.append((s, bad_mask))
            continue
        # 范围两端的 `*` 不在末尾: 两种读法差几十倍, 解析层已经不猜, 这里把两种量级说清
        amb_star = _ambiguous_wildcard_range_reading(body)
        if amb_star:
            out.append((s, amb_star))
            continue
        nets = _nets_of_line(body)
        # 掩码笔误先单独点名: 这一片段整条都不参与匹配, 说成「收窄」会让人以为它还在名单里
        bad_pref = _bad_prefix_reason(body, partial=bool(nets))
        if bad_pref:
            out.append((s, bad_pref))
            continue
        if nets:
            glued = _glued_bracket_fragments(body)
            extra = ('; ' + _glued_bracket_hint(glued)) if glued else ''
            # 纯 IP 写法 (含分隔符/端口) 与 URL 都是正常输入, 不用提示
            if _is_clean_ip_line(body):
                note = (_literal_reading_note(body) or _huge_mask_reason(body)
                        or _userinfo_stripped_reading(body))
            else:
                note = _noise_reading(nets) + extra
            # 行里其余部分进了名单, 但同一段文字里还有写法整条落空 —— 也要点名,
            # 否则「名单里 1 条、清单上写了 2 条」这种差异在结果区完全看不出来。
            dropped = _dropped_fragment_reason(body, nets, note or '')
            if dropped:
                note = (note + '; ' + dropped) if note else dropped
            if note:
                out.append((s, note))
            continue
        if _DOMAIN_RE.match(s) or _DOMAIN_RE.match(extract_host(s) or ''):
            continue
        if ':' in s and re.search(r'[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,}', s):
            out.append((s, '暂不支持 IPv6'))
        elif _has_leading_zero(body):
            # `010.1.1.1` 在 IPv4 里有八进制歧义 (Python 直接拒), 不猜、不自动改, 只把原因说清楚
            out.append((s, _leading_zero_reading(body)
                        or '段里有前导 0 (如 010.1.1.1), 八进制有歧义故不识别; 请写成 10.1.1.1'))
        elif re.search(r'\d', s):
            glued = _glued_bracket_fragments(body)
            if glued:
                out.append((s, _glued_bracket_hint(glued)))
            else:
                out.append((s, _ipish_failure_chain(body, nets)))
        else:
            out.append((s, '既不是 IP 也不是域名'))
    return out


_DIAG_MAX = 40


# 诊断原因分八类, 汇总提示要按类说清楚, 不能把「按字面量收窄」也笼统叫「无法识别」
_UNREC_KINDS = (('bad', '无法识别'), ('prefix', '非法前缀'),
                ('noise', '整行含噪声'), ('narrow', '按字面量收窄'),
                ('partial', '同行有写法未进名单'),
                ('suffix', '范围结尾缩写'), ('reversed', '范围两端写反'),
                ('huge', '覆盖过大'))


def unrec_kind(reason):
    """把 find_unrecognized 的原因归到 narrow / partial / prefix / noise / suffix / reversed / huge / bad"""
    r = str(reason)
    if '非法' in r:
        return 'prefix'
    if '归零' in r:
        return 'huge'
    if '写反' in r:
        return 'reversed'
    if '范围结尾' in r:
        return 'suffix'
    if ('按字面量识别' in r or '五段写法' in r or '没有被识别' in r
            or '现只按左侧' in r or '范围没有展开' in r or '斜杠写法不完整' in r):
        return 'narrow'
    if '整行含文字' in r:
        return 'noise'
    # 放在最后: 这类原因常常是接在噪声/收窄提示后面的半句,
    # 前面那句才是这一行的主要问题, 不能被「同行还有」抢走分类。
    if '同行还有' in r:
        return 'partial'
    return 'bad'


def unrec_summary(unrec):
    """'4 行需人工核对 (无法识别 2、按字面量收窄 1、整行含噪声 1)'"""
    cnt = {}
    for _, reason in unrec:
        cnt[unrec_kind(reason)] = cnt.get(unrec_kind(reason), 0) + 1
    parts = ['%s %d' % (label, cnt[k]) for k, label in _UNREC_KINDS if cnt.get(k)]
    return '%d 行需人工核对 (%s)' % (len(unrec), '、'.join(parts))


def diag_label(s):
    """
    诊断区 (未识别检查 / [注意] 提示 / CLI stderr) 里怎么称呼一行。
    结果区是可以「复制结果」「导出」的, 所以能挖出 IP 的行只报那个 IP,
    不把整条命令行 / 本地路径抄进去; 完全解析不出的行才截断显示原文。
    路径行单独一条分支: 它解析不出 IP, 走不到「噪声行」那条路, 于是原文被整个抄进
    提示语 —— 而提示语显示的正是结果区那块文本, 也会被人复制走, 泄露环境和噪声行一样。
    """
    if _is_path_line(s):
        forms = [x for x in _line_display_forms(s) if x != str(s)]
        if forms:
            return 'IP ' + '、'.join(forms[:3]) + '（整行是路径，原文已省略）'
        return '本地路径（原文已省略）'
    if is_noise_line(s):
        forms = [x for x in _line_display_forms(s) if x != str(s)]
        if forms:
            return 'IP ' + '、'.join(forms[:3]) + '（整行含无关文字，原文已省略）'
    t = str(s)
    return t if len(t) <= _DIAG_MAX else t[:_DIAG_MAX] + '…'


def find_unrecognized_numbered(lines, numbers=None):
    """
    同 find_unrecognized, 但带上行号, 方便回到输入框定位那一行。
    `numbers` 省略时按 lines 自己的下标从 1 起编号 (GUI 一行一条喂进来的场景, 行为不变);
    传入时必须与 lines 等长, 那是 read_lines_numbered/read_lines_with_numbers 给的**物理行号**:
    read_lines 会把一行里的 `,，、;；|` 与制表符拆成好几条, 拿拆完的下标当行号,
    一行写三个地址就能把「第 1 行」的笔误报成「第 2 行」—— 人回到文件改的是另一条,
    改完还是没收, 提示等于把人往错的那一行引。
    """
    if numbers is None:
        pairs = list(enumerate(lines, 1))
    else:
        nums = list(numbers)
        pairs = list(zip(nums, lines)) if len(nums) == len(lines) else list(enumerate(lines, 1))
    out = []
    for i, s in pairs:
        for line_, reason in find_unrecognized([s]):
            out.append((i, line_, reason))
    return out


def _networks_overlap(a, b):
    """判断两个IPv4网段是否有交集 (含包含/相等/部分重叠)."""
    try:
        return a.overlaps(b)
    except Exception:
        return False


# ═══════════════════════════════════════════
#  提取IP列表 (从输入行)
# ═══════════════════════════════════════════

def extract_ips_from_source(source, is_text=False):
    """
    从输入源提取所有IP地址 (展开网络段 ≤ /24, 更大的段本身入列不展开)。
    走统一口径 _nets_of_line: 以前先 extract_host(行) 再解析, host 会在空格/逗号处截断,
    `10.0.0.0/24 (内网)` 只剩 10.0.0.0 一个 (少 255 个), `1.1.1.1,2.2.2.2` 只剩第一个。
    """
    ips = []
    for line in read_lines(source, is_text):
        for n in _nets_of_line(line):
            if n.num_addresses == 1:
                ips.append(str(n.network_address))
            elif n.num_addresses <= 256:
                ips.extend(str(ip) for ip in n)
            else:
                ips.append(str(n))
    return ips


# ═══════════════════════════════════════════
#  核心操作
# ═══════════════════════════════════════════

def _nets_are_private(nets):
    """
    「这一条是不是内网」跟着条目走: 整段必须**完整落在某一个**内网/保留段里才算。
    以前只看两端点: `0.0.0.0/0` 的两端 (0.0.0.0 与 255.255.255.255) 在 Python 眼里
    都属于保留段, 于是「排除内网」把整张 IPv4 当成内网删掉, `1.1.1.1/1` 也一样 ——
    一行半张互联网, 中间几十亿个公网地址一个都没被留住, 结果区里悄无声息。
    跨界的 (`10.0.0.0/8` 里还有公网那半片) 同样不算内网 —— 按一半算会把公网资产删掉。
    """
    if not nets:
        return False
    for n in nets:
        try:
            net = n if isinstance(n, ipaddress.IPv4Network) else ipaddress.IPv4Network(n)
        except Exception:
            return False
        if not any(net.subnet_of(b) for b in _INTERNAL_BLOCKS):
            return False
    return True


def _line_is_internal(line):
    """
    判断一行 (单IP / 范围 / CIDR / 通配符 / 枚举段 / 带文字前缀如ip127.0.0.1) 是否属于内网.
    范围/CIDR 要求整个网段都落在内网地址空间才算内网.
    域名/无法识别 → False.
    一行写了几个独立地址时这里给的是整行结论, 逐条结论走 filter_internal (同一份
    `_line_forms_and_nets`), 免得「整行算公网、行里那个内网地址却被留在公网堆里」。
    """
    # 与名单匹配走同一个解析口径 (_nets_of_line): 先按原始行解析 (枚举段 10.10.83/84/85.0、
    # 掩码写法、行内注释都不会被截断), 失败才退回 extract_host。
    return _nets_are_private(_nets_of_line(line))


def _clean_ip_text(line, nets):
    """
    生成干净的存储文本 (存白名单/黑名单用).
    一行只写了一个地址/一个范围时, 存用户自己的写法 (去掉不可见杂质后的样子) ——
    名单是用户要盯着看的, `127.168.10.1~29` 拆成 8 行 CIDR 反而看不懂,
    而且读回来是同一批地址 (`_nets_of_line` 就是判定入口), 不存在精度差别。
    一行写了多个地址、或整行夹着无关文字时, 才拆成一条条干净的单地址/单网段。
    """
    s = line.strip()
    if nets and len(_tokens_of_line(s)) == 1 and not is_noise_line(s):
        cand = _display_line(s, nets)
        if cand and '\n' not in cand and _nets_of_line(cand) == nets:
            return cand
    parts = []
    for n in nets:
        if n.num_addresses == 1:
            parts.append(str(n.network_address))
        else:
            parts.append(str(n))
    return '\n'.join(parts)


def filter_internal(lines):
    """
    排除内网IP, 保留公网 + 域名 (支持 单IP/范围/CIDR/嵌入文字; 噪声行只输出内嵌 IP)。
    逐条判定: `aaa10.0.0.1 8.8.8.8` 里的 10.0.0.1 进 removed、8.8.8.8 留在 kept ——
    旧实现按整行下一个结论, 行里有一个公网地址就把内网那条一起留在「公网」结果里,
    反过来「仅内网」也会把它整个丢掉 (内网资产凭空消失)。
    """
    kept, removed = [], []
    for line in lines:
        for form, ns in _line_forms_and_nets(line):
            (removed if _nets_are_private(ns) else kept).append(form)
    return kept, removed


def filter_only_internal(lines):
    """仅保留内网IP (逐条判定, 见 filter_internal)"""
    kept, removed = [], []
    for line in lines:
        for form, ns in _line_forms_and_nets(line):
            (kept if _nets_are_private(ns) else removed).append(form)
    return kept, removed


def dedup_lines(lines):
    """去重, 保留首次出现顺序"""
    seen = set()
    result = []
    dupes = 0
    for line in lines:
        key = line.strip()
        if key not in seen:
            seen.add(key)
            result.append(line)
        else:
            dupes += 1
    return result, dupes


def _maximal_networks(items):
    """
    items: [(IPv4Network, 出现序号)]  (顺序无关, 序号仅用于回显位置)
    返回 [(net, 最小序号)]: 去掉被其它段包含的段, 相邻但不重叠的段各自保留。
    对齐网段两两必「互含或不相交」, 故按 (起始IP, 前缀长度) 排序后单次扫描即可,
    O(n log n) —— 取代原先对每个段线性扫全表的 O(n²) 写法。
    """
    ordered = sorted(items, key=lambda t: (int(t[0].network_address), t[0].prefixlen))
    out = []
    cur_end = -1
    for n, pos in ordered:
        start = int(n.network_address)
        end = start + n.num_addresses - 1
        if start > cur_end:                 # 新极大段
            out.append([n, pos])
            cur_end = end
        elif pos < out[-1][1]:              # 落在当前段内 → 只是可能更早出现
            out[-1][1] = pos
    return [(n, p) for n, p in out]


def dedup_by_network(lines):
    """
    按网段重叠去重, 重叠时保留覆盖更全的网段, 输出紧凑网段列表 (保首次顺序).
    如 0.0.0.0 与 0.0.0.0/16 重叠 → 保留 0.0.0.0/16 (信息更全), 与输入顺序无关.
    无法解析成IP的行 (域名/乱码) 按原样文本判重.
    不变式: len(result) + dupes == 解析出的网段数 + 唯一原样行数.
    """
    net_items = []       # (net, 序号)
    raw_out = {}         # 序号 -> 原样行 (域名/乱码)
    seen_raw = set()
    dupes = 0
    pos = 0
    for line in lines:
        # 走统一口径 _nets_of_line: 以前这里 `_try_parse_networks(整行) + extract_host 兜底`,
        # `10.0.0.0/24 (内网)` 会被兜底成单个 10.0.0.0 —— 去重一次, 白名单从 256 个 IP
        # 缩成 1 个, 下一轮「白名单过滤」就把整个 C 段当外人放行。
        nets = _nets_of_line(line)
        if not nets:
            # 路径行 (C:\logs\10.0.0.5.txt、/var/log/x.log) 一个地址都没写出来, 又不能让
            # 原文进结果区 —— 结果区是要「复制结果」「导出」成资产清单的, 把本地路径抄进去
            # 既没用又泄露环境信息 (README 案例 4 的承诺)。这一行不会静默消失:
            # 「未识别检查」里 `_path_line_reading` 点名说清它为什么没收。
            if _is_path_line(line):
                continue
            key = line.strip()
            if key in seen_raw:
                dupes += 1
            else:
                seen_raw.add(key)
                raw_out[pos] = key
            pos += 1
            continue
        for n in nets:
            net_items.append((n, pos))
            pos += 1

    maxima = _maximal_networks(net_items)
    dupes += len(net_items) - len(maxima)
    out = dict(raw_out)
    for n, p in maxima:
        out[p] = format_network(n)
    return [out[k] for k in sorted(out)], dupes


# ═══════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════

def _warn_unrecognized(label, lines, numbers=None):
    """
    把「需要人工核对」的行提示到 stderr: 无法识别 / 非法前缀 / 整行含噪声 / 按字面量收窄 /
    范围结尾缩写 / 范围两端写反 / 覆盖过大 (见 _UNREC_KINDS).
    这些行原先被静默丢弃 —— 白名单少写一行 ≠ 白名单生效, 漏报比误报更危险, 所以必须出声。
    `numbers` 是与 lines 等长的物理行号 (read_lines_with_numbers 给的): 没有它就只能按
    「拆出来的第几条」报行号, 而用户手里那份文件看到的是第几**行**。
    """
    unrec = find_unrecognized_numbered(lines, numbers)
    if not unrec:
        return 0
    # 中文 Windows 的控制台默认是 cp936(GBK), `⚠` 这类字符不在里面:
    # Python 对 stderr 用 backslashreplace, 用户看到的就是字面量 "\u26a0 输入 ..."。
    # 所以 CLI 输出只用 GBK 里有的字符 (GUI 的 Text 控件走 unicode, 不受影响)。
    print(f"[警告] {label}: {unrec_summary([(s, r) for _, s, r in unrec])}:", file=sys.stderr)
    for i, s, reason in unrec[:10]:
        print(f"    第 {i} 行    {diag_label(s)}    # {reason}", file=sys.stderr)
    if len(unrec) > 10:
        print(f"    … 另有 {len(unrec) - 10} 行", file=sys.stderr)
    noise_n = sum(1 for _, s, _ in unrec if is_noise_line(s))
    if noise_n:
        print(f"  其中 {noise_n} 行整行夹着无关文字, 结果里只输出挖出的内嵌 IP, 原始行不会写进输出",
              file=sys.stderr)
    huge_n = sum(1 for _, _, r in unrec if unrec_kind(r) == 'huge')
    if huge_n:
        print(f"  另有 {huge_n} 行写了极小前缀 (/0~/8): 掩码会把写下的地址归零成大片网段, "
              f"照常参与匹配, 请确认掩码不是笔误", file=sys.stderr)
    return len(unrec)


def cli():
    # 控制台编码兜底: 中文 Windows 的 cmd 默认 cp936(GBK), 而 sys.stdout 用 strict 模式,
    # 任何 GBK 里没有的字符都会抛 UnicodeEncodeError —— 结果已经算好了, 只差最后一步打印,
    # 崩在这里等于白跑。stderr 默认是 backslashreplace, 会把 `⚠` 打成字面量 "\u26a0"。
    # 统一换成 replace: 宁可少一个装饰符号, 也不能崩、不能把转义序列糊到用户脸上。
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(errors='replace')
        except (AttributeError, ValueError):   # 非 TextIOWrapper (被重定向/替换) 时跳过
            pass

    p = argparse.ArgumentParser(description=f'IP Toolbox (IP 工具箱) v{VERSION}')
    p.add_argument('input', nargs='?', help='输入文件')
    p.add_argument('-n', '--no-internal', action='store_true', help='排除内网IP')
    p.add_argument('--only-internal', action='store_true', help='仅保留内网IP')
    p.add_argument('-r', '--range-file', help='白名单/范围文件')
    p.add_argument('--exclude', help='排除范围文件 (黑名单)')
    p.add_argument('--dedup', metavar='FILE2', help='与另一文件查重')
    p.add_argument('--uniq', action='store_true', help='文件内去重')
    p.add_argument('-o', '--output', help='输出文件')
    p.add_argument('-v', '--version', action='version', version=f'{APP_NAME} {VERSION}')
    args = p.parse_args()

    # 完全无参数 → GUI; 给了选项却没有输入 → 明确报错, 不再悄悄弹 GUI
    if not args.input:
        if any((args.no_internal, args.only_internal, args.range_file,
                args.exclude, args.dedup, args.uniq, args.output)):
            p.print_usage(sys.stderr)
            print('错误: 需要输入文件 (不带任何参数才是启动 GUI)', file=sys.stderr)
            sys.exit(2)
        print("无参数启动 GUI...")
        gui()
        return

    # 输入/名单文件读不了 → 报错退出, 不当空文件静默处理
    # (名单读成空 = 白名单过滤把全部行判为「不在名单」, 静默下去会让人以为名单坏了)
    for f in (args.input, args.range_file, args.exclude, args.dedup):
        if not f:
            continue
        if not os.path.exists(f):
            print(f'错误: 文件不存在 → {f}', file=sys.stderr)
            sys.exit(2)
        if not os.path.isfile(f):
            print(f'错误: 这是目录不是文件 → {f}', file=sys.stderr)
            sys.exit(2)
        if not os.access(f, os.R_OK):
            # Excel 打开着的 CSV 会被独占; 这里明确说读不了, 而不是 returning [] 装成功
            print(f'错误: 没有读取权限 (文件可能被 Excel 占用) → {f}', file=sys.stderr)
            sys.exit(2)

    def _load(path, label):
        """
        读名单/输入文件, 返回 (条目列表, 与条目等长的物理行号)。失败必须报错退出,
        不能当成「这个文件是空的」继续跑:
        白名单读成空 → 「保留 0, 移除全部」, 黑名单读成空 → 「一条都没排除」,
        两种结果看起来都完全正常, 却和文件内容正好相反。
        上面那道 os.access 预检挡不住 Excel 的独占锁 (它会说「能读」, 真正 open 才炸),
        所以最终判据是 read_lines(strict=True) 有没有抛出来。
        行号跟着一起返回: 「未识别检查」要说「第 N 行」, 那个 N 得是用户在文件里数出来的
        那一行, 不能是一行拆成几条之后的第几条。
        """
        try:
            return read_lines_with_numbers(path, strict=True)
        except (RuntimeError, OSError) as e:
            print(f'错误: {label}读取失败 → {e}', file=sys.stderr)
            sys.exit(2)

    def _nets_of_file(path, label, raw, nums=None):
        """名单文件 → 网段列表; 一个网段都没解析出来时报错退出 (不给「保留 0」的假结果)"""
        nets = parse_to_networks('\n'.join(raw), is_text=True)
        if not nets:
            print(f'错误: {label}没有解析出任何网段 → {path} (里面的写法一条都没进名单)',
                  file=sys.stderr)
            _warn_unrecognized(f'{label} {path}', raw, nums)
            sys.exit(2)
        return nets

    lines, line_nums = _load(args.input, '输入文件')
    _warn_unrecognized(f'输入 {args.input}', lines, line_nums)
    lines = normalize_lines(lines)      # 噪声行只留内嵌 IP, 不把整条命令行/路径写进结果

    # 去重
    if args.uniq:
        lines, dupes = dedup_lines(lines)
        print(f"去重: {len(lines)} 唯一, {dupes} 重复")

    # 内网过滤
    if args.no_internal and args.only_internal:
        print('错误: -n/--no-internal 与 --only-internal 互相矛盾, 本次按 -n (排除内网) 执行',
              file=sys.stderr)
    if args.no_internal:
        lines, removed = filter_internal(lines)
        print(f"排除内网: 保留 {len(lines)}, 移除 {len(removed)}")
    elif args.only_internal:
        lines, removed = filter_only_internal(lines)
        print(f"仅内网: 保留 {len(lines)}, 移除 {len(removed)}")

    # 范围过滤
    if args.range_file:
        wl_raw, wl_nums = _load(args.range_file, '白名单')
        nets = _nets_of_file(args.range_file, '白名单', wl_raw, wl_nums)
        _warn_unrecognized(f'白名单 {args.range_file}', wl_raw, wl_nums)
        lines, removed = filter_by_networks(lines, nets, keep_in=True)
        print(f"白名单过滤: 保留 {len(lines)}, 移除 {len(removed)}")
    if args.exclude:
        bl_raw, bl_nums = _load(args.exclude, '黑名单')
        nets = _nets_of_file(args.exclude, '黑名单', bl_raw, bl_nums)
        _warn_unrecognized(f'黑名单 {args.exclude}', bl_raw, bl_nums)
        lines, removed = filter_by_networks(lines, nets, keep_in=False)
        print(f"黑名单排除: 保留 {len(lines)}, 移除 {len(removed)}")

    # 查重
    if args.dedup:
        dl, dl_nums = _load(args.dedup, '对比文件')
        _warn_unrecognized(f'对比文件 {args.dedup}', dl, dl_nums)
        nets2 = parse_to_networks('\n'.join(dl), is_text=True)
        if not nets2:
            # 对比文件解析不出任何网段 → 继续跑就会输出「共同 0」, 看起来像"两份没交集",
            # 实际是文件白写了。这跟名单读成空一样, 必须报错退出而不是给个 0。
            print(f'错误: 对比文件没有解析出任何网段 → {args.dedup}', file=sys.stderr)
            sys.exit(2)
        nets1 = parse_to_networks('\n'.join(lines), is_text=True)
        # 旧实现是 `set(展开IP) & set(展开IP)`: 超过 /24 的段不展开, 集合里存的是
        # '10.0.0.0/8' 这种字符串, 于是 文件1 的 10.0.0.1 与 文件2 的 10.0.0.0/8
        # 判成"没交集" —— 明明全覆盖, 共同却是 0。改成按区间求交, 与 GUI 同口径。
        n1 = _ips_total(nets1)
        n2 = _ips_total(nets2)
        common = _ips_intersection_total(nets1, nets2)
        hit_lines, miss_lines = check_overlap(lines, nets2)
        print(f"\n查重: 文件1 {n1} IP | 文件2 {n2} IP")
        print(f"  共同: {common} | 仅1: {n1 - common} | 仅2: {n2 - common}")
        print(f"  命中行: {len(hit_lines)}/{len(lines)} 行 (输出这些行, 未命中 {len(miss_lines)} 行)")
        lines = hit_lines

    # 输出
    if args.output:
        if lines:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(lines) + '\n')
            except OSError as e:
                # 目录、只读位置、父目录不存在、目标被 Excel 占用 —— 都要报错退出,
                # 而不是甩一段 traceback 或打印「输出 →」假装写成功了
                print(f'错误: 无法写入 {args.output} ({type(e).__name__}: {e.strerror})',
                      file=sys.stderr)
                sys.exit(2)
            print(f"输出 → {args.output}")
        else:
            # 结果为空时连文件都不打开: `open(...,'w')` 会先把目标截成 0 字节,
            # 上一次跑出来的清单就这么被一条空结果清掉了 —— 覆盖只该发生在真有新内容时。
            print(f'结果为空, 未改动 {args.output}'
                  f'{" (里面还是上一次的内容)" if os.path.exists(args.output) else " (也没有创建新文件)"}',
                  file=sys.stderr)
            print(f"输出 → {args.output} (结果为空, 未写入也未清空)")
    else:
        # 也包括 --dedup: 上面那句「输出这些行」必须真的输出, 否则用户只看到统计、
        # 命中了哪些行还得再跑一遍加 -o
        for l in lines:
            print(l)


# ═══════════════════════════════════════════
#  GUI
# ═══════════════════════════════════════════

def gui():
    import tkinter as tk
    import tkinter.ttk as ttk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    root.title(f"IP 工具箱 v{VERSION}")

    # 窗口尺寸: 适配屏幕, 保证底部按钮可见 (小屏自动压缩)
    try:
        _sw = root.winfo_screenwidth()
        _sh = root.winfo_screenheight()
    except Exception:
        _sw, _sh = 1920, 1080
    _win_w = min(820, max(800, _sw - 120))
    _win_h = min(760, max(640, _sh - 120))
    root.geometry(f"{_win_w}x{_win_h}")
    root.minsize(800, 640)
    root.resizable(True, True)

    BG = '#f0f0f0'
    root.configure(bg=BG)

    # ── 拖放支持 (可选) ──
    DND = False
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD
        # 如果已导入 tkinterdnd2, 重新创建 root
        root.withdraw()
        root.destroy()
        root = TkinterDnD.Tk()
        root.title(f"IP 工具箱 v{VERSION}")
        root.geometry(f"{_win_w}x{_win_h}")
        root.minsize(800, 640)
        root.resizable(True, True)
        root.configure(bg=BG)
        DND = True
    except ImportError:
        pass

    # 细滚动条样式 (须在 root 确定后配置, 否则 TkinterDnD 重建后样式丢失)
    try:
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Thin.Vertical.TScrollbar', gripcount=0, arrowsize=8, borderwidth=1)
        style.configure('Thin.Horizontal.TScrollbar', gripcount=0, arrowsize=8, borderwidth=1)
    except Exception:
        pass

    # ---- 持久化路径 ----
    WHITE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.ip_tool_whitelist.txt')
    BLACK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.ip_tool_blacklist.txt')

    # ---- 状态 (存原始文本, 实时解析为 networks 用于匹配) ----
    state = {'white_raw': '', 'black_raw': '', 'white_nets': [], 'black_nets': []}

    def _load_raw(path):
        """本地名单可能被我手写/改成 GBK, 编码不能写死 utf-8 (否则启动即崩)。"""
        if not os.path.exists(path):
            return ''
        try:
            return read_text_any_encoding(path)
        except OSError as e:
            pending_load_errors.append(f'{os.path.basename(path)} 读取失败: {e}')
            return ''

    pending_load_errors = []
    state['white_raw'] = _load_raw(WHITE_FILE)
    state['black_raw'] = _load_raw(BLACK_FILE)

    def reload_nets():
        state['white_nets'] = parse_to_networks(state['white_raw'], is_text=True)
        state['black_nets'] = parse_to_networks(state['black_raw'], is_text=True)
    reload_nets()

    def save_lists():
        """名单文件可能被 Excel/编辑器占用 (Windows 常见), 不能静默丢掉用户的名单。"""
        errors = []
        for path, key in ((WHITE_FILE, 'white_raw'), (BLACK_FILE, 'black_raw')):
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(state[key])
            except OSError as e:
                errors.append(f'{os.path.basename(path)}: {e}')
        if errors:
            set_status('名单保存失败 (文件被占用或无写权限): ' + ' | '.join(errors))
            return False
        return True

    LIST_FILETYPES = [("支持格式", "*.txt;*.csv;*.xlsx"), ("文本", "*.txt"),
                      ("CSV", "*.csv"), ("Excel", "*.xlsx"), ("所有", "*.*")]

    def import_list(which, label):
        """名单导入与输入区共用 read_lines: 同一套编码探测 + csv/xlsx 支持。"""
        f = filedialog.askopenfilename(filetypes=LIST_FILETYPES)
        if not f:
            return
        try:
            lines = read_lines(f)
        except Exception as e:
            set_status(f'{label}导入失败: {e}')
            return
        if not lines:
            set_status(f'{label}导入: 文件里没有可用内容')
            return
        key = which + '_raw'
        state[key] = ('\n'.join([state[key], '\n'.join(lines)])
                      if state[key] else '\n'.join(lines))
        reload_nets()
        save_lists()
        refresh_status()
        set_status(f'{label}已导入: {os.path.basename(f)} (+{len(lines)} 行)')

    def _count_ips(nets):
        """计算网络段覆盖的IP总数 (重叠段只算一次, 与结果区统计口径一致: 同一个 _ips_total)"""
        return _ips_total(nets)

    def _format_count(nets):
        """格式化显示: 段数 + IP总数"""
        segs = len(nets)
        ip_count = _count_ips(nets)
        if ip_count >= 100000000:
            ip_str = f"{ip_count/100000000:.1f}亿"
        elif ip_count >= 10000:
            ip_str = f"{ip_count/10000:.1f}万"
        else:
            ip_str = str(ip_count)
        return f"{segs}段 / {ip_str} IP"

    def refresh_status():
        wl_var.set(f"白名单: {_format_count(state['white_nets'])}")
        bl_var.set(f"黑名单: {_format_count(state['black_nets'])}")

    # ---- 主布局 ----
    main = tk.Frame(root, bg=BG)
    main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # ---- Row 0: 标题 ----
    title = tk.Label(main, text="IP 工具箱", font=('Microsoft YaHei', 12, 'bold'), bg=BG)
    title.pack(anchor='w')

    # ---- Row 1: 输入区 ----
    inp_frame = tk.LabelFrame(main, text="输入 (粘贴URL/IP, 支持各种分隔符)", font=('Microsoft YaHei', 8), bg=BG, padx=5, pady=5)
    inp_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 4))

    inp_text = tk.Text(inp_frame, height=8, font=('Consolas', 9), relief='solid', borderwidth=1, wrap=tk.NONE)
    inp_text.grid(row=0, column=0, sticky='nsew')

    # 右键菜单 (复制/粘贴/剪切/全选)
    def _text_menu(event):
        widget = event.widget
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="复制", accelerator="Ctrl+C",
                         command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="粘贴", accelerator="Ctrl+V",
                         command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_command(label="剪切", accelerator="Ctrl+X",
                         command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_separator()
        menu.add_command(label="全选", accelerator="Ctrl+A",
                         command=lambda: widget.tag_add(tk.SEL, "1.0", tk.END))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    inp_text.bind("<Button-3>", _text_menu)

    # 拖放支持
    if DND:
        def on_drop(event):
            file_path = event.data.strip('{}')
            if os.path.isfile(file_path):
                try:
                    lines = read_lines(file_path)
                    inp_text.delete('1.0', tk.END)
                    inp_text.insert('1.0', '\n'.join(lines))
                    set_status(f"已拖入: {file_path} ({len(lines)} 行)")
                except Exception as e:
                    messagebox.showerror("导入错误", str(e))
        inp_text.drop_target_register(DND_FILES)
        inp_text.dnd_bind('<<Drop>>', on_drop)

    # 滚动条 (grid 布局保证可见)
    inp_scroll_x = ttk.Scrollbar(inp_frame, orient=tk.HORIZONTAL, command=inp_text.xview, style='Thin.Horizontal.TScrollbar')
    inp_scroll_y = ttk.Scrollbar(inp_frame, orient=tk.VERTICAL, command=inp_text.yview, style='Thin.Vertical.TScrollbar')
    inp_text.configure(xscrollcommand=inp_scroll_x.set, yscrollcommand=inp_scroll_y.set)
    inp_scroll_y.grid(row=0, column=1, sticky='ns')
    inp_scroll_x.grid(row=1, column=0, sticky='ew')
    inp_frame.grid_rowconfigure(0, weight=1)
    inp_frame.grid_columnconfigure(0, weight=1)

    inp_btn_frame = tk.Frame(inp_frame, bg=BG)
    inp_btn_frame.grid(row=2, column=0, columnspan=2, sticky='ew', pady=(4, 0))

    def import_file():
        f = filedialog.askopenfilename(filetypes=[
            ("支持格式","*.txt;*.csv;*.xlsx"), ("文本","*.txt"), ("CSV","*.csv"), ("Excel","*.xlsx"), ("所有","*.*")])
        if f:
            try:
                lines = read_lines(f)
                inp_text.delete('1.0', tk.END)
                inp_text.insert('1.0', '\n'.join(lines))
                set_status(f"已导入: {f} ({len(lines)} 行)")
            except Exception as e:
                messagebox.showerror("导入错误", str(e))

    def clear_input():
        inp_text.delete('1.0', tk.END)
        set_status("已清空输入")

    tk.Button(inp_btn_frame, text="导入文件", command=import_file, bg='#e0e0e0', relief='flat', padx=12).pack(side=tk.LEFT)
    tk.Button(inp_btn_frame, text="清空", command=clear_input, bg='#e0e0e0', relief='flat', padx=12).pack(side=tk.LEFT, padx=4)

    drop_hint = "支持拖放文件 | .txt .csv .xlsx | 中英文逗号/分号/空格分隔" if DND else "支持 .txt .csv .xlsx | 中英文逗号/分号/空格分隔"
    tk.Label(inp_btn_frame, text=drop_hint, font=('Microsoft YaHei', 7), bg=BG, fg='#999').pack(side=tk.RIGHT)

    # ---- Row 2: 快捷操作 + 名单管理 ----
    mid_frame = tk.Frame(main, bg=BG)
    mid_frame.pack(fill=tk.X, pady=4)

    # 快捷操作按钮
    act_frame = tk.LabelFrame(mid_frame, text="快捷操作", font=('Microsoft YaHei', 8), bg=BG, padx=8, pady=3)
    act_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

    btn_row1 = tk.Frame(act_frame, bg=BG)
    btn_row1.pack(fill=tk.X)
    tk.Button(btn_row1, text="排除内网", command=lambda: do_action('no_internal'), bg='#ff9800', fg='white', relief='flat', padx=7).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_row1, text="仅内网", command=lambda: do_action('only_internal'), bg='#ff9800', fg='white', relief='flat', padx=7).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_row1, text="去重", command=lambda: do_action('dedup'), bg='#2196f3', fg='white', relief='flat', padx=7).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_row1, text="保留重复", command=lambda: do_action('keep_dup'), bg='#e91e63', fg='white', relief='flat', padx=7).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_row1, text="提取IP", command=lambda: do_action('extract'), bg='#2196f3', fg='white', relief='flat', padx=7).pack(side=tk.LEFT, padx=2)

    btn_row2 = tk.Frame(act_frame, bg=BG)
    btn_row2.pack(fill=tk.X, pady=(2, 0))
    tk.Button(btn_row2, text="在白名单中", command=lambda: do_action('in_white'), bg='#4caf50', fg='white', relief='flat', padx=7).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_row2, text="在黑名单中", command=lambda: do_action('in_black'), bg='#f44336', fg='white', relief='flat', padx=7).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_row2, text="不在白名单", command=lambda: do_action('not_white'), bg='#4caf50', fg='white', relief='flat', padx=7).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_row2, text="不在黑名单", command=lambda: do_action('not_black'), bg='#f44336', fg='white', relief='flat', padx=7).pack(side=tk.LEFT, padx=2)
    # 名单里写错的行会被静默跳过 —— 给一个入口把「根本没被识别」的行列出来
    tk.Button(btn_row2, text="未识别检查", command=lambda: do_action('unrecognized'), bg='#9e9e9e', fg='white', relief='flat', padx=7).pack(side=tk.LEFT, padx=2)

    # 白名单 / 黑名单 管理
    list_frame = tk.Frame(mid_frame, bg=BG)
    list_frame.pack(side=tk.RIGHT, padx=(10, 0))

    # 白名单
    wl_frame = tk.LabelFrame(list_frame, text="白名单", font=('Microsoft YaHei', 9), bg=BG, padx=6, pady=2)
    wl_frame.pack(fill=tk.X, pady=(0, 2))

    wl_var = tk.StringVar(value=f"白名单: {len(state['white_nets'])} 段")
    tk.Label(wl_frame, textvariable=wl_var, font=('Microsoft YaHei', 9), bg=BG, anchor='w').pack(side=tk.LEFT, expand=True, fill=tk.X)

    def import_white():
        import_list('white', '白名单')

    def view_white():
        show_popup("白名单", state['white_raw'], 'white')

    def clear_white():
        if messagebox.askyesno("确认", f"清空白名单?"):
            state['white_raw'] = ''
            state['white_nets'] = []
            save_lists()
            refresh_status()
            set_status("白名单已清空")

    def _net_covered_by(nets, net):
        """net is fully covered by some existing network (or equal)"""
        return any(net.subnet_of(n) for n in nets)

    def collect_new_entries(source_text, cover_nets):
        """
        「把输入加进名单」的唯一口径 —— 主窗口「+当前」(白/黑) 和弹窗「从输入添加」
        三处都走这里, 只留一份判定逻辑。
        为什么必须收成一个函数: 弹窗那版以前直接喂 `extract_ips_from_source`, 它把每个
        ≤/24 的网段摊平成一个个单 IP, 于是一点下去编辑器多出 258 行、`114.114.114.0/24`
        这个用户自己的紧凑写法凭空消失, 而且它不看编辑器里已有什么, 再点一次就是 515 行
        重复, 保存后名单文件也变成 515 行。同一个按钮文案、两套口径, 用户无从判断哪份是真。
        这里逐行 `_nets_of_line` (带中文标注的 `10.0.0.0/24 (内网)` 也解析得出来, 不会
        静默跳过), `_clean_ip_text` 保住用户原本的写法, 已被 cover_nets 覆盖的跳过,
        source_text 内部按解析结果去重 —— 所以同一段内容点第二次必然是 0 新增。
        """
        seen = set()
        added = []
        for line in read_lines(source_text, is_text=True):
            nets = _nets_of_line(line)
            if not nets:
                continue
            key = tuple(str(n) for n in nets)
            if key in seen:
                continue
            seen.add(key)
            if all(_net_covered_by(cover_nets, n) for n in nets):
                continue
            added.append(_clean_ip_text(line, nets))
        return added

    def add_input_to_white():
        inp = inp_text.get('1.0', 'end-1c').strip()
        if not inp:
            return
        added_lines = collect_new_entries(inp, state['white_nets'])
        if added_lines:
            add_text = '\n'.join(added_lines)
            state['white_raw'] = state['white_raw'] + ('\n' if state['white_raw'] else '') + add_text
            reload_nets()
            save_lists()
            refresh_status()
            set_status(f"已加入白名单: +{len(added_lines)} 条 (已去重, 总计 {_format_count(state['white_nets'])})")
        else:
            set_status("没有新IP需要添加 (输入重复或已在白名单中)")

    tk.Button(wl_frame, text="导入", command=import_white, bg='#e8e8e8', relief='flat', padx=4, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=1)
    tk.Button(wl_frame, text="+当前", command=add_input_to_white, bg='#c8e6c9', relief='flat', padx=4, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=1)
    tk.Button(wl_frame, text="查看", command=view_white, bg='#e8e8e8', relief='flat', padx=4, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=1)
    tk.Button(wl_frame, text="清空", command=clear_white, bg='#ffcdd2', relief='flat', padx=4, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=1)

    # 黑名单
    bl_frame = tk.LabelFrame(list_frame, text="黑名单", font=('Microsoft YaHei', 9), bg=BG, padx=6, pady=2)
    bl_frame.pack(fill=tk.X)

    bl_var = tk.StringVar(value=f"黑名单: {len(state['black_nets'])} 段")
    tk.Label(bl_frame, textvariable=bl_var, font=('Microsoft YaHei', 9), bg=BG, anchor='w').pack(side=tk.LEFT, expand=True, fill=tk.X)

    def import_black():
        import_list('black', '黑名单')

    def view_black():
        show_popup("黑名单", state['black_raw'], 'black')

    def clear_black():
        if messagebox.askyesno("确认", f"清空黑名单?"):
            state['black_raw'] = ''
            state['black_nets'] = []
            save_lists()
            refresh_status()
            set_status("黑名单已清空")

    def add_input_to_black():
        inp = inp_text.get('1.0', 'end-1c').strip()
        if not inp:
            return
        added_lines = collect_new_entries(inp, state['black_nets'])
        if added_lines:
            add_text = '\n'.join(added_lines)
            state['black_raw'] = state['black_raw'] + ('\n' if state['black_raw'] else '') + add_text
            reload_nets()
            save_lists()
            refresh_status()
            set_status(f"已加入黑名单: +{len(added_lines)} 条 (已去重, 总计 {_format_count(state['black_nets'])})")
        else:
            set_status("没有新IP需要添加 (输入重复或已在黑名单中)")

    tk.Button(bl_frame, text="导入", command=import_black, bg='#e8e8e8', relief='flat', padx=4, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=1)
    tk.Button(bl_frame, text="+当前", command=add_input_to_black, bg='#ffcdd2', relief='flat', padx=4, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=1)
    tk.Button(bl_frame, text="查看", command=view_black, bg='#e8e8e8', relief='flat', padx=4, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=1)
    tk.Button(bl_frame, text="清空", command=clear_black, bg='#ffcdd2', relief='flat', padx=4, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=1)

    refresh_status()

    # ---- 威胁情报查询 (微步 ThreatBook / AbuseIPDB) ----
    TI_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.ip_tool_threatbook_key.txt')
    ABUSE_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.ip_tool_abuseipdb_key.txt')
    TI_SOURCE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.ip_tool_ti_source.txt')

    def _read_file(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read().strip()
        except Exception:
            return ''

    ti_key = _read_file(TI_KEY_FILE)
    abuse_key = _read_file(ABUSE_KEY_FILE)
    ti_source = _read_file(TI_SOURCE_FILE) or 'threatbook'

    ti_frame = tk.LabelFrame(main, text="威胁情报查询 (情报源可切换)", font=('Microsoft YaHei', 8),
                             bg=BG, padx=8, pady=2)
    ti_frame.pack(fill=tk.X, pady=(4, 0))

    # Row 0: 情报源选择
    ti_row0 = tk.Frame(ti_frame, bg=BG)
    ti_row0.pack(fill=tk.X, pady=(2, 0))
    tk.Label(ti_row0, text="情报源:", font=('Microsoft YaHei', 8), bg=BG).pack(side=tk.LEFT)
    ti_source_var = tk.StringVar(value=ti_source)
    tk.Radiobutton(ti_row0, text="微步 ThreatBook", variable=ti_source_var, value='threatbook',
                   bg=BG, activebackground=BG, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=5)
    tk.Radiobutton(ti_row0, text="AbuseIPDB (免费1000/天)", variable=ti_source_var, value='abuseipdb',
                   bg=BG, activebackground=BG, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=5)

    # Row 1: 微步 API Key
    ti_row1 = tk.Frame(ti_frame, bg=BG)
    ti_row1.pack(fill=tk.X, pady=(2, 0))
    tk.Label(ti_row1, text="微步Key:", font=('Microsoft YaHei', 8), bg=BG).pack(side=tk.LEFT)
    ti_key_var = tk.StringVar(value=ti_key)
    tk.Entry(ti_row1, textvariable=ti_key_var, font=('Consolas', 9),
             relief='solid', borderwidth=1, show='*').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

    def _save_key(path, value, name):
        """
        Key 落盘: 目录里同名的是文件夹、文件被别的程序占用、路径只读 —— 这些都得在状态栏
        说清楚, 而不是把 traceback 甩在界面上 (同文件里 save_lists 早就包了 OSError, 只有
        Key 这两颗按钮是裸 open)。状态栏永远不回显 Key 本身。
        """
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(value)
            try:
                os.chmod(path, 0o600)    # 凭据文件只让本人可读 (Windows 上近似)
            except OSError:
                pass
            set_status(f'{name} 已保存')
            return True
        except OSError as e:
            set_status(f'{name} 保存失败: {type(e).__name__}: '
                       f'{getattr(e, "strerror", None) or e}')
            return False

    def save_ti_key():
        _save_key(TI_KEY_FILE, ti_key_var.get().strip(), 'ThreatBook API Key')

    tk.Button(ti_row1, text="保存", command=save_ti_key, bg='#e0e0e0', relief='flat', padx=6,
              font=('Microsoft YaHei', 8)).pack(side=tk.RIGHT)

    # Row 2: AbuseIPDB API Key
    ti_row2 = tk.Frame(ti_frame, bg=BG)
    ti_row2.pack(fill=tk.X, pady=(2, 0))
    tk.Label(ti_row2, text="AbuseKey:", font=('Microsoft YaHei', 8), bg=BG).pack(side=tk.LEFT)
    ti_abuse_key_var = tk.StringVar(value=abuse_key)
    tk.Entry(ti_row2, textvariable=ti_abuse_key_var, font=('Consolas', 9),
             relief='solid', borderwidth=1, show='*').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

    def save_abuse_key():
        _save_key(ABUSE_KEY_FILE, ti_abuse_key_var.get().strip(), 'AbuseIPDB API Key')

    tk.Button(ti_row2, text="保存", command=save_abuse_key, bg='#e0e0e0', relief='flat', padx=6,
              font=('Microsoft YaHei', 8)).pack(side=tk.RIGHT)

    # Row 3: 选项 + 查询按钮
    ti_row3 = tk.Frame(ti_frame, bg=BG)
    ti_row3.pack(fill=tk.X, pady=(2, 0))

    ti_skip_priv = tk.BooleanVar(value=True)
    tk.Checkbutton(ti_row3, text="跳过内网", variable=ti_skip_priv, bg=BG, activebackground=BG,
                   font=('Microsoft YaHei', 8)).pack(side=tk.LEFT)
    ti_skip_white = tk.BooleanVar(value=True)
    tk.Checkbutton(ti_row3, text="跳过白名单", variable=ti_skip_white, bg=BG, activebackground=BG,
                   font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=(10, 0))
    tk.Label(ti_row3, text="批量自动并发(≤5)", font=('Microsoft YaHei', 7), bg=BG,
             fg='#999').pack(side=tk.LEFT, padx=(10, 0))

    def do_ti_query():
        inp = inp_text.get('1.0', 'end-1c').strip()
        if not inp:
            set_status('请先在输入区粘贴IP!')
            return

        source = ti_source_var.get()
        if source == 'abuseipdb':
            key = ti_abuse_key_var.get().strip()
            if not key:
                set_status('请先填写并保存 AbuseIPDB API Key')
                return
            platform = 'AbuseIPDB'
            build = build_abuseipdb_detail
        else:
            key = ti_key_var.get().strip()
            if not key:
                set_status('请先填写并保存 ThreatBook API Key')
                return
            platform = '微步 ThreatBook'
            build = build_threatbook_detail

        # 记住情报源选择
        try:
            with open(TI_SOURCE_FILE, 'w', encoding='utf-8') as f:
                f.write(source)
        except Exception:
            pass

        # 只提取单个IP (不展开CIDR, 省配额)
        ips = extract_single_ips(inp, is_text=True)
        skip_priv = ti_skip_priv.get()
        skip_white = ti_skip_white.get()
        to_query = []
        for ip in ips:
            if skip_priv and is_private(ip):
                continue
            if skip_white and ip_in_networks(ip, state['white_nets']):
                continue
            to_query.append(ip)

        if not to_query:
            set_status('没有需要查询的IP (全部被跳过)')
            return

        set_status(f'正在查询 {len(to_query)} 个IP ({platform})...')

        out_text.tag_configure('ti_mal', foreground='#d32f2f')
        out_text.tag_configure('ti_sus', foreground='#f57c00')
        out_text.tag_configure('ti_clean', foreground='#388e3c')
        out_text.tag_configure('ti_err', foreground='#888888')

        out_text.delete('1.0', tk.END)
        out_text.insert(tk.END, f'威胁情报查询 ({platform}) — 共 {len(to_query)} 个IP\n')
        out_text.insert(tk.END, f'{"="*70}\n')

        # 后台线程查询, 避免阻塞 UI; 结果经队列回传主线程渲染
        import queue as _queue
        import threading as _threading
        result_q = _queue.Queue()

        def _worker():
            try:
                results = query_batch(to_query, key, source=source, max_workers=5)
                result_q.put(results)
            except Exception as e:
                result_q.put([(ip, None, f'查询异常: {e}') for ip in to_query])

        def _render():
            try:
                results = result_q.get_nowait()
            except _queue.Empty:
                root.after(100, _render)
                return

            mal_count = clean_count = sus_count = err_count = 0
            for ip, info, err in results:
                if err:
                    err_count += 1
                    out_text.insert(tk.END, f'{ip}\n', 'ti_err')
                    for el in err.split('\n'):
                        out_text.insert(tk.END, f'  {el}\n', 'ti_err')
                    out_text.insert(tk.END, '\n')
                    continue
                verdict, lines = build(info)
                if verdict == 'malicious':
                    mal_count += 1
                    tag = '恶意'
                    tag_name = 'ti_mal'
                elif verdict == 'suspicious':
                    sus_count += 1
                    tag = '可疑'
                    tag_name = 'ti_sus'
                else:
                    clean_count += 1
                    tag = '良好'
                    tag_name = 'ti_clean'
                out_text.insert(tk.END, f'{ip}   [判定: {tag}]\n', tag_name)
                for el in lines:
                    out_text.insert(tk.END, f'  {el}\n', tag_name)
                out_text.insert(tk.END, '\n')

            out_text.insert(tk.END, f'{"="*70}\n')
            out_text.insert(tk.END, f'统计: 恶意 {mal_count} | 可疑 {sus_count} | 良好 {clean_count} | '
                                    f'失败 {err_count} | 共 {len(to_query)}\n')
            out_count_var.set(f"共 {len(to_query)} 个IP (恶意{mal_count} 可疑{sus_count} 良好{clean_count} 失败{err_count})")
            set_status(f'威胁情报查询完成: 恶意 {mal_count}, 可疑 {sus_count}, '
                       f'良好 {clean_count}, 失败 {err_count}')
            ti_query_btn.config(state=tk.NORMAL)

        ti_query_btn.config(state=tk.DISABLED)
        _threading.Thread(target=_worker, daemon=True).start()
        root.after(100, _render)

    ti_query_btn = tk.Button(ti_row3, text="威胁情报查询", command=do_ti_query, bg='#7b1fa2', fg='white', relief='flat',
              font=('Microsoft YaHei', 8), padx=12)
    ti_query_btn.pack(side=tk.RIGHT)

    # ---- Row 4: 查重模式 ----
    cmp_frame = tk.Frame(main, bg=BG)
    cmp_frame.pack(fill=tk.X, pady=2)

    tk.Label(cmp_frame, text="查重:", font=('Microsoft YaHei', 8), bg=BG).pack(side=tk.LEFT)
    cmp_var = tk.StringVar(value='white')
    tk.Radiobutton(cmp_frame, text="vs 白名单", variable=cmp_var, value='white', bg=BG, activebackground=BG, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=5)
    tk.Radiobutton(cmp_frame, text="vs 黑名单", variable=cmp_var, value='black', bg=BG, activebackground=BG, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=5)
    tk.Radiobutton(cmp_frame, text="vs 文件", variable=cmp_var, value='file', bg=BG, activebackground=BG, font=('Microsoft YaHei', 8)).pack(side=tk.LEFT, padx=5)

    def _ip_sort_key(x):
        """排序键: 交给模块级 ip_sort_key (CIDR / URL / 噪声行都不崩)"""
        return ip_sort_key(x)

    def do_cross_dedup(want='dup'):
        # want: 'dup' = 查重(输出在名单里的)  'notdup' = 查不重(输出不在名单里的)
        # 按原始行分类, 域名/非IP 视为不在名单 (保留原行, 不丢失)
        mode = cmp_var.get()
        inp = inp_text.get('1.0', 'end-1c').strip()
        if not inp:
            set_status("请先输入IP!")
            return

        lines = read_lines(inp, is_text=True)

        if mode in ('white', 'black'):
            target_nets = state['white_nets'] if mode == 'white' else state['black_nets']
            label = "白名单" if mode == 'white' else "黑名单"
            # 与「快捷操作·在白/黑名单中」判定一致: 行解析出的网段与名单有交集即算"在"
            dup_lines, notdup_lines = check_overlap(lines, target_nets)
        else:
            f = filedialog.askopenfilename(filetypes=LIST_FILETYPES)
            if not f:
                return
            # 与 vs 白/黑名单、快捷操作、CLI -r 走同一个 check_overlap:
            # 旧写法是 `extract_host(行) in 文件IP集合` 的精确匹配, 名单里写
            # `127.168.10.1~29` / `10.0.0.0/24` 时, 单个 IP 行永远判不成"在名单里",
            # 同一个问题在两个按钮上给出两个答案。
            target_nets = parse_to_networks(f)
            label = "文件 " + os.path.basename(f)
            if not target_nets:
                set_status(f"⚠ {os.path.basename(f)} 没解析出任何网段, 无法查重 "
                           f"(空文件/编码不支持/内容不是IP写法)")
                return
            dup_lines, notdup_lines = check_overlap(lines, target_nets)

        out_text.delete('1.0', tk.END)

        if want == 'notdup':
            # 计算展开后的实际IP总数 (处理CIDR/范围行)
            notdup_ips = count_expanded_ips('\n'.join(notdup_lines), is_text=True)
            out_text.insert(tk.END, f"查不重 (不在{label}中) — {len(notdup_lines)} 行 / {notdup_ips} 个IP\n")
            out_text.insert(tk.END, f"{'='*50}\n")
            for line in sorted(notdup_lines, key=_ip_sort_key):
                out_text.insert(tk.END, line + '\n')
            out_count_var.set(f"共 {len(notdup_lines)} 行 / {notdup_ips} 个IP")
            set_status(f"查不重: {len(notdup_lines)} 行 / {notdup_ips} 个IP, 不在{label}中")
        else:
            dup_ips = count_expanded_ips('\n'.join(dup_lines), is_text=True)
            out_text.insert(tk.END, f"查重 (在{label}中) — {len(dup_lines)} 行 / {dup_ips} 个IP\n")
            out_text.insert(tk.END, f"{'='*50}\n")
            for line in sorted(dup_lines, key=_ip_sort_key):
                out_text.insert(tk.END, line + '\n')
            out_count_var.set(f"共 {len(dup_lines)} 行 / {dup_ips} 个IP")
            set_status(f"查重: {len(dup_lines)} 行 / {dup_ips} 个IP, 在{label}中")

        # 噪声行按内嵌 IP 判定并输出, 这里点名哪些行被改写过, 免得以为结果丢了行
        if mode in ('white', 'black'):
            noise = [l for l in lines if is_noise_line(l)]
            if noise:
                sample = '、'.join(diag_label(x) for x in noise[:3])
                out_text.insert(tk.END, f'\n[注意] {len(noise)} 行整行夹着无关文字, '
                                        f'已按内嵌 IP 参与{label}比对并只输出 IP: {sample}\n'
                                        f'       点「未识别检查」查看全部。')

    tk.Button(cmp_frame, text="查重", command=lambda: do_cross_dedup('dup'), bg='#e91e63', fg='white', relief='flat', padx=10, font=('Microsoft YaHei', 9)).pack(side=tk.LEFT, padx=5)
    tk.Button(cmp_frame, text="查不重", command=lambda: do_cross_dedup('notdup'), bg='#4caf50', fg='white', relief='flat', padx=10, font=('Microsoft YaHei', 9)).pack(side=tk.LEFT, padx=2)

    # 结果操作按钮 (与查重同行, 节省纵向空间)
    out_count_var = tk.StringVar(value="共 0 行 / 0 个IP")

    def copy_result():
        root.clipboard_clear()
        root.clipboard_append(out_text.get('1.0', 'end-1c'))
        set_status("已复制到剪贴板")

    def export_result():
        f = filedialog.asksaveasfilename(defaultextension=".txt",
                                         filetypes=[("文本", "*.txt"), ("CSV", "*.csv"), ("所有", "*.*")])
        if not f:
            return
        try:
            # 带 BOM: 中文 Windows 上双击用 Excel/写字板打开才不会乱码
            with open(f, 'w', encoding='utf-8-sig') as fh:
                fh.write(out_text.get('1.0', 'end-1c'))
        except OSError as e:
            set_status(f'导出失败: {e}')
            return
        set_status(f"已导出: {f}")

    def clear_result():
        out_text.delete('1.0', tk.END)
        out_count_var.set("共 0 行 / 0 个IP")
        set_status("已清除结果")

    tk.Button(cmp_frame, text="清空结果", command=clear_result, bg='#e0e0e0', relief='flat', padx=6, font=('Microsoft YaHei', 9)).pack(side=tk.RIGHT)
    tk.Button(cmp_frame, text="导出", command=export_result, bg='#e0e0e0', relief='flat', padx=6, font=('Microsoft YaHei', 9)).pack(side=tk.RIGHT, padx=2)
    tk.Button(cmp_frame, text="复制结果", command=copy_result, bg='#e0e0e0', relief='flat', padx=6, font=('Microsoft YaHei', 9)).pack(side=tk.RIGHT, padx=2)

    # ---- Row 4: 输出区 ----
    out_frame = tk.LabelFrame(main, text="结果", font=('Microsoft YaHei', 8), bg=BG, padx=5, pady=5)
    out_frame.pack(fill=tk.BOTH, expand=True, pady=(6, 4))

    out_text = tk.Text(out_frame, height=8, font=('Consolas', 9), relief='solid', borderwidth=1, wrap=tk.NONE)
    out_text.grid(row=0, column=0, sticky='nsew')
    out_text.bind("<Button-3>", _text_menu)

    out_scroll_x = ttk.Scrollbar(out_frame, orient=tk.HORIZONTAL, command=out_text.xview, style='Thin.Horizontal.TScrollbar')
    out_scroll_y = ttk.Scrollbar(out_frame, orient=tk.VERTICAL, command=out_text.yview, style='Thin.Vertical.TScrollbar')
    out_text.configure(xscrollcommand=out_scroll_x.set, yscrollcommand=out_scroll_y.set)
    out_scroll_y.grid(row=0, column=1, sticky='ns')
    out_scroll_x.grid(row=1, column=0, sticky='ew')
    out_frame.grid_rowconfigure(0, weight=1)
    out_frame.grid_columnconfigure(0, weight=1)

    # 状态栏
    status_var = tk.StringVar(value="就绪")
    tk.Label(out_frame, textvariable=status_var, font=('Microsoft YaHei', 8), bg=BG, fg='#666').grid(row=2, column=0, columnspan=2, sticky='ew', pady=(4, 0))

    def set_status(msg):
        status_var.set(msg)

    if pending_load_errors:
        set_status('⚠ 本地名单未完全加载: ' + ' | '.join(pending_load_errors))

    # ---- 操作逻辑 ----
    def do_action(action):
        inp = inp_text.get('1.0', 'end-1c').strip()
        if not inp:
            set_status("请先输入IP/URL!")
            return

        # 行号要用输入框里看得见的那一行: `read_lines` 会把一行里的 `,，、;；|` 拆成好几条,
        # 拿拆完的条目下标当行号, `8.8.8.8, 256.1.1.1, 9.9.9.9` 里的笔误就被报成「第 2 行」,
        # 用户回到输入框第 2 行看到的却是干净的 `1.2.3.4` —— 提示指向错行等于没有提示。
        # 条目本身仍出自同一个 `_entries_from_raw`, 与 read_lines 一字不差, 判定不会变。
        lines, line_numbers = read_lines_with_numbers(inp, is_text=True)

        if action == 'no_internal':
            kept, removed = filter_internal(lines)
            out_text.delete('1.0', tk.END)
            out_text.insert(tk.END, '\n'.join(kept))
            out_count = count_expanded_ips('\n'.join(kept), is_text=True)
            out_text.insert(tk.END, f'\n\n[共 {len(kept)} 行 / {out_count} 个IP]')
            out_count_var.set(f"共 {len(kept)} 行 / {out_count} 个IP")
            set_status(f"排除内网: 保留 {len(kept)} 行 / {out_count} 个IP, 移除 {len(removed)}")

        elif action == 'only_internal':
            kept, removed = filter_only_internal(lines)
            out_text.delete('1.0', tk.END)
            out_text.insert(tk.END, '\n'.join(kept))
            out_count = count_expanded_ips('\n'.join(kept), is_text=True)
            out_text.insert(tk.END, f'\n\n[共 {len(kept)} 行 / {out_count} 个IP]')
            out_count_var.set(f"共 {len(kept)} 行 / {out_count} 个IP")
            set_status(f"仅内网: 保留 {len(kept)} 行 / {out_count} 个IP, 移除 {len(removed)}")

        elif action == 'dedup':
            result, dupes = dedup_by_network(lines)
            out_text.delete('1.0', tk.END)
            out_text.insert(tk.END, '\n'.join(result))
            out_count = count_expanded_ips('\n'.join(result), is_text=True)
            out_text.insert(tk.END, f'\n\n[共 {len(result)} 行 / {out_count} 个IP]')
            out_count_var.set(f"共 {len(result)} 行 / {out_count} 个IP")
            set_status(f"去重: {len(result)} 唯一行 / {out_count} 个IP, {dupes} 重复行")

        elif action == 'keep_dup':
            # 按IP重叠判重: 输出重叠部分的交集网段 (如 0.0.0.0 与 0.0.0.0/16 → 0.0.0.0)
            dup_nets = find_overlapping_networks(inp, is_text=True)
            dup_lines = [format_network(n) for n in dup_nets]
            out_text.delete('1.0', tk.END)
            out_text.insert(tk.END, '\n'.join(dup_lines))
            out_count = count_expanded_ips('\n'.join(dup_lines), is_text=True)
            out_text.insert(tk.END, f'\n\n[共 {len(dup_lines)} 行 / {out_count} 个IP]')
            out_count_var.set(f"共 {len(dup_lines)} 行 / {out_count} 个IP")
            set_status(f"重叠IP: {len(dup_lines)} 段 (重叠部分), {out_count} 个IP")

        elif action == 'extract':
            # 展开所有范围 → 完整IP列表
            nets = parse_to_networks(inp, is_text=True)
            all_ips = set()
            total_expanded = 0
            compact_lines = []
            for n in nets:
                if n.num_addresses == 1:
                    all_ips.add(str(n.network_address))
                    compact_lines.append(str(n.network_address))
                elif n.num_addresses <= 256:
                    for ip in n:
                        all_ips.add(str(ip))
                    total_expanded += n.num_addresses
                    # 小范围: 展开所有IP
                    compact_lines.append(f"# {n} ({n.num_addresses} IP)")
                    for ip in n:
                        compact_lines.append(str(ip))
                else:
                    compact_lines.append(f"# {n} ({n.num_addresses} IP, 范围太大不展开)")
                    all_ips.add(str(n))
            out_count = count_expanded_ips(inp, is_text=True)
            out_text.delete('1.0', tk.END)
            out_text.insert(tk.END, '\n'.join(compact_lines))
            out_text.insert(tk.END, f'\n\n[共 {len(compact_lines)} 行 / {out_count} 个IP]')
            out_count_var.set(f"共 {len(compact_lines)} 行 / {out_count} 个IP")
            set_status(f"提取IP: {out_count} 个IP ({len(nets)} 段)")

        elif action in ('in_white', 'in_black', 'not_white', 'not_black'):
            # 四个名单按钮共用一套判定 (与 CLI --whitelist/--exclude 同一个 check_overlap)
            is_white = action in ('in_white', 'not_white')
            want_kept = action in ('in_white', 'in_black')
            list_nets = state['white_nets'] if is_white else state['black_nets']
            list_name = '白名单' if is_white else '黑名单'
            kept, removed = check_overlap(lines, list_nets)
            result = kept if want_kept else removed
            verb = '在' if want_kept else '不在'
            out_text.delete('1.0', tk.END)
            out_text.insert(tk.END, '\n'.join(result))
            out_count = count_expanded_ips('\n'.join(result), is_text=True)
            out_text.insert(tk.END, f'\n\n[共 {len(result)} 行 / {out_count} 个IP]')
            out_count_var.set(f"共 {len(result)} 行 / {out_count} 个IP")
            set_status(f"{verb}{list_name}: {len(result)} 行 / {out_count} 个IP")

        elif action == 'unrecognized':
            # 行号来自输入框的物理行 (见 do_action 开头的 read_lines_with_numbers)
            unrec = find_unrecognized_numbered(lines, line_numbers)
            out_text.delete('1.0', tk.END)
            if not unrec:
                out_text.insert(tk.END, f'全部 {len(lines)} 行都能识别 ✓')
                out_count_var.set("需检查 0 行")
                set_status("未发现需人工核对的行")
                return
            for i, s, reason in unrec:
                out_text.insert(tk.END, f'第 {i} 行    {diag_label(s)}    # {reason}\n')
            out_text.insert(tk.END, f'\n[需检查 {len(unrec)} 行 / 输入共 {len(lines)} 行]')
            out_count_var.set(f"需检查 {len(unrec)} 行")
            set_status(f"⚠ {unrec_summary([(s, r) for _, s, r in unrec])} (见结果区)")
            return

        # 名单/内网筛选后, 把「被静默跳过 / 从噪声里挖出来 / 按字面量收窄」的行提示出来:
        # 白名单写错时不至于毫无察觉
        unrec = find_unrecognized_numbered(lines, line_numbers)
        if unrec:
            sample = '、'.join(diag_label(s) for _, s, _ in unrec[:5])
            more = ' …' if len(unrec) > 5 else ''
            out_text.insert(tk.END,
                            f'\n[注意] {unrec_summary([(s, r) for _, s, r in unrec])}: '
                            f'{sample}{more}\n       点「未识别检查」查看全部。')
            narrow_n = sum(1 for _, _, r in unrec if unrec_kind(r) == 'narrow')
            if narrow_n:
                out_text.insert(tk.END,
                                f'\n       其中 {narrow_n} 行手写多值写法按字面量展开 '
                                f'(几个数字就是几个 IP, 不自动扩成 C 段), 照常参与匹配; '
                                f'要整段请写显式掩码。')
            huge_n = sum(1 for _, _, r in unrec if unrec_kind(r) == 'huge')
            if huge_n:
                out_text.insert(tk.END,
                                f'\n       还有 {huge_n} 行写了极小前缀 (/0~/8): '
                                f'掩码会把你写下的地址归零成大片网段, 一行就可能覆盖整张互联网。'
                                f'照常参与匹配, 但请确认掩码不是笔误。')
            noise_n = sum(1 for _, s, _ in unrec if is_noise_line(s))
            if noise_n:
                out_text.insert(tk.END,
                                f'\n       另有 {noise_n} 行整行夹着无关文字, '
                                f'结果里只输出挖出的内嵌 IP, 原始行不进结果区。')
            set_status(f'⚠ {len(unrec)} 行需检查 · {status_var.get()}')

    # ---- 弹窗 (查看/编辑 名单原始文本) ----
    def show_popup(title_str, raw_text, list_key):
        popup = tk.Toplevel(root)
        popup.title(title_str)
        popup.geometry("580x560")

        pf = tk.Frame(popup)
        pf.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # ---- 搜索栏 ----
        search_frame = tk.Frame(pf)
        search_frame.pack(fill=tk.X, pady=(0, 4))

        tk.Label(search_frame, text="搜索:", font=('Microsoft YaHei', 8)).pack(side=tk.LEFT)
        search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=search_var, font=('Consolas', 9),
                                relief='solid', borderwidth=1)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        match_var = tk.StringVar(value="")
        tk.Label(search_frame, textvariable=match_var, font=('Microsoft YaHei', 7), fg='#666').pack(side=tk.RIGHT)

        # 提示
        lbl = tk.Label(pf, text="支持: 单IP / CIDR / 范围 / 通配符 / 枚举 / 掩码写法 / 中英文逗号分隔"
                               "  (手写多值按字面量展开, 要整段请写 /24 这类掩码)",
                       font=('Microsoft YaHei', 7), fg='#666')
        lbl.pack(anchor='w')

        # ---- 文本编辑器 ----
        popup_text = tk.Text(pf, font=('Consolas', 9))
        popup_text.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        popup_text.bind("<Button-3>", _text_menu)

        # 弹窗打开时的名单快照: 保存时靠它分清「用户在弹窗里删掉的条目」和
        # 「弹窗打开期间主窗口 +当前 新加的条目」 (见 merge_with_snapshot)
        snapshot_text = raw_text
        popup_text.insert('1.0', raw_text)

        # 搜索高亮用的 tag
        popup_text.tag_configure('highlight', background='#ffeb3b')
        popup_text.tag_configure('current_match', background='#ffb74d')
        popup_text.tag_configure('hidden', elide=True)

        # 计数: 文案只有一个来源 —— `_format_count` 本身就返回 "N段 / M IP"。
        # 以前写成 f"共 {len(nets)} 段 / {_format_count(nets)}" → 标签读起来是
        # 「共 3 段 / 3段 / 258 IP」; 而且只在打开时按快照算一次, 用户在弹窗里删到只剩
        # 2 条数字还是一动不动, 保存后又和状态栏的口径对不上。
        count_var = tk.StringVar(value='')
        count_lbl = tk.Label(pf, textvariable=count_var, font=('Microsoft YaHei', 7), fg='#666')
        count_lbl.pack(anchor='w')

        def refresh_count(*_args):
            """编辑器内容一变就按当前文本重算 (insert/delete 都会触发 <<Modified>>)"""
            count_var.set(_format_count(
                parse_to_networks(popup_text.get('1.0', 'end-1c'), is_text=True)))
            popup_text.edit_modified(False)   # 复位脏标记, 下一次改动才还会再触发事件
            return None

        popup_text.bind('<<Modified>>', refresh_count)
        refresh_count()

        # ---- 搜索逻辑 (只高亮, 不隐藏) ----
        # Ctrl+G 是真的「跳到下一个匹配」并滚动过去: 按钮上写着「显示全部(Ctrl+G/ESC)」,
        # 绑定却只是把焦点丢回搜索框, 按下去界面一动不动 —— 文案与行为互相矛盾。
        # ESC 只清搜索与高亮、绝不关窗口: 窗口一关, 用户没点「保存」的编辑就凭空没了。
        match_state = {'keyword': '', 'ranges': [], 'index': -1}

        def collect_matches(keyword):
            """当前文本里 keyword 的全部命中区间 (每次重算: 编辑过的旧下标不可信)"""
            ranges = []
            start_pos = '1.0'
            while True:
                idx = popup_text.search(keyword, start_pos, stopindex=tk.END, nocase=True)
                if not idx:
                    break
                end_idx = f"{idx}+{len(keyword)}c"
                ranges.append((idx, end_idx))
                start_pos = end_idx
            return ranges

        def highlight_matches(keyword):
            popup_text.tag_remove('highlight', '1.0', tk.END)
            popup_text.tag_remove('current_match', '1.0', tk.END)
            ranges = collect_matches(keyword)
            for a, b in ranges:
                popup_text.tag_add('highlight', a, b)
            match_state['keyword'] = keyword
            match_state['ranges'] = ranges
            if match_state['index'] >= len(ranges):
                # 文本被删改过, 命中数变少了: 下标往回夹, 不报「第 7/2 处」这种鬼话
                match_state['index'] = 0 if ranges else -1
            return ranges

        def clear_search_state():
            popup_text.tag_remove('highlight', '1.0', tk.END)
            popup_text.tag_remove('current_match', '1.0', tk.END)
            match_state['keyword'] = ''
            match_state['ranges'] = []
            match_state['index'] = -1
            match_var.set("")

        def do_search(*_args):
            keyword = search_var.get().strip()
            if not keyword:
                # 注意不能在这里再调 reset_search(): 它会 set 同一个 StringVar, 而 Tcl
                # 的 write trace 对「写入同样的值」也照样触发 → 无限递归。
                clear_search_state()
                return
            ranges = highlight_matches(keyword)
            if ranges:
                match_state['index'] = 0
                popup_text.see(ranges[0][0])
                popup_text.tag_add('current_match', *ranges[0])
                match_var.set(f"1/{len(ranges)} 处")
            else:
                match_state['index'] = -1
                match_var.set("0 处匹配")

        def goto_next_match(event=None):
            keyword = search_var.get().strip()
            if not keyword:
                # 没有搜索词时无处可跳, 退回这个快捷键以前唯一的作用: 聚焦搜索框
                search_entry.focus_set()
                return "break"
            ranges = highlight_matches(keyword)
            if not ranges:
                match_state['index'] = -1
                match_var.set("0 处匹配")
                return "break"
            match_state['index'] = (match_state['index'] + 1) % len(ranges)
            start, end = ranges[match_state['index']]
            popup_text.see(start)
            popup_text.tag_add('current_match', start, end)
            match_var.set(f"{match_state['index'] + 1}/{len(ranges)} 处")
            return "break"

        def reset_search():
            """清掉搜索词与高亮 —— 只清搜索, 不 destroy 窗口 (那等于扔掉未保存的编辑)"""
            clear_search_state()
            search_var.set("")

        def on_escape(event=None):
            reset_search()
            return "break"

        search_var.trace('w', do_search)
        # 绑定 Ctrl+F 聚焦搜索框
        popup.bind('<Control-f>', lambda e: search_entry.focus_set())
        popup.bind('<Control-g>', goto_next_match)
        popup.bind('<Escape>', on_escape)
        search_entry.focus_set()

        # ---- 按钮 ----
        btn_f = tk.Frame(pf)
        btn_f.pack(fill=tk.X, pady=(6, 0))

        def merge_with_snapshot(editor_raw):
            """
            弹窗是非模态的 (不 grab_set), 它开着的时候主窗口的「+当前」照样能点, 而且
            当场就落盘。以前保存是 `state[list_key+'_raw'] = 编辑器内容` 一刀切覆盖,
            弹窗打开期间加进去的条目被这份旧快照整个抹掉 —— 实测: +当前 114.114.114.0/24
            → 点「查看」→ +当前 223.5.5.5 (文件里两条俱在) → 弹窗点「保存」→ 文件只剩
            114.114.114.0/24, 223.5.5.5 无声消失, 状态栏还笑眯眯说「已更新」。
            合并规则: 编辑器对「它展示过的那些条目」是权威的, 所以在弹窗里的删改都算数;
            只把「现在的名单里有、快照里没有」的行补回来 —— 那些只可能是弹窗打开期间加的。
            比较用解析出的网段而不是原始字符串: `114.114.114.0/24` 与
            `114.114.114.0/24 (DNS)` 是同一批地址, 按字符串比会把旧条目当成新条目再补一遍。
            解析不出网段的行 (注释/噪声) 不参与合并, 免得把垃圾行来回搬运。
            补回来时也要跳过编辑器里已经写过的那份: 用户在弹窗里手打了 `223.5.5.5`,
            同时又点过「+当前」, 按差集补 would 在同一份名单里写两遍。
            反过来, 若用户在主窗口点了「清空」, 现在的条目比快照还少 → 差集为空 →
            一条都不补, 编辑器说了算: 清空不会被这份快照复活。
            """
            def keys_of(raw):
                return {tuple(str(n) for n in nets)
                        for nets in map(_nets_of_line, read_lines(raw, is_text=True)) if nets}

            # 快照里的 (弹窗展示过、用户可能已经删掉) + 编辑器里已有的 → 都不许再补第二遍
            skip = keys_of(snapshot_text) | keys_of(editor_raw)
            extra, extra_seen = [], set()
            for line in read_lines(state[list_key + '_raw'], is_text=True):
                nets = _nets_of_line(line)
                if not nets:
                    continue
                key = tuple(str(n) for n in nets)
                if key in skip or key in extra_seen:
                    continue
                extra_seen.add(key)
                extra.append(line)
            if not extra:
                return editor_raw
            head = editor_raw.rstrip('\n')
            return '\n'.join(([head] if head.strip() else []) + extra)

        def save_changes():
            # 先合并再落盘, 覆盖式保存会抹掉弹窗打开期间「+当前」的条目 (见 merge_with_snapshot)
            state[list_key + '_raw'] = merge_with_snapshot(popup_text.get('1.0', 'end-1c'))
            reload_nets()
            save_lists()
            refresh_status()
            popup.destroy()
            set_status(f"{title_str}已更新: {_format_count(state[list_key + '_nets'])}")

        def delete_selected():
            try:
                popup_text.get('sel.first', 'sel.last')
                popup_text.delete('sel.first', 'sel.last')
            except tk.TclError:
                line_no = popup_text.index(tk.INSERT).split('.')[0]
                popup_text.delete(f"{line_no}.0", f"{int(line_no)+1}.0")
            refresh_count()   # 计数必须跟着编辑器走, 不能停在打开时那份快照

        def add_from_input():
            editor_raw = popup_text.get('1.0', 'end-1c')
            # 与主窗口「+当前」同一个口径 (collect_new_entries): 保住 `114.114.114.0/24`
            # 这种紧凑写法、跳过已被编辑器覆盖的条目、同一份输入点第二次是 0 新增。
            # 旧写法走 extract_ips_from_source: 一点就是 258 行散 IP 外加一个空行,
            # 再点一次 515 行重复, 保存后名单文件也变成 515 行。
            added = collect_new_entries(inp_text.get('1.0', 'end-1c'),
                                        parse_to_networks(editor_raw, is_text=True))
            if not added:
                # 以前这里什么都不说: 点了「从输入添加」没反应, 谁也不知道是没解析出来
                # 还是按钮坏了。
                set_status('输入里没有可添加的 IP/网段 (没解析出来, 或编辑器里已经有了)')
                return
            reset_search()
            # 编辑器为空时不前置换行: 以前固定 insert(END, '\\n' + ...) 会在开头留一行空白
            popup_text.insert('end-1c',
                              ('\n' if editor_raw.strip() else '') + '\n'.join(added))
            refresh_count()
            set_status(f"已添加 {len(added)} 条到编辑器, 请点保存")

        tk.Button(btn_f, text="保存", command=save_changes, bg='#4caf50', fg='white', relief='flat', padx=12).pack(side=tk.LEFT)
        tk.Button(btn_f, text="删除选中", command=delete_selected, bg='#f44336', fg='white', relief='flat', padx=12).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_f, text="从输入添加", command=add_from_input, bg='#2196f3', fg='white', relief='flat', padx=12).pack(side=tk.LEFT, padx=4)
        # 文案只写它真正做的事: 这颗按钮清搜索词与高亮 (ESC 同), 跳到下一个匹配是 Ctrl+G
        tk.Button(btn_f, text="清除搜索(ESC)", command=reset_search, bg='#e0e0e0', relief='flat', padx=10, font=('Microsoft YaHei', 7)).pack(side=tk.RIGHT)

    # ---- 快捷键 ----
    root.bind('<Control-Return>', lambda e: do_action('no_internal'))

    root.mainloop()


# ═══════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════

if __name__ == '__main__':
    if len(sys.argv) > 1:
        cli()
    else:
        gui()
