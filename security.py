"""提示词注入 / 越狱防护工具：文本清洗、风险分级、限流与输出护栏。

安全约定：
- 这些函数只负责“降低攻击面”，不是权限边界。权限校验、群隔离、写库永远
  不依赖模型输出，也不依赖本模块。
- 任何模型输出都必须经过 ``sanitize_answer`` 才能发到群里。
- 风险规则只用于分流与留痕，不能作为唯一防线；真正的兜底是输出护栏和
  “模型没有工具、不直接写库”。
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

import config

logger = logging.getLogger(__name__)

# 固定话术由服务端提供，绝不使用模型返回的拒答文本。
REFUSE_TEXT = "这个问题我暂时没法确认。可以问我比赛、训练、报名相关的问题，或等老师回复~"
GUARD_FAILED_TEXT = "这个问题我暂时没法确认，可以换个问法，或等老师回复~"
HANDOFF_TEXT = "收到，已记录给老师，稍后回复你~"
RATE_LIMITED_TEXT = "你问得有点快，稍等一分钟再试~"
TOO_LONG_TEXT = f"问题有点长，请精简到 {config.QA_MAX_QUESTION_CHARS} 字以内再问~"

_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u180e\u00ad"))
_BIDI = dict.fromkeys(map(ord, "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"))
# 只归一化全角字母/数字/空格，避免把中文标点“，”“（）”改成半角，
# 那样会破坏比赛名称、备注等展示内容的原貌。
_FULLWIDTH_ALNUM = {
    **{code: code - 0xFEE0 for code in range(0xFF10, 0xFF1A)},
    **{code: code - 0xFEE0 for code in range(0xFF21, 0xFF3B)},
    **{code: code - 0xFEE0 for code in range(0xFF41, 0xFF5B)},
    0xFF20: ord("@"),
    0x3000: ord(" "),
}
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_MULTI_SPACE = re.compile(r"[ \t]+")
_MULTI_NEWLINE = re.compile(r"\n{3,}")
_WS = re.compile(r"\s+")

# 风险规则：名称、权重、正则。权重用于分流，不是“命中即封”。
_RULES = (
    ("override_zh", 5, re.compile(
        r"(忽略|无视|忘记|不要遵守|跳过).{0,12}(之前|以上|前面|系统|所有).{0,12}"
        r"(指令|提示|规则|要求)")),
    ("override_en", 5, re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,40}"
        r"\b(previous|above|prior|system|all)\b.{0,20}"
        r"\b(instructions?|prompts?|rules?)\b", re.I)),
    ("role_hijack", 2, re.compile(
        r"(你现在是|从现在开始你是|扮演|进入.{0,6}(模式|角色)|开发者模式|越狱|"
        r"\bDAN\b|developer mode|jailbreak|act as|pretend to be)", re.I)),
    ("prompt_leak", 5, re.compile(
        r"(系统提示词|初始指令|你的设定|你的提示词|重复.{0,6}(上面|以上)|"
        r"system prompt|initial instructions|repeat.{0,20}(above|prompt))", re.I)),
    ("delimiter_forge", 2, re.compile(
        r"(【存档数据】|<\|?(system|im_start|im_end)\|?>|\[INST\]|"
        r"</?UNTRUSTED|^\s*(system|assistant)\s*:)", re.I | re.M)),
    ("fake_authority", 2, re.compile(
        r"(我是(管理员|老师|超管|系统)|系统通知|管理员通知|官方通知|@全体成员)", re.I)),
    ("encoded", 1, re.compile(
        r"(base64|rot13|十六进制|解码后|decode and (run|execute))", re.I)),
)
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

# 模型复述 system 内容时用于拒绝的静态片段。
_PROMPT_ECHO_FRAGMENTS = (
    "安全规则（最高优先级",
    "UNTRUSTED_DATA_",
    "只输出最终答复",
)
_PROMPT_ECHO_PATTERN = re.compile(
    r"(系统提示词|初始指令|system\s*prompt|initial\s*instructions)", re.I
)

# 伪造通知/模板：这类标记出现在任何位置都拒绝，避免用“你好，【提醒】……”绕过。
_SPOOF_MARKERS = (
    "【提醒】", "【新比赛发布】", "【系统通知】", "【官方通知】",
    "管理员通知", "系统通知", "@全体成员", "@所有人",
)
# 行首模板标记；只检查行首，避免误杀正文里的普通提及。
_SPOOF_LINE_PREFIXES = ("Q：",)
_AT_SEGMENT = re.compile(r"<@!?[^>]*>")
# 一次扫描同时处理完整 URL 和裸域名，避免把已放行 URL 的路径
# （如 /file.html）误判成裸域名。
_LINK_OR_DOMAIN = re.compile(
    r"(https?://[^\s]+)"
    r"|(?<![A-Za-z0-9.-])((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![A-Za-z0-9.-])",
    re.I,
)
_URL_TRAILING = ".,;:!?，。；：！？）)】」》"


def _truncate_excerpt(text: str) -> str:
    # 日志保持单行，避免载荷里的换行伪造出额外的日志行。
    return normalize_untrusted(text, config.SEC_LOG_EXCERPT).replace("\n", " ")


def log_security_event(event: str, *, rules: list[str] | None = None,
                       score: int = 0, group_id: str = "",
                       member_id: str = "", text: str = "") -> None:
    """结构化安全日志：只记录规则名和截断片段，避免日志变成载荷仓库。"""
    logger.warning(
        "event=security decision=%s rules=%s score=%d group=%s member_hash=%s excerpt=%r",
        event,
        ",".join(rules or []) or "-",
        score,
        group_id or "-",
        hashlib.sha256(member_id.encode("utf-8")).hexdigest()[:12] if member_id else "-",
        _truncate_excerpt(text),
    )


def normalize_untrusted(text: str, limit: int) -> str:
    """归一化全角字母数字 + 去除零宽/双向/控制字符 + 压缩空白 + 硬截断。"""
    if not isinstance(text, str):
        return ""
    text = text.translate(_FULLWIDTH_ALNUM)
    text = text.translate(_INVISIBLE).translate(_BIDI)
    text = _CONTROL.sub("", text)
    text = _MULTI_SPACE.sub(" ", text)
    text = _MULTI_NEWLINE.sub("\n\n", text)
    return text.strip()[:limit]


def _defang_notice_markers(text: str) -> str:
    """中和“【提醒】”类模板标记和群发 @，避免字段伪装成独立通知。"""
    for marker in _SPOOF_MARKERS:
        if marker.startswith("【"):
            text = text.replace(marker, "[" + marker[1:-1] + "]")
        elif marker.startswith("@"):
            text = text.replace(marker, marker[0] + " " + marker[1:])
    return text


def defang_notice_markers(text: str) -> str:
    """多行文本（如 FAQ 答案）的模板标记中和，保留原有换行。"""
    return _defang_notice_markers(text) if isinstance(text, str) else ""


def single_line(text: str, limit: int) -> str:
    """用于比赛名称、地点等会进入通知模板的字段：强制单行。"""
    if not isinstance(text, str):
        return ""
    text = normalize_untrusted(text, max(1, limit) * 4)
    text = _WS.sub(" ", text)
    return _defang_notice_markers(text.strip()[:limit])


def assess_risk(text: str) -> tuple[int, list[str]]:
    """返回 (风险分, 命中规则名)。只用于分流、限流和留痕。"""
    score = 0
    hits: list[str] = []
    for name, weight, pattern in _RULES:
        if pattern.search(text):
            score += weight
            hits.append(name)
    if _B64_BLOB.search(text):
        score += 1
        hits.append("encoded_blob")
    return score, hits


def new_nonce() -> str:
    """每次请求生成不可预测的分隔符后缀。"""
    return secrets.token_hex(4)


def wrap_untrusted(label: str, content: str, nonce: str | None = None) -> tuple[str, str]:
    """用随机 nonce 包裹不可信数据，返回 (包裹后的文本, nonce)。

    同时把数据里的半角尖括号换成全角，避免 ``<|im_start|>`` 一类模型特殊
    标记在 tokenizer 层被当成角色控制符；标签本身由本函数在替换后添加。
    """
    safe_label = re.sub(r"[^A-Z0-9_]", "_", (label or "DATA").upper()) or "DATA"
    nonce = nonce or new_nonce()
    content = (content or "").replace("<", "＜").replace(">", "＞")
    return f"<{safe_label}_{nonce}>\n{content}\n</{safe_label}_{nonce}>", nonce


def parse_answer_envelope(content: str) -> tuple[str, str] | None:
    """解析问答 JSON 信封，返回 (kind, text)；任何不合规都返回 None。"""
    if not content or not content.strip():
        return None
    s = content.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    try:
        data = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    kind = data.get("kind")
    text = data.get("text")
    if kind not in ("answer", "refuse", "handoff"):
        return None
    if not isinstance(text, str) or not text.strip():
        return None
    return kind, text.strip()


def sanitize_answer(text: str, allowed_urls: set[str] | None = None,
                    limit: int | None = None) -> tuple[str | None, str | None]:
    """最终输出护栏，返回 (安全文本, 拒绝原因)。

    - 超长/控制字符/零宽字符被清洗或截断；
    - 提示词回显、行首伪造通知直接拒绝；
    - 链接只允许本次存档中逐字出现过的 URL，其余替换为 [链接已省略]。
    """
    limit = limit or config.QA_MAX_ANSWER_CHARS
    allowed = allowed_urls or set()
    text = normalize_untrusted(text, limit * 2)
    text = _AT_SEGMENT.sub("", text)

    if any(fragment in text for fragment in _PROMPT_ECHO_FRAGMENTS):
        return None, "prompt_echo"
    if _PROMPT_ECHO_PATTERN.search(text):
        return None, "prompt_echo"
    if any(marker in text for marker in _SPOOF_MARKERS):
        return None, "spoof_prefix"
    for line in text.splitlines():
        if line.strip().startswith(_SPOOF_LINE_PREFIXES):
            return None, "spoof_prefix"

    allowed_hosts = set()
    for url in allowed:
        try:
            host = urlparse(url).hostname
        except ValueError:
            host = None
        if host:
            allowed_hosts.add(host.lower())

    def replace_link(match: re.Match) -> str:
        url = match.group(1)
        if url:
            url = url.rstrip(_URL_TRAILING)
            return url if url in allowed else "[链接已省略]"
        domain = match.group(2)
        return domain if domain.lower() in allowed_hosts else "[链接已省略]"

    text = _LINK_OR_DOMAIN.sub(replace_link, text).strip()[:limit]
    if not text:
        return None, "empty"
    return text, None


def clean_url(value: str) -> str:
    """数据层 URL 校验：只接受无凭据的 http/https，长度不超过 2000。

    超长链接直接拒绝而不是截断，避免把半截 URL 当成有效来源。
    """
    s = normalize_untrusted(value, 4000).strip()
    if not s:
        return ""
    if len(s) > 2000:
        raise ValueError("链接过长")
    if any(ch.isspace() for ch in s):
        raise ValueError("链接不能包含空白字符")
    parsed = urlparse(s)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("链接必须是 http/https")
    if parsed.username or parsed.password:
        raise ValueError("链接不能包含账号密码")
    if not parsed.hostname:
        raise ValueError("链接缺少主机名")
    return s


class RateLimiter:
    """单进程滑动窗口限流 + 相同文本去重。

    多实例部署时该限流只在单进程内生效；需要跨实例时换成 SQLite/Redis。
    """

    def __init__(self, per_minute: int | None = None, per_hour: int | None = None,
                 dup_window: int | None = None):
        self.per_minute = per_minute if per_minute is not None else config.QA_RATE_PER_MINUTE
        self.per_hour = per_hour if per_hour is not None else config.QA_RATE_PER_HOUR
        self.dup_window = dup_window if dup_window is not None else config.QA_DUP_WINDOW_SECONDS
        self._minute: dict[str, deque[float]] = defaultdict(deque)
        self._hour: dict[str, deque[float]] = defaultdict(deque)
        self._seen: dict[str, float] = {}

    def allow(self, key: str, text: str, now: float | None = None) -> tuple[bool, str]:
        now = time.monotonic() if now is None else now
        digest = hashlib.sha256((text or "").encode("utf-8")).hexdigest()
        seen_key = f"{key}:{digest}"
        last = self._seen.get(seen_key)
        if last is not None and now - last < self.dup_window:
            return False, "duplicate"
        for bucket, window, limit in (
            (self._minute, 60, self.per_minute),
            (self._hour, 3600, self.per_hour),
        ):
            q = bucket[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False, "rate_limited"
        self._minute[key].append(now)
        self._hour[key].append(now)
        self._seen[seen_key] = now
        self._prune(now)
        return True, ""

    def _prune(self, now: float) -> None:
        if len(self._seen) < 5000:
            return
        cutoff = now - self.dup_window
        self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
        for bucket in (self._minute, self._hour):
            for key in list(bucket):
                q = bucket[key]
                while q and now - q[0] > 3600:
                    q.popleft()
                if not q:
                    bucket.pop(key, None)

    def reset(self) -> None:
        """测试/排障用：清空全部窗口。"""
        self._minute.clear()
        self._hour.clear()
        self._seen.clear()


rate_limiter = RateLimiter()
