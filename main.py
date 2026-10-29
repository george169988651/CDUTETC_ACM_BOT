"""CDUTETC ACM 机器人主程序。

职责：连接 QQ 官方机器人，路由群消息：
  - 命令式操作（/修正、/征集、/报名、/征集汇总、/征集关闭 等）→ commands 模块分发
  - 「发布 <链接/信息>」命令（老师白名单）→ 抓取 → 提取 → 免审 confirmed → @全体通知
  - 非命令消息 → FAQ 自动回复；未命中则收集为未答问题
  - 周期提醒：比赛临近 + 征集登记截止 + 训练开始
  - 周期抓取：公共来源低频抓取（默认关闭）+ 变化检测 + 免审记录（不通知全员）
  - 自动周赛：每周日按模板生成记录并提醒（默认不通知全员，超管确认后处理）

安全要点：
  - 群与发布者白名单默认全拒绝；权限校验先于抓取/调模型/写库。
  - 身份一律取自 SDK 事件字段（group_openid / member_openid），不信消息正文。
  - 提醒/抓取通知按平台权限接入：当前未申请到主动消息权限时为日志模式，
    回调返回 False，不标记去重（不会拿日志冒充已发送）。

扩展指南：
  - 新增消息指令：commands.py 的 handlers 表里加分支
  - 新增定时任务：on_ready 里 self.sched.add_job(...)
"""

import logging

import botpy
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from botpy.message import GroupMessage

import commands
import config
import crawler
import database as db
from database import create_competition, create_published_competition, init_db
from fetcher import FetchError, fetch_text
from llm import extract_contest
from reminder import check_general_reminders, check_reminders
from utils import (
    extract_url,
    is_allowed_group,
    is_publish_command,
    is_teacher,
    strip_at,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("main")


def _build_confirm(info: dict) -> str:
    """构造存档成功后的确认回复。"""
    return (
        "比赛信息已记录~\n"
        f"比赛：{info.get('name') or '未知'}\n"
        f"报名截止：{info.get('reg_deadline') or '待定'}\n"
        f"比赛时间：{info.get('contest_time') or '待定'}\n"
        f"形式/地点：{info.get('mode') or '待定'} {info.get('location') or ''}\n"
        "有问题随时 @ 我！"
    )


class ACMBot(botpy.Client):
    """QQ 官方机器人客户端。"""

    def __init__(self, intents=None):
        super().__init__(intents=intents or botpy.Intents(public_messages=True))
        self.sched: AsyncIOScheduler | None = None

    # ---------- 生命周期 ----------

    async def on_ready(self):
        """登录成功后：初始化数据库、启动定时提醒与公共抓取（幂等）。"""
        if self.sched is not None:
            logger.info("机器人已上线（调度器已存在，跳过重复创建）")
            return
        init_db()
        self.sched = AsyncIOScheduler(timezone=config.TZ_NAME)
        self.sched.add_job(
            self._remind_job,
            "interval",
            minutes=config.REMIND_CHECK_INTERVAL_MINUTES,
            id="remind-check",
        )
        self.sched.add_job(
            self._crawl_job,
            "interval",
            minutes=config.FETCH_MIN_INTERVAL_MINUTES,
            id="source-crawl",
        )
        if config.WEEKLY_CONTEST_ENABLED:
            start_hh, start_mm = config.WEEKLY_CONTEST_START.split(":")
            self.sched.add_job(
                self._weekly_contest_job,
                "cron",
                day_of_week=config.WEEKLY_CONTEST_WEEKDAY,
                hour=int(start_hh),
                minute=int(start_mm),
                id="weekly-contest",
            )
        self.sched.start()
        logger.info(
            "机器人已上线：每 %d 分钟检查提醒，每 %d 分钟抓取公共来源%s",
            config.REMIND_CHECK_INTERVAL_MINUTES,
            config.FETCH_MIN_INTERVAL_MINUTES,
            "，自动周赛已开启（%s %s-%s）" % (
                "周日" if config.WEEKLY_CONTEST_WEEKDAY == 6 else f"星期{config.WEEKLY_CONTEST_WEEKDAY + 1}",
                config.WEEKLY_CONTEST_START,
                config.WEEKLY_CONTEST_END,
            ) if config.WEEKLY_CONTEST_ENABLED else "，自动周赛关闭",
        )

    # ---------- 群消息路由 ----------

    async def on_group_at_message_create(self, message: GroupMessage):
        try:
            group_id = (
                getattr(message, "group_openid", None)
                or getattr(message, "group_id", None)
            )
            if not is_allowed_group(group_id, config.ALLOWED_GROUPS):
                logger.info("非授权群消息已忽略: %s", group_id)
                return
            text = strip_at(message.content)
            if not text:
                return
            member_id = self._extract_member_id(message)
            if is_publish_command(text, config.PUBLISH_CMD):
                await self._handle_publish(message, text, group_id, member_id)
                return
            replies = await commands.handle_command(text, group_id, member_id)
            if replies is None:
                replies = await commands.handle_non_command_message(text, group_id, member_id)
            for reply in replies:
                if reply.get("text"):
                    await self._safe_reply(message, reply["text"])
        except Exception:
            logger.exception("处理群消息失败")
            await self._safe_reply(message, "出错了，稍后再试试~")

    # ---------- 内部处理 ----------

    def _extract_member_id(self, message: GroupMessage) -> str:
        """提取消息成员标识，恒为字符串。

        qq-botpy 1.2.1 真实消息结构中成员标识位于 message.author.member_openid
        （嵌套字段）；旧版/测试消息可能在顶层 member_openid / author_id / author。
        优先读嵌套字段，兼容旧字段兜底，最后统一转字符串。
        """
        author = getattr(message, "author", None)
        if author is not None:
            nested = getattr(author, "member_openid", None)
            if nested is None and isinstance(author, dict):
                nested = author.get("member_openid")
            if nested is not None:
                return str(nested)
        for attr in ("member_openid", "author_id"):
            val = getattr(message, attr, None)
            if val is not None:
                return str(val)
        author_val = getattr(message, "author", None)
        if author_val is not None:
            return str(author_val)
        return ""

    async def _handle_publish(self, message: GroupMessage, text: str,
                              group_id: str, member_id: str):
        """发布命令（v2 免审）：老师权限校验 → 抓取 → 提取 → 校验 → confirmed → @全体通知。"""
        if not is_teacher(member_id):
            await self._safe_reply(message, "抱歉，你没有发布比赛信息的权限~")
            return

        url = extract_url(text)
        if not url:
            await self._safe_reply(
                message, "请带上比赛链接，例如：发布 https://example.com/contest"
            )
            return

        try:
            page = await fetch_text(url)
        except FetchError as e:
            await self._safe_reply(
                message,
                f"链接抓取失败：{e}。可以换个可访问的链接，或直接把比赛信息发给我~",
            )
            return

        info, err = await extract_contest(f"链接正文：{page}\n老师原文补充：{text}")
        if err is not None or not info:
            await self._safe_reply(
                message,
                f"信息提取失败：{err or '未知原因'}。"
                "可以直接告诉我：比赛名称、报名截止/比赛时间（YYYY-MM-DD HH:MM）、形式、地点~",
            )
            return

        info["source_link"] = url
        try:
            # 正式比赛、来源和已抓取正文基线一并提交，供后台检测后续变化。
            create_published_competition(
                {
                    "name": info.get("name", ""),
                    "official_reg_deadline": info.get("reg_deadline", ""),
                    "official_time": info.get("contest_time", ""),
                    "official_rules": info.get("raw_note", ""),
                    "official_site": info.get("source_link", ""),
                    "summary": "",
                },
                source_url=url,
                source_text=page,
                operator=f"publish:{member_id}",
            )
        except ValueError as e:
            await self._safe_reply(message, f"信息校验失败：{e}")
            return

        logger.info("已免审发布比赛: %s（群 %s）", info.get("name"), group_id)
        await self._safe_reply(
            message,
            _build_confirm(info) + "\n已免审发布为正式比赛，并已尝试向全部允许群发送通知。",
        )
        # 全员通知：主动消息权限未开通时为日志模式，如实标注不冒充已发送
        notice = (
            f"【新比赛发布】{info.get('name') or '未知'}\n"
            f"报名截止：{info.get('reg_deadline') or '待定'}\n"
            f"比赛时间：{info.get('contest_time') or '待定'}\n"
            f"来源：{url}\n请及时查看并准备报名~"
        )
        for gid in sorted(config.ALLOWED_GROUPS):
            await self._send_group_log_only(gid, notice)

    async def _safe_reply(self, message: GroupMessage, content: str):
        """回复失败也不影响主流程。"""
        try:
            await message.reply(content=content)
        except Exception:
            logger.exception("回复消息失败")

    # ---------- 定时任务回调 ----------

    async def _send_group_log_only(self, group_id: str, text: str) -> bool:
        """主动消息发送回调（日志模式）。

        未申请到 QQ 开放平台「群主动消息」权限时使用：只记录日志并返回 False，
        上层因此不会标记去重，也不会把日志当作已发送。
        申请权限后替换为真实主动消息接口：发送成功返回 True，失败返回 False。
        """
        logger.info("[主动消息][群 %s] %s", group_id, text)
        return False

    async def _remind_job(self):
        """周期检查提醒：比赛临近 + 征集登记截止 + 训练开始。"""
        await check_reminders(self._send_group_log_only)
        await check_general_reminders(self._send_group_log_only)

    async def _weekly_contest_job(self):
        """自动周赛：每周日按模板生成周赛记录（默认不通知全员）。

        生成前检查本周是否已有同名记录，避免重复；生成记录不主动通知，
        超管确认后再通知全员或 /修正 调整/删除。
        """
        template = config.WEEKLY_CONTEST_TEMPLATE
        for c in db.list_competitions():
            if c.get("name") == template:
                logger.info("本周周赛记录已存在，跳过自动生成（比赛 id=%s）", c["id"])
                return
        start = config.WEEKLY_CONTEST_START
        end = config.WEEKLY_CONTEST_END
        try:
            cid = create_competition(
                {
                    "name": template,
                    "official_reg_deadline": "",
                    "official_time": f"本周日 {start}-{end}",
                    "official_rules": "",
                    "official_site": "",
                    "summary": "自动周赛（模板生成，默认不通知全员）",
                },
                status="confirmed",
                operator="weekly:auto",
            )
        except ValueError as e:
            logger.warning("自动周赛生成失败: %s", e)
            return
        logger.info("已自动生成周赛记录: %s（id=%s），未通知全员", template, cid)

    async def _crawl_job(self):
        """周期抓取公共来源（默认关闭）：变化检测 → 免审记录 → 不通知全员。"""
        await crawler.run_fetch(send_group=self._send_group_log_only)


def run_bot() -> None:
    """启动入口：配置检查 → 构造客户端（Intents）→ run(appid=, secret=)。"""
    config.check_config()
    intents = botpy.Intents(public_messages=True)
    bot = ACMBot(intents=intents)
    bot.run(appid=config.APPID, secret=config.APP_SECRET)


if __name__ == "__main__":
    run_bot()
