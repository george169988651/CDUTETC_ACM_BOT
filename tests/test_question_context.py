"""比赛发布到问答上下文的离线回归测试，不访问真实 QQ、网页或模型。"""

import json
import re
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import config
import database
import llm
import main


@pytest.fixture
def memory_db(monkeypatch):
    conn = sqlite3.connect(":memory:")
    monkeypatch.setattr(database, "_connect", lambda: conn)
    database.init_db()
    yield conn
    conn.close()


@pytest.fixture
def bot(memory_db, monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_GROUPS", {"g1", "g2"})
    monkeypatch.setattr(config, "TEACHER_WHITELIST", {"teacher"})
    client = main.ACMBot()
    replies = []

    async def reply(message, content):
        replies.append((message.group_openid, content))

    monkeypatch.setattr(client, "_safe_reply", reply)
    monkeypatch.setattr(client, "_send_group_log_only", AsyncMock(return_value=False))
    return client, replies


def _message(content, group_id="g1", member_id="student"):
    return SimpleNamespace(
        content=content,
        group_openid=group_id,
        author=SimpleNamespace(member_openid=member_id),
    )


def _public(name="正式校赛", **overrides):
    info = {
        "name": name,
        "official_reg_deadline": "2026-11-10 23:59",
        "official_time": "2026-11-20 09:00",
        "official_site": "https://example.com/contest",
    }
    info.update(overrides)
    return info


_ARCHIVE_RE = re.compile(r"<ARCHIVE_[0-9a-f]+>\n(.*?)\n</ARCHIVE_[0-9a-f]+>", re.S)


def _prompt_contests(chat_call):
    """从 user message 的随机 nonce 存档块中取出比赛上下文。"""
    user = chat_call.args[1]
    match = _ARCHIVE_RE.search(user)
    assert match is not None
    return json.loads(match.group(1))


def _answer(text):
    return json.dumps({"kind": "answer", "text": text}, ensure_ascii=False)


async def test_published_competition_reaches_qa_model_in_allowed_groups(bot, monkeypatch):
    client, replies = bot
    fetch = AsyncMock(return_value="校赛官网正文")
    chat = AsyncMock(side_effect=[
        json.dumps({
            "name": "新发布校赛",
            "reg_deadline": "2026-11-10 23:59",
            "contest_time": "2026-11-20 09:00",
        }, ensure_ascii=False),
        _answer("报名截止是 2026-11-10 23:59。"),
        _answer("比赛时间是 2026-11-20 09:00。"),
    ])
    monkeypatch.setattr(main, "fetch_text", fetch)
    monkeypatch.setattr(llm, "_chat_once", chat)

    await client.on_group_at_message_create(
        _message("发布 https://example.com/contest", member_id="teacher")
    )
    assert len(database.list_competitions(status="confirmed")) == 1
    assert database.list_contests("g1") == []

    await client.on_group_at_message_create(_message("新发布校赛什么时候截止报名？"))
    await client.on_group_at_message_create(
        _message("新发布校赛什么时候比赛？", group_id="g2")
    )

    fetch.assert_awaited_once_with("https://example.com/contest")
    assert chat.await_count == 3
    expected = [{
        "name": "新发布校赛",
        "reg_deadline": "2026-11-10 23:59",
        "contest_time": "2026-11-20 09:00",
        "mode": "",
        "location": "",
        "source_link": "https://example.com/contest",
    }]
    assert _prompt_contests(chat.await_args_list[1]) == expected
    assert _prompt_contests(chat.await_args_list[2]) == expected
    assert ("g1", "报名截止是 2026-11-10 23:59。") in replies
    assert ("g2", "比赛时间是 2026-11-20 09:00。") in replies


async def test_long_published_source_keeps_core_fields_and_next_competition(bot, monkeypatch):
    client, _ = bot
    monkeypatch.setattr(database, "now_str", lambda: "2026-11-01 09:00:00")
    normal_url = "https://example.com/normal"
    long_url = "https://example.com/contest?value=" + "a" * 1500
    fetch = AsyncMock(return_value="比赛官网正文")
    chat = AsyncMock(side_effect=[
        json.dumps({
            "name": "正常来源校赛",
            "reg_deadline": "2026-11-11 23:59",
            "contest_time": "2026-11-21 09:00",
        }, ensure_ascii=False),
        json.dumps({
            "name": "长来源校赛",
            "reg_deadline": "2026-11-12 23:59",
            "contest_time": "2026-11-22 09:00",
        }, ensure_ascii=False),
        _answer("两场比赛的信息均可查询。"),
    ])
    monkeypatch.setattr(main, "fetch_text", fetch)
    monkeypatch.setattr(llm, "_chat_once", chat)

    for url in (normal_url, long_url):
        await client.on_group_at_message_create(
            _message(f"发布 {url}", member_id="teacher")
        )
    await client.on_group_at_message_create(_message("这两场校赛什么时候报名？"))

    assert chat.await_count == 3
    assert [call.args[0] for call in fetch.await_args_list] == [normal_url, long_url]
    context = _prompt_contests(chat.await_args)
    assert [c["name"] for c in context] == ["长来源校赛", "正常来源校赛"]
    assert context[0]["reg_deadline"] == "2026-11-12 23:59"
    assert context[0]["contest_time"] == "2026-11-22 09:00"
    assert context[0].get("source_link", "") == ""
    assert context[1]["reg_deadline"] == "2026-11-11 23:59"
    assert context[1]["contest_time"] == "2026-11-21 09:00"
    assert context[1]["source_link"] == normal_url


def test_question_context_keeps_legacy_records_isolated(memory_db):
    database.create_competition(_public(), status="confirmed")
    database.save_contest("g1", {
        "name": "本群旧校赛", "mode": "线下", "location": "本群机房",
        "source_link": "https://example.com/legacy",
    })
    database.save_contest("g2", {"name": "其他群旧校赛"})
    database.save_contest("", {"name": "未归属旧校赛"})

    g1 = database.list_question_contests("g1")
    assert {c["name"] for c in g1} == {"正式校赛", "本群旧校赛"}
    legacy = next(c for c in g1 if c["name"] == "本群旧校赛")
    assert legacy["mode"] == "线下"
    assert legacy["location"] == "本群机房"
    assert legacy["source_link"] == "https://example.com/legacy"
    assert {c["name"] for c in database.list_question_contests("g2")} == {
        "正式校赛", "其他群旧校赛",
    }


async def test_qa_prompt_excludes_drafts_pending_and_private_legacy(bot, monkeypatch):
    client, _ = bot
    cid = database.create_competition(_public(), status="confirmed")
    database.create_competition(_public("尚未确认草稿"))
    database.add_pending_update(cid, {
        "name": "待审更新标题", "official_reg_deadline": "2026-12-01 23:59",
    })
    database.save_contest("g1", {"name": "本群旧记录"})
    database.save_contest("g2", {"name": "其他群私有记录"})
    database.save_contest("", {"name": "未归属记录"})
    chat = AsyncMock(return_value=_answer("正式报名截止是 2026-11-10 23:59。"))
    monkeypatch.setattr(llm, "_chat_once", chat)

    await client.on_group_at_message_create(_message("正式校赛什么时候截止？"))

    chat.assert_awaited_once()
    context = _prompt_contests(chat.await_args)
    assert {c["name"] for c in context} == {"正式校赛", "本群旧记录"}
    formal = next(c for c in context if c["name"] == "正式校赛")
    assert formal["reg_deadline"] == "2026-11-10 23:59"
    assert "2026-12-01 23:59" not in chat.await_args.args[0]
    assert "2026-12-01 23:59" not in chat.await_args.args[1]


async def test_qa_reads_amended_formal_fields_instead_of_old_version(bot, monkeypatch):
    client, _ = bot
    cid = database.create_competition(_public("原校赛标题"), status="confirmed")
    assert database.amend_competition(cid, {
        "name": "修正校赛标题",
        "official_reg_deadline": "2026-12-02 23:59",
        "official_time": "2026-12-10 09:00",
        "official_site": "https://example.com/corrected",
    }, operator="admin")
    chat = AsyncMock(return_value=_answer("已按修正后的正式信息回答。"))
    monkeypatch.setattr(llm, "_chat_once", chat)

    await client.on_group_at_message_create(_message("修正校赛标题什么时候报名？"))

    chat.assert_awaited_once()
    assert _prompt_contests(chat.await_args) == [{
        "name": "修正校赛标题",
        "reg_deadline": "2026-12-02 23:59",
        "contest_time": "2026-12-10 09:00",
        "mode": "",
        "location": "",
        "source_link": "https://example.com/corrected",
    }]


def test_question_context_orders_updates_and_limits_stably(memory_db, monkeypatch):
    monkeypatch.setattr(database, "now_str", lambda: "2026-11-01 09:00:00")
    public_ids = [
        database.create_competition(_public(f"公共{i}"), status="confirmed")
        for i in range(3)
    ]
    legacy_ids = [database.save_contest("g1", {"name": f"旧{i}"}) for i in range(3)]
    memory_db.execute(
        "UPDATE competitions SET updated_at = ? WHERE id = ?",
        ("2026-11-02 09:00:00", public_ids[0]),
    )
    memory_db.execute(
        "UPDATE contests SET created_at = ? WHERE id = ?",
        ("2026-11-03 09:00:00", legacy_ids[0]),
    )

    expected = ["旧0", "公共0", "公共2", "公共1", "旧2"]
    assert [c["name"] for c in database.list_question_contests("g1")] == expected
    assert [c["name"] for c in database.list_question_contests("g1", limit=3)] == expected[:3]
    assert [c["name"] for c in database.list_question_contests("g1")] == expected


@pytest.mark.parametrize("group_id, limit", [("", 5), ("g1", 0), ("g1", -1)])
def test_question_context_empty_group_or_nonpositive_limit_returns_empty(memory_db, group_id, limit):
    database.create_competition(_public(), status="confirmed")
    assert database.list_question_contests(group_id, limit=limit) == []


async def test_faq_match_still_skips_qa_model(bot, monkeypatch):
    client, replies = bot
    database.create_competition(_public(), status="confirmed")
    database.add_faq("g1", "校赛怎么报名", "请找负责老师登记。")
    chat = AsyncMock(return_value="不应调用")
    monkeypatch.setattr(llm, "_chat_once", chat)

    await client.on_group_at_message_create(_message("校赛怎么报名？"))

    chat.assert_not_awaited()
    assert replies == [("g1", "Q：校赛怎么报名\nA：请找负责老师登记。")]
