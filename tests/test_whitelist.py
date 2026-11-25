"""白名单四层模型与"防手误"校验的测试。"""
from datetime import datetime, timedelta, timezone

import pytest

from ksc2pan.config import WhitelistCfg
from ksc2pan.normalize import parse_ip
from ksc2pan.whitelist import Whitelist, WhitelistError

BASE = """
version: "test"
assets:
  - cidr: 222.128.16.0/28
    why: 出口 NAT
    owner: 网络组
    ticket: NET-1
  - cidr: 114.114.114.114/32
    why: 内部 DNS
"""


def make(tmp_path, text: str = BASE, **kwargs) -> Whitelist:
    path = tmp_path / "wl.yaml"
    path.write_text(text, encoding="utf-8")
    cfg = WhitelistCfg(path=str(path), **kwargs)
    wl = Whitelist(cfg)
    wl.load(strict=True)
    return wl


def test_builtin_private_is_l0(tmp_path):
    wl = make(tmp_path)
    hit = wl.match(parse_ip("10.20.30.40"))
    assert hit is not None and hit.layer == "L0"


def test_asset_match(tmp_path):
    wl = make(tmp_path)
    hit = wl.match(parse_ip("222.128.16.5"))
    assert hit is not None
    assert hit.layer == "L1"
    assert hit.why == "出口 NAT"
    assert hit.ticket == "NET-1"


def test_public_not_matched(tmp_path):
    wl = make(tmp_path)
    assert wl.match(parse_ip("45.83.12.77")) is None


def test_temporary_requires_expire(tmp_path):
    text = BASE + "temporary:\n  - cidr: 58.246.99.18/32\n    why: 厂商支持\n"
    with pytest.raises(WhitelistError):
        make(tmp_path, text)


def test_temporary_expired_is_ignored(tmp_path):
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    text = BASE + (
        "temporary:\n"
        "  - cidr: 58.246.99.18/32\n"
        "    why: 厂商支持\n"
        f'    expire: "{past}"\n'
    )
    wl = make(tmp_path, text)
    assert wl.match(parse_ip("58.246.99.18")) is None


def test_temporary_valid_matches_l2(tmp_path):
    future = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
    text = BASE + (
        "temporary:\n"
        "  - cidr: 58.246.99.18/32\n"
        "    why: 厂商支持\n"
        f'    expire: "{future}"\n'
    )
    wl = make(tmp_path, text)
    hit = wl.match(parse_ip("58.246.99.18"))
    assert hit is not None and hit.layer == "L2"


def test_reject_too_wide_network(tmp_path):
    text = "assets:\n  - cidr: 0.0.0.0/0\n    why: 手滑\n"
    with pytest.raises(WhitelistError):
        make(tmp_path, text)


def test_reject_missing_why(tmp_path):
    text = "assets:\n  - cidr: 222.128.16.0/28\n"
    with pytest.raises(WhitelistError):
        make(tmp_path, text)


def test_reject_invalid_cidr(tmp_path):
    text = "assets:\n  - cidr: 222.128.16.0/33\n    why: x\n"
    with pytest.raises(WhitelistError):
        make(tmp_path, text)


def test_growth_ratio_guard(tmp_path):
    wl = make(tmp_path)
    # 直接篡改成大量条目，模拟"误粘贴一整份路由表"
    extra = "".join(f"  - cidr: 8.8.{i}.0/24\n    why: x\n" for i in range(60))
    (tmp_path / "wl.yaml").write_text("assets:\n" + extra, encoding="utf-8")
    wl.load(strict=False)
    assert "异常增长" in wl.last_error
    # 旧配置仍生效
    assert wl.match(parse_ip("222.128.16.5")) is not None


def test_export_excludes_l0(tmp_path):
    wl = make(tmp_path)
    exported = wl.export_cidrs()
    assert "222.128.16.0/28" in exported
    assert not any(e.startswith("10.") for e in exported)


def test_observe_only_window(tmp_path):
    now = datetime.now(timezone.utc)
    text = BASE + (
        "windows:\n"
        f'  - start: "{(now - timedelta(hours=1)).isoformat()}"\n'
        f'    end: "{(now + timedelta(hours=1)).isoformat()}"\n'
        "    mode: observe_only\n"
        "    why: 升级窗口\n"
    )
    wl = make(tmp_path, text)
    win = wl.observe_only_now()
    assert win is not None and win.why == "升级窗口"


def test_check_api_shape(tmp_path):
    wl = make(tmp_path)
    out = wl.check("222.128.16.5")
    assert out["valid"] is True
    assert out["whitelisted"] is True
    assert out["hit"]["layer"] == "L1"
    assert wl.check("not-an-ip")["valid"] is False


def test_local_override_is_merged(tmp_path):
    """现场真实网段放 whitelist.local.yaml，不进 Git，但会参与判定。"""
    wl = make(tmp_path)
    assert wl.match(parse_ip("58.246.99.18")) is None

    (tmp_path / "whitelist.local.yaml").write_text(
        "assets:\n  - cidr: 58.246.99.0/24\n    why: 现场业务段\n    owner: 网络组\n",
        encoding="utf-8",
    )
    wl.load(strict=False)

    hit = wl.match(parse_ip("58.246.99.18"))
    assert hit is not None and hit.why == "现场业务段"
    assert wl.stats()["local_override"].endswith("whitelist.local.yaml")
    # 基础文件的条目仍然有效
    assert wl.match(parse_ip("222.128.16.5")) is not None


def test_local_override_obeys_same_validation(tmp_path):
    wl = make(tmp_path)
    (tmp_path / "whitelist.local.yaml").write_text(
        "assets:\n  - cidr: 0.0.0.0/0\n    why: 手滑\n", encoding="utf-8"
    )
    wl.load(strict=False)
    assert "过宽" in wl.last_error
    # 拒绝加载后旧快照仍生效，不会"半套配置"运行
    assert wl.match(parse_ip("222.128.16.5")) is not None
