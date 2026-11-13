"""批次验真 API 测试：本地静态服务器托管 sample-site，完整覆盖信任链。

覆盖场景：
* 正常批次（签名有效 + 摘要一致）→ 可信；
* 伪造批次（摘要与网页吻合但签名错误）→ 不可信，且不得抓取任何详情页；
* 清单签发后页面内容变更 → 摘要不符 → 不可信；
* 同一 URL 不同摘要 / 重复条目只下载一次 / 跳转 / 404 / 外站 URL 等边界。
"""

from __future__ import annotations

import base64
import collections
import functools
import http.server
import json
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.main import app

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample-site"

# 与 scripts/generate_manifest_samples.py 中的演示 seed 一致（仅用于本地演示/测试）
OFFICIAL_SEED = bytes(range(32))
ATTACKER_SEED = bytes(range(32, 64))
PUBLIC_KEY_B64 = (SAMPLE_DIR / "manifest" / "public.key").read_text().strip()


class _VerifyHandler(http.server.SimpleHTTPRequestHandler):
    """静态托管 sample-site，并支持注入动态清单/签名与统计请求次数。"""

    injected: dict[str, bytes] = {}
    counts: collections.Counter[str] = collections.Counter()

    def log_message(self, *args):  # 静默测试输出
        pass

    def do_GET(self):
        self.__class__.counts[self.path] += 1
        if self.path in self.__class__.injected:
            body = self.__class__.injected[self.path]
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/detail/g005-moved.html":
            # 模拟镜像站把公告页搬到别处：返回 301，验真方必须拒绝跟随
            self.send_response(301)
            self.send_header("Location", "/detail/g005-original.html")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        super().do_GET()


@pytest.fixture(scope="module")
def server():
    handler = functools.partial(_VerifyHandler, directory=str(SAMPLE_DIR))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(autouse=True)
def _reset_handler_state():
    _VerifyHandler.injected.clear()
    _VerifyHandler.counts.clear()
    yield


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _sign(payload: bytes, seed: bytes = OFFICIAL_SEED) -> bytes:
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(payload)
    return base64.b64encode(signature) + b"\n"


def _inject_batch(name: str, items: list[dict], seed: bytes = OFFICIAL_SEED) -> None:
    """生成一份动态清单与签名，注入静态服务器（相对 URL 与真实样例同风格）。"""
    manifest = {
        "batch_id": "TEST-BATCH",
        "issued_at": "2026-11-06T10:00:00+08:00",
        "items": items,
    }
    payload = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _VerifyHandler.injected[f"/manifest/{name}.json"] = payload
    _VerifyHandler.injected[f"/manifest/{name}.sig"] = _sign(payload, seed)


def _verify(client, base: str, manifest_path: str, signature_path: str | None = None,
            public_key: str = PUBLIC_KEY_B64):
    resp = client.post(
        "/api/v1/verify-batch",
        json={
            "manifest_url": f"{base}{manifest_path}",
            "signature_url": f"{base}{signature_path or manifest_path.replace('.json', '.sig')}",
            "public_key": public_key,
            "timeout": 5,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# --------------------------------------------------------------------------- #
# 静态样例：正常 / 伪造 / 内容变更
# --------------------------------------------------------------------------- #
def test_ok_batch_is_trusted(client, server):
    data = _verify(client, server, "/manifest/batch-ok.json")

    assert data["trusted"] is True
    assert data["signature_valid"] is True
    assert data["batch_id"] == "GSB-2026-001"
    assert data["item_count"] == 3
    assert data["ok_count"] == 3
    assert all(i["status"] == "ok" for i in data["items"])
    assert all(i["actual_sha256"] == i["declared_sha256"] for i in data["items"])
    # 相对 URL 已按清单地址解析为同站绝对 URL
    assert all(i["url"].startswith(server) for i in data["items"])


def test_forged_manifest_rejected_without_fetching_details(client, server):
    """伪造清单与网页内容相互吻合，但签名不是官方密钥所签 → 不可信，且不抓详情。"""
    data = _verify(client, server, "/manifest/batch-forged.json")

    assert data["trusted"] is False
    assert data["signature_valid"] is False
    # 验签失败：清单内容一律不采纳，未抓取任何详情页
    assert data["items"] == []
    assert any("签名验证失败" in w for w in data["warnings"])
    assert not any(path.startswith("/detail/") for path in _VerifyHandler.counts)


def test_tampered_manifest_bytes_rejected(client, server):
    """在已签发清单上追加一个字节 → 原始字节改变 → 验签失败。"""
    original = (SAMPLE_DIR / "manifest" / "batch-ok.json").read_bytes()
    _VerifyHandler.injected["/manifest/tampered.json"] = original + b" "
    _VerifyHandler.injected["/manifest/tampered.sig"] = (
        SAMPLE_DIR / "manifest" / "batch-ok.sig"
    ).read_bytes()

    data = _verify(client, server, "/manifest/tampered.json")
    assert data["trusted"] is False
    assert data["signature_valid"] is False
    assert data["items"] == []


def test_changed_content_rejected_with_valid_signature(client, server):
    """官方签名有效，但 g004 页面在签发后被改动 → 摘要不符 → 不可信。"""
    data = _verify(client, server, "/manifest/batch-changed.json")

    assert data["trusted"] is False
    assert data["signature_valid"] is True
    assert data["batch_id"] == "GSB-2026-004"
    assert data["ok_count"] == 0
    item = data["items"][0]
    assert item["status"] == "digest_mismatch"
    assert item["actual_sha256"] is not None
    assert item["actual_sha256"] != item["declared_sha256"]
    assert "不符" in item["detail"]


def test_response_does_not_echo_unverified_bodies(client, server):
    """响应只含元数据：任何情况下都不得回显未经验证的页面正文。"""
    for path in ("/manifest/batch-ok.json", "/manifest/batch-changed.json"):
        resp = client.post(
            "/api/v1/verify-batch",
            json={
                "manifest_url": f"{server}{path}",
                "signature_url": f"{server}{path.replace('.json', '.sig')}",
                "public_key": PUBLIC_KEY_B64,
                "timeout": 5,
            },
        )
        assert "市政绿化" not in resp.text
        assert "档案数字化" not in resp.text
        assert "<html" not in resp.text.lower()


# --------------------------------------------------------------------------- #
# 动态构造的边界场景
# --------------------------------------------------------------------------- #
def test_conflicting_digests_for_same_url(client, server):
    """清单为同一 URL 列出不同摘要 → 清单自相矛盾，整批不可信且不下载该页。"""
    _inject_batch(
        "conflict",
        [
            {"url": "../detail/g001-original.html", "sha256": "a" * 64},
            {"url": "../detail/g001-original.html", "sha256": "b" * 64},
        ],
    )
    data = _verify(client, server, "/manifest/conflict.json")

    assert data["trusted"] is False
    assert data["signature_valid"] is True
    assert {i["status"] for i in data["items"]} == {"conflicting_digests"}
    assert any("不同摘要" in w for w in data["warnings"])
    assert _VerifyHandler.counts["/detail/g001-original.html"] == 0


def test_duplicate_entries_same_digest_downloaded_once(client, server):
    """相同 URL 的重复条目（摘要一致）只下载一次，整批仍可信。"""
    import hashlib

    digest = hashlib.sha256((SAMPLE_DIR / "detail" / "g001-corr1.html").read_bytes()).hexdigest()
    _inject_batch(
        "dup",
        [
            {"url": "../detail/g001-corr1.html", "sha256": digest},
            {"url": "../detail/g001-corr1.html", "sha256": digest},
        ],
    )
    data = _verify(client, server, "/manifest/dup.json")

    assert data["trusted"] is True
    assert data["item_count"] == 2
    assert all(i["status"] == "ok" for i in data["items"])
    assert _VerifyHandler.counts["/detail/g001-corr1.html"] == 1


def test_redirected_detail_rejected(client, server):
    _inject_batch(
        "redirect",
        [{"url": "../detail/g005-moved.html", "sha256": "c" * 64}],
    )
    data = _verify(client, server, "/manifest/redirect.json")

    assert data["trusted"] is False
    item = data["items"][0]
    assert item["status"] == "redirected"
    assert "跳转" in item["detail"]
    # 拒绝跟随：跳转目标从未被请求
    assert _VerifyHandler.counts["/detail/g005-original.html"] == 0


def test_missing_detail_rejected(client, server):
    _inject_batch(
        "missing",
        [{"url": "../detail/no-such-page.html", "sha256": "d" * 64}],
    )
    data = _verify(client, server, "/manifest/missing.json")

    assert data["trusted"] is False
    item = data["items"][0]
    assert item["status"] == "fetch_failed"
    assert "404" in item["detail"]


def test_foreign_detail_url_rejected(client, server):
    """清单指向外站详情页 → 拒绝抓取，整批不可信。"""
    _inject_batch(
        "foreign",
        [{"url": "http://evil-mirror.example.gov/detail/x.html", "sha256": "e" * 64}],
    )
    data = _verify(client, server, "/manifest/foreign.json")

    assert data["trusted"] is False
    item = data["items"][0]
    assert item["status"] == "foreign_url"
    assert "不同站" in item["detail"]


def test_invalid_sha256_entry_rejected(client, server):
    _inject_batch(
        "bad-digest",
        [{"url": "../detail/g001-original.html", "sha256": "not-a-sha256"}],
    )
    data = _verify(client, server, "/manifest/bad-digest.json")

    assert data["trusted"] is False
    assert data["items"][0]["status"] == "invalid_entry"
    assert _VerifyHandler.counts["/detail/g001-original.html"] == 0


def test_empty_items_rejected(client, server):
    _inject_batch("empty", [])
    data = _verify(client, server, "/manifest/empty.json")

    assert data["trusted"] is False
    assert data["signature_valid"] is True
    assert data["items"] == []
    assert any("不含任何公告条目" in w for w in data["warnings"])


def test_mixed_batch_reports_each_item(client, server):
    """部分条目通过、部分失败：逐项给出状态与原因，整批不可信。"""
    import hashlib

    good = hashlib.sha256((SAMPLE_DIR / "detail" / "g001-corr2.html").read_bytes()).hexdigest()
    _inject_batch(
        "mixed",
        [
            {"url": "../detail/g001-corr2.html", "sha256": good},
            {"url": "../detail/no-such-page.html", "sha256": "f" * 64},
        ],
    )
    data = _verify(client, server, "/manifest/mixed.json")

    assert data["trusted"] is False
    assert data["ok_count"] == 1
    statuses = {i["url"].rsplit("/", 1)[-1]: i["status"] for i in data["items"]}
    assert statuses == {"g001-corr2.html": "ok", "no-such-page.html": "fetch_failed"}


# --------------------------------------------------------------------------- #
# 请求级校验与传输失败
# --------------------------------------------------------------------------- #
def test_wrong_public_key_rejected(client, server):
    attacker_public = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(ATTACKER_SEED)
        .public_key().public_bytes_raw()
    ).decode()
    data = _verify(client, server, "/manifest/batch-ok.json", public_key=attacker_public)

    assert data["trusted"] is False
    assert data["signature_valid"] is False
    assert data["items"] == []


def test_manifest_not_found(client, server):
    data = _verify(client, server, "/manifest/no-such-manifest.json")

    assert data["trusted"] is False
    assert data["signature_valid"] is False
    assert any("清单抓取失败" in w for w in data["warnings"])


def test_signature_not_base64(client, server):
    _VerifyHandler.injected["/manifest/badsig.json"] = (
        SAMPLE_DIR / "manifest" / "batch-ok.json"
    ).read_bytes()
    _VerifyHandler.injected["/manifest/badsig.sig"] = b"%%not-base64%%"

    data = _verify(client, server, "/manifest/badsig.json")
    assert data["trusted"] is False
    assert data["signature_valid"] is False
    assert any("Base64" in w for w in data["warnings"])


def test_invalid_public_key_returns_422(client, server):
    resp = client.post(
        "/api/v1/verify-batch",
        json={
            "manifest_url": f"{server}/manifest/batch-ok.json",
            "signature_url": f"{server}/manifest/batch-ok.sig",
            "public_key": "not!!base64",
        },
    )
    assert resp.status_code == 422


def test_cross_site_signature_url_returns_422(client, server):
    resp = client.post(
        "/api/v1/verify-batch",
        json={
            "manifest_url": f"{server}/manifest/batch-ok.json",
            "signature_url": "http://evil-mirror.example.gov/batch-ok.sig",
            "public_key": PUBLIC_KEY_B64,
        },
    )
    assert resp.status_code == 422
