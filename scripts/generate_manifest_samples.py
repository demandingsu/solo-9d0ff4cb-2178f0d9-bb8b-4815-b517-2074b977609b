#!/usr/bin/env python3
"""重新生成 sample-site/manifest/ 下的演示批次清单与签名文件。

* 演示密钥由固定 seed 派生，任何时候运行结果完全一致（离线、可重现）；
* 私钥仅用于本地演示，生产环境必须使用离线保管的真实密钥重新签发；
* 运行：python scripts/generate_manifest_samples.py

生成三组样例：
1. batch-ok       正常批次：摘要与详情页实际字节一致，官方密钥签名 → 可信；
2. batch-forged   伪造批次：摘要同样与网页吻合，但签名来自攻击者密钥，
                  用官方公钥验签失败 → 不可信（内容自洽 ≠ 可信）；
3. batch-changed  内容变更：官方密钥签名有效，但清单记录的是 g004 旧版内容的
                  摘要，线上页面已被改动 → 摘要不符 → 不可信。
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent.parent
SITE_DIR = ROOT / "sample-site"
MANIFEST_DIR = SITE_DIR / "manifest"

# 演示用固定 seed（公开在仓库中，切勿用于生产）
OFFICIAL_SEED = bytes(range(32))
ATTACKER_SEED = bytes(range(32, 64))

# g004 详情页“签发时”的旧版内容：线上文件随后被改动
# （投标截止时间 12:00 → 17:00、加工量 100 万页 → 120 万页、开标室三楼 → 一楼），
# batch-changed.json 记录的是这份旧版字节的摘要。
G004_OLD_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>档案数字化加工服务采购项目公开招标公告</title>
</head>
<body>
<article>
  <h1>档案数字化加工服务采购项目公开招标公告</h1>
  <table>
    <tr><th>项目编号</th><td>GSB-2026-004</td></tr>
    <tr><th>采购单位</th><td>某市档案馆</td></tr>
    <tr><th>公告类型</th><td>公开招标公告（原公告）</td></tr>
    <tr><th>发布时间</th><td>2026-11-02 09:00</td></tr>
    <tr><th>投标截止时间</th><td>2026-11-18 12:00</td></tr>
  </table>
  <section>
    <h2>项目概况</h2>
    <p>本项目为馆藏档案数字化加工服务，加工量约 100 万页，欢迎符合资格条件的供应商参加投标。</p>
    <p>供应商应于投标截止时间前将响应文件递交至市公共资源交易中心三楼开标室，逾期送达的响应文件不予受理。</p>
  </section>
</article>
</body>
</html>
"""


def _sha256_of_file(relative: str) -> str:
    return hashlib.sha256((SITE_DIR / relative).read_bytes()).hexdigest()


def _write_batch(name: str, manifest: dict, signing_seed: bytes) -> None:
    payload = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    signature = Ed25519PrivateKey.from_private_bytes(signing_seed).sign(payload)
    (MANIFEST_DIR / f"{name}.json").write_bytes(payload)
    (MANIFEST_DIR / f"{name}.sig").write_bytes(base64.b64encode(signature) + b"\n")


def main() -> None:
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)

    official_key = Ed25519PrivateKey.from_private_bytes(OFFICIAL_SEED)
    public_b64 = base64.b64encode(
        official_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    (MANIFEST_DIR / "public.key").write_text(public_b64 + "\n", encoding="utf-8")

    ok_items = [
        {"url": f"../detail/{page}.html", "sha256": _sha256_of_file(f"detail/{page}.html")}
        for page in ("g001-original", "g001-corr1", "g001-corr2")
    ]

    # 1) 正常批次：官方密钥签名
    _write_batch(
        "batch-ok",
        {
            "batch_id": "GSB-2026-001",
            "issued_at": "2026-11-06T10:00:00+08:00",
            "items": ok_items,
        },
        OFFICIAL_SEED,
    )

    # 2) 伪造批次：条目与摘要完全照抄真实页面（内容自洽），但用攻击者密钥签名
    _write_batch(
        "batch-forged",
        {
            "batch_id": "GSB-2026-001",
            "issued_at": "2026-11-06T10:00:00+08:00",
            "items": ok_items,
        },
        ATTACKER_SEED,
    )

    # 3) 内容变更批次：官方密钥签名，但摘要对应 g004 旧版内容
    _write_batch(
        "batch-changed",
        {
            "batch_id": "GSB-2026-004",
            "issued_at": "2026-11-02T09:30:00+08:00",
            "items": [
                {
                    "url": "../detail/g004-original.html",
                    "sha256": hashlib.sha256(G004_OLD_HTML.encode("utf-8")).hexdigest(),
                }
            ],
        },
        OFFICIAL_SEED,
    )

    print(f"演示公钥（public.key）：{public_b64}")
    print(f"已生成：{sorted(p.name for p in MANIFEST_DIR.iterdir())}")


if __name__ == "__main__":
    main()
