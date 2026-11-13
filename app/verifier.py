"""批次验真：Ed25519 验签 + 清单摘要逐页核对。

信任链与安全约束：
* 先验签，后抓详情 —— 签名验证失败时绝不抓取清单列出的任何 URL，
  伪造清单即使与网页内容相互吻合也不能当作可信公告；
* 签名覆盖清单 HTTP 响应的原始字节，不做任何规范化；
* 清单 / 签名 / 详情页一律不跟随重定向（3xx 即判不可信）；
* 相同 URL 只下载一次；清单为同一 URL 列出不同摘要 → 清单自相矛盾，整批不可信；
* 详情读取失败、跳转、摘要缺失或不符 → 整批不可信，逐项给出原因与来源；
* 响应只包含 URL 与摘要等元数据，绝不回显未经验证的页面正文。
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import re
from datetime import datetime, timezone
from typing import NamedTuple
from urllib.parse import urljoin

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from app.models import (
    Manifest,
    VerifyItemResult,
    VerifyItemStatus,
    VerifyRequest,
    VerifyResponse,
)
from app.parser import same_site

_MAX_CONCURRENCY = 5
_USER_AGENT = "TenderBatchVerifier/1.0 (+local procurement batch verification API)"
_MAX_MANIFEST_BYTES = 1 * 1024 * 1024   # 清单大小上限
_MAX_SIGNATURE_BYTES = 4 * 1024         # Base64 签名文件大小上限
_MAX_DETAIL_BYTES = 20 * 1024 * 1024    # 单个详情页大小上限
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ED25519_SIGNATURE_BYTES = 64


class _FetchIssue(NamedTuple):
    """抓取失败原因。kind: transport / redirect / http / too_large。"""

    kind: str
    message: str


async def _fetch_bytes(
    client: httpx.AsyncClient, url: str, max_bytes: int
) -> tuple[bytes | None, _FetchIssue | None]:
    """抓取 URL 原始字节；跳转、非 200、传输错误一律转为失败原因，绝不跟随重定向。"""
    try:
        response = await client.get(url)
    except httpx.HTTPError as exc:
        return None, _FetchIssue("transport", f"抓取失败：{exc.__class__.__name__}")
    if response.is_redirect:
        location = response.headers.get("location", "")
        return None, _FetchIssue(
            "redirect", f"返回跳转（HTTP {response.status_code} → {location}），已拒绝跟随"
        )
    if response.status_code != 200:
        return None, _FetchIssue("http", f"HTTP 状态码 {response.status_code}")
    content = response.content
    if len(content) > max_bytes:
        return None, _FetchIssue("too_large", f"响应体超过大小限制（{max_bytes} 字节）")
    return content, None


def _decode_signature(raw: bytes) -> bytes | None:
    """解码 Base64 签名文件内容（容忍首尾空白与换行），要求正好 64 字节。"""
    try:
        signature = base64.b64decode(re.sub(rb"\s+", b"", raw), validate=True)
    except (binascii.Error, ValueError):
        return None
    return signature if len(signature) == _ED25519_SIGNATURE_BYTES else None


class _Entry(NamedTuple):
    """规范化后的清单条目。"""

    resolved_url: str                       # 相对路径已按清单 URL 解析为绝对 URL
    declared_sha256: str                    # 小写十六进制（非法时保留原始小写形态）
    error_status: VerifyItemStatus | None   # 条目级先验错误（不同站 / 格式非法）
    error_detail: str


def _normalize_entries(manifest: Manifest, manifest_url: str) -> list[_Entry]:
    """把清单条目规范化为绝对 URL + 摘要，并做同站与格式校验。"""
    entries: list[_Entry] = []
    for item in manifest.items:
        resolved = urljoin(manifest_url, item.url.strip())
        declared = item.sha256.strip().lower()
        if not _SHA256_RE.match(declared):
            entries.append(
                _Entry(resolved, declared, VerifyItemStatus.INVALID_ENTRY,
                       "清单中的 SHA-256 不是 64 位十六进制")
            )
        elif not resolved.startswith(("http://", "https://")):
            entries.append(
                _Entry(resolved, declared, VerifyItemStatus.INVALID_ENTRY,
                       "URL 无法解析为 http/https 绝对地址")
            )
        elif not same_site(resolved, manifest_url):
            entries.append(
                _Entry(resolved, declared, VerifyItemStatus.FOREIGN_URL,
                       "详情 URL 与清单不同站点，拒绝抓取")
            )
        else:
            entries.append(_Entry(resolved, declared, None, ""))
    return entries


async def verify_batch(req: VerifyRequest) -> VerifyResponse:
    """验真主流程：取清单与签名 → 验签 → 解析清单 → 去重抓取 → 逐条核对摘要。"""
    checked_at = datetime.now(timezone.utc)
    manifest_url = str(req.manifest_url)
    signature_url = str(req.signature_url)

    def finish(
        *,
        trusted: bool = False,
        signature_valid: bool = False,
        batch_id: str | None = None,
        items: list[VerifyItemResult] | None = None,
        warnings: list[str] | None = None,
    ) -> VerifyResponse:
        item_list = items or []
        return VerifyResponse(
            manifest_url=manifest_url,
            signature_url=signature_url,
            trusted=trusted,
            signature_valid=signature_valid,
            batch_id=batch_id,
            item_count=len(item_list),
            ok_count=sum(1 for i in item_list if i.status == VerifyItemStatus.OK),
            items=item_list,
            warnings=warnings or [],
            checked_at=checked_at,
        )

    # 公钥格式已由请求模型校验（Base64、32 字节）
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(req.public_key))

    timeout = httpx.Timeout(req.timeout)
    async with httpx.AsyncClient(
        timeout=timeout, headers={"User-Agent": _USER_AGENT}, follow_redirects=False
    ) as client:
        # 1) 抓清单与签名（同站约束已由请求模型保证；两者都不跟随跳转）
        (manifest_bytes, manifest_issue), (signature_bytes, sig_issue) = await asyncio.gather(
            _fetch_bytes(client, manifest_url, _MAX_MANIFEST_BYTES),
            _fetch_bytes(client, signature_url, _MAX_SIGNATURE_BYTES),
        )
        if manifest_issue is not None or manifest_bytes is None:
            return finish(warnings=[f"清单抓取失败：{manifest_url}（{manifest_issue.message}），整批不可信"])
        if sig_issue is not None or signature_bytes is None:
            return finish(warnings=[f"签名抓取失败：{signature_url}（{sig_issue.message}），整批不可信"])

        # 2) 解码 Base64 签名
        signature = _decode_signature(signature_bytes)
        if signature is None:
            return finish(
                warnings=["签名内容不是合法的 Base64 或长度不是 64 字节，整批不可信"]
            )

        # 3) 验签：签名覆盖清单原始字节。失败 → 不解析清单、不抓任何详情页。
        try:
            public_key.verify(signature, manifest_bytes)
        except InvalidSignature:
            return finish(
                warnings=[
                    "签名验证失败：清单可能被伪造或篡改（即使清单与网页内容相互吻合也不可信）。"
                    "未抓取任何详情页。"
                ]
            )

        # 4) 验签通过后才解析清单 JSON
        try:
            manifest = Manifest.model_validate_json(manifest_bytes)
        except ValidationError:
            return finish(
                signature_valid=True,
                warnings=["清单签名有效，但内容不是合法的批次清单 JSON，整批不可信"],
            )

        if not manifest.items:
            return finish(
                signature_valid=True,
                batch_id=manifest.batch_id,
                warnings=["清单不含任何公告条目，无法作为可信批次"],
            )

        # 5) 规范化条目（相对 URL 解析、同站校验、摘要格式校验）
        entries = _normalize_entries(manifest, manifest_url)

        # 6) 同 URL 分组：同一 URL 被声明了不同摘要 → 清单自相矛盾，整批不可信
        digests_by_url: dict[str, set[str]] = {}
        for entry in entries:
            if entry.error_status is None:
                digests_by_url.setdefault(entry.resolved_url, set()).add(entry.declared_sha256)
        conflicted_urls = {u for u, ds in digests_by_url.items() if len(ds) > 1}

        # 7) 去重抓取：相同 URL 只下载一次；自相矛盾的 URL 不下载
        unique_urls = [u for u in digests_by_url if u not in conflicted_urls]
        semaphore = asyncio.Semaphore(_MAX_CONCURRENCY)

        async def fetch_one(url: str) -> tuple[str, bytes | None, _FetchIssue | None]:
            async with semaphore:
                content, issue = await _fetch_bytes(client, url, _MAX_DETAIL_BYTES)
                return url, content, issue

        fetched: dict[str, tuple[bytes | None, _FetchIssue | None]] = {}
        for url, content, issue in await asyncio.gather(*(fetch_one(u) for u in unique_urls)):
            fetched[url] = (content, issue)

    # 8) 逐条核对（保持清单原始顺序，重复条目共享同一次下载结果）
    entry_counts: dict[str, int] = {}
    for entry in entries:
        if entry.error_status is None:
            entry_counts[entry.resolved_url] = entry_counts.get(entry.resolved_url, 0) + 1

    results: list[VerifyItemResult] = []
    for entry in entries:
        if entry.error_status is not None:
            results.append(
                VerifyItemResult(
                    url=entry.resolved_url,
                    declared_sha256=entry.declared_sha256,
                    status=entry.error_status,
                    detail=entry.error_detail,
                )
            )
            continue

        url = entry.resolved_url
        if url in conflicted_urls:
            results.append(
                VerifyItemResult(
                    url=url,
                    declared_sha256=entry.declared_sha256,
                    status=VerifyItemStatus.CONFLICTING_DIGESTS,
                    detail="清单为同一 URL 声明了多个不同摘要，清单自相矛盾，未下载该页面",
                )
            )
            continue

        content, issue = fetched[url]
        if issue is not None or content is None:
            status = (
                VerifyItemStatus.REDIRECTED
                if issue is not None and issue.kind == "redirect"
                else VerifyItemStatus.FETCH_FAILED
            )
            results.append(
                VerifyItemResult(
                    url=url,
                    declared_sha256=entry.declared_sha256,
                    status=status,
                    detail=f"详情页读取失败：{issue.message if issue else '未知错误'}",
                )
            )
            continue

        actual = hashlib.sha256(content).hexdigest()
        if actual != entry.declared_sha256:
            results.append(
                VerifyItemResult(
                    url=url,
                    declared_sha256=entry.declared_sha256,
                    status=VerifyItemStatus.DIGEST_MISMATCH,
                    actual_sha256=actual,
                    detail="页面实际字节 SHA-256 与清单声明不符，内容可能已变更或被篡改",
                )
            )
            continue

        detail = "摘要一致，页面字节与清单吻合"
        if entry_counts.get(url, 0) > 1:
            detail += "；清单中的重复条目，共享同一次下载"
        results.append(
            VerifyItemResult(
                url=url,
                declared_sha256=entry.declared_sha256,
                status=VerifyItemStatus.OK,
                actual_sha256=actual,
                detail=detail,
            )
        )

    # 9) 汇总：全部条目核对通过才可信
    trusted = all(r.status == VerifyItemStatus.OK for r in results)
    warnings: list[str] = []
    for url in sorted(conflicted_urls):
        warnings.append(f"清单为同一 URL 声明了不同摘要：{url}")
    for status, label in (
        (VerifyItemStatus.DIGEST_MISMATCH, "摘要不符"),
        (VerifyItemStatus.FETCH_FAILED, "详情页读取失败"),
        (VerifyItemStatus.REDIRECTED, "详情页返回跳转"),
        (VerifyItemStatus.FOREIGN_URL, "详情 URL 不属于清单站点"),
        (VerifyItemStatus.INVALID_ENTRY, "清单条目非法"),
    ):
        urls = [r.url for r in results if r.status == status]
        if urls:
            warnings.append(f"{len(urls)} 项{label}：{'、'.join(urls)}")
    if not trusted:
        warnings.append("存在未通过核对的条目，整批不可信")

    return finish(
        trusted=trusted,
        signature_valid=True,
        batch_id=manifest.batch_id,
        items=results,
        warnings=warnings,
    )
