"""Pydantic 数据模型：请求 / 响应 / 内部记录。"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator

from app.parser import same_site


class ProjectStatus(str, Enum):
    """投标状态。

    OPEN         可投标（存在有效截止时间，且未取消）
    CLOSED       不可投标（公告明确取消采购）
    PENDING      待核实（抓取/解析失败，或无法得到有效截止时间，不能把旧时间当最终期限）
    NOT_FOUND    列表页未发现与该项目编号相关的同站点公告
    """

    OPEN = "open"
    CLOSED = "closed"
    PENDING = "pending"
    NOT_FOUND = "not_found"


class NoticeKind(str, Enum):
    ORIGINAL = "original"          # 原公告
    CORRECTION = "correction"      # 更正公告（含澄清、变更、延期）
    CANCELLATION = "cancellation"  # 取消公告（更正的一种，且明确取消采购）


class FetchRequest(BaseModel):
    """采集请求。"""

    list_url: HttpUrl = Field(..., description="采购公告列表页 URL")
    project_code: str = Field(..., min_length=1, description="项目编号，如 GSB-2026-001")
    timeout: float = Field(10.0, ge=1.0, le=60.0, description="单次请求超时时间（秒）")


class NoticeRecord(BaseModel):
    """单条公告详情的解析结果（按发布时间排序）。"""

    url: HttpUrl
    kind: NoticeKind
    title: str
    published_at: datetime | None = None
    deadline: datetime | None = Field(
        None, description="该公告声明的投标截止时间；未提及则为 None，合并时沿用已生效时间"
    )
    cancelled: bool = False
    cancellation_reason: str | None = None


class SourceLink(BaseModel):
    """来源链接（列表页 + 参与合并的详情页）。"""

    role: str  # list / original / correction / cancellation
    url: HttpUrl
    title: str | None = None


class FetchResponse(BaseModel):
    """采集响应。"""

    project_code: str
    list_url: HttpUrl
    status: ProjectStatus
    can_bid: bool = Field(..., description="当前是否可投标")
    effective_deadline: datetime | None = Field(
        None, description="有效投标截止时间；待核实/未找到时为 None，绝不返回旧时间冒充最终期限"
    )
    cancelled: bool = False
    notices: list[NoticeRecord] = Field(default_factory=list)
    sources: list[SourceLink] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    fetched_at: datetime


# --------------------------------------------------------------------------- #
# 批次验真（识别镜像站点上冒充正式发布的公告批次）
# --------------------------------------------------------------------------- #
class VerifyRequest(BaseModel):
    """批次验真请求。

    信任链：事先确认的 Ed25519 公钥 → 验证签名（覆盖清单原始字节）→ 清单 → 详情页字节。
    清单与网页内容即使相互吻合，没有有效签名也一律不可信。
    """

    manifest_url: HttpUrl = Field(..., description="同站 JSON 清单 URL")
    signature_url: HttpUrl = Field(
        ..., description="签名 URL（文件内容为 Base64 编码的 Ed25519 签名，覆盖清单原始字节）"
    )
    public_key: str = Field(
        ..., description="事先确认的 Ed25519 公钥（Base64 编码的 32 字节原始公钥）"
    )
    timeout: float = Field(10.0, ge=1.0, le=60.0, description="单次请求超时时间（秒）")

    @field_validator("public_key")
    @classmethod
    def _public_key_must_be_base64_32_bytes(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("public_key 必须是 Base64 编码的 32 字节 Ed25519 公钥") from exc
        if len(raw) != 32:
            raise ValueError(f"public_key 解码后必须为 32 字节，实际 {len(raw)} 字节")
        return value.strip()

    @model_validator(mode="after")
    def _signature_must_be_same_site(self) -> "VerifyRequest":
        if not same_site(str(self.signature_url), str(self.manifest_url)):
            raise ValueError("signature_url 必须与 manifest_url 同站点")
        return self


class VerifyItemStatus(str, Enum):
    """单条清单条目的核对结果。"""

    OK = "ok"                                # 页面实际字节摘要与清单一致
    FETCH_FAILED = "fetch_failed"            # 详情页读取失败（网络错误 / 非 200 / 超限）
    REDIRECTED = "redirected"                # 详情页返回跳转，已拒绝跟随
    DIGEST_MISMATCH = "digest_mismatch"      # 实际字节 SHA-256 与清单声明不符
    CONFLICTING_DIGESTS = "conflicting_digests"  # 清单为同一 URL 列出不同摘要
    FOREIGN_URL = "foreign_url"              # 详情 URL 与清单不同站，拒绝抓取
    INVALID_ENTRY = "invalid_entry"          # 清单条目本身非法（摘要格式错误等）


class VerifyItemResult(BaseModel):
    """单条清单条目的核对明细（只含元数据，绝不回显未经验证的页面正文）。"""

    url: str = Field(..., description="解析后的详情页绝对 URL（来源）")
    declared_sha256: str = Field(..., description="清单声明的 SHA-256（小写十六进制）")
    status: VerifyItemStatus
    actual_sha256: str | None = Field(None, description="实际下载字节的 SHA-256；未下载时为 None")
    detail: str = Field("", description="核对结论与原因说明")


class VerifyResponse(BaseModel):
    """批次验真响应。trusted=false 时 items/warnings 逐项说明原因与来源。"""

    manifest_url: HttpUrl
    signature_url: HttpUrl
    trusted: bool = Field(..., description="整批是否可信；任一环节失败都为 false")
    signature_valid: bool = Field(..., description="Ed25519 签名是否通过验证")
    batch_id: str | None = Field(None, description="清单声明的批次号（验签通过后才采纳）")
    item_count: int = 0
    ok_count: int = 0
    items: list[VerifyItemResult] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    checked_at: datetime


# --------------------------------------------------------------------------- #
# 清单文件格式（签名验证通过前不得解析使用）
# --------------------------------------------------------------------------- #
class ManifestItem(BaseModel):
    """清单条目：详情 URL（支持相对清单 URL 的相对路径）+ 页面字节 SHA-256。"""

    url: str
    sha256: str


class Manifest(BaseModel):
    """批次清单 JSON 文档。"""

    batch_id: str | None = None
    issued_at: str | None = None
    items: list[ManifestItem]
