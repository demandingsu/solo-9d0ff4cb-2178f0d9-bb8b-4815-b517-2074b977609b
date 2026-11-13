# 采购公告采集 API

传入**采购公告列表页 URL** 与**项目编号**，自动抓取该页指向的同站点原公告与更正公告，
从详情页提取发布时间、投标截止时间与取消采购信息，按发布时间合并后返回：
当前是否可投标、有效截止时间、项目状态以及全部来源链接。

另提供**批次验真 API**：针对镜像站点上冒充正式发布的公告批次，用事先确认的
Ed25519 公钥验证签名清单，再逐页核对详情页字节摘要——伪造清单即使与网页内容
相互吻合，也不会被当作可信公告。

## 业务规则

| 规则 | 实现位置 |
| --- | --- |
| 只采集列表页指向的**同站点**详情链接，外站链接、登录/导航链接自动忽略 | `app/parser.py::extract_detail_links` |
| 按**发布时间**从早到晚合并原公告与更正公告 | `app/merger.py::merge_notices` |
| 更正公告**未提及截止时间**时，沿用此前已生效的截止时间 | `app/merger.py` |
| 更正公告给出新截止时间（如延期）时，以新时间覆盖 | `app/merger.py` |
| 公告明确**取消采购** → 状态 `closed`、不可投标，不再返回有效截止时间（旧时间仅在公告明细中保留） | `app/merger.py` |
| **任一关联详情页**抓取/解析失败（404、超时、结构异常等）→ 状态 `pending` 待核实，`effective_deadline` 强制为 `null`，**绝不把旧时间当作最终期限** | `app/merger.py` + `app/collector.py` |
| 发布时间缺失、缺少原公告、全部公告均无截止时间等信息链不完整情况，同样标记 `pending` | `app/merger.py` |

### 项目状态（`status`）

- `open`：可投标，`effective_deadline` 为合并后的有效截止时间；
- `closed`：采购已取消，`can_bid=false`，无有效截止时间；
- `pending`：待核实，存在关联页面失败或信息不完整，`effective_deadline=null`；
- `not_found`：列表页未发现与该项目编号相关的公告。

## 批次验真（`/api/v1/verify-batch`）

维护人员事先确认发布方的 **Ed25519 公钥**（线下渠道获取，不经过被怀疑的镜像站）。
验真时提供三样输入：同站 **JSON 清单 URL**、**签名 URL**（文件内容为 Base64 编码的
Ed25519 签名，覆盖清单 HTTP 响应的**原始字节**）、**公钥**（Base64 编码的 32 字节）。

信任链与安全约束（实现于 `app/verifier.py`）：

| 规则 | 说明 |
| --- | --- |
| **先验签，后抓详情** | 签名验证失败时不解析清单、不抓取任何详情页——伪造清单与网页即使内容吻合也不可信 |
| 签名覆盖清单原始字节 | 不做任何规范化，改动一个字节即验签失败 |
| 清单/签名/详情**不跟随重定向** | 任何 3xx 都判为不可信 |
| 相同 URL 只下载一次 | 重复条目共享同一次下载结果 |
| 同一 URL 不同摘要 → 整批不可信 | 清单自相矛盾，该 URL 不下载 |
| 详情读取失败 / 跳转 / 摘要不符 → 整批不可信 | 逐项给出 `status`、原因与来源 URL |
| 详情 URL 必须与清单同站 | 外站条目拒绝抓取 |
| **不回显未经验证的正文** | 响应只含 URL、摘要等元数据 |

### 清单格式

```json
{
  "batch_id": "GSB-2026-001",
  "issued_at": "2026-11-06T10:00:00+08:00",
  "items": [
    {"url": "../detail/g001-original.html", "sha256": "<页面字节的 SHA-256，64 位小写十六进制>"}
  ]
}
```

`url` 支持相对清单地址的相对路径（解析后必须与清单同站）；`sha256` 为详情页
**原始字节**的 SHA-256。

### 调用示例

```bash
PUBKEY=$(curl -s http://localhost:8080/manifest/public.key)   # 演示公钥；生产中应线下确认
curl -X POST http://localhost:8000/api/v1/verify-batch \
  -H 'Content-Type: application/json' \
  -d "{
    \"manifest_url\": \"http://localhost:8080/manifest/batch-ok.json\",
    \"signature_url\": \"http://localhost:8080/manifest/batch-ok.sig\",
    \"public_key\": \"$PUBKEY\"
  }"
```

响应关键字段：

```json
{
  "trusted": true,
  "signature_valid": true,
  "batch_id": "GSB-2026-001",
  "item_count": 3,
  "ok_count": 3,
  "items": [
    {"url": "http://.../detail/g001-original.html", "status": "ok",
     "declared_sha256": "...", "actual_sha256": "...", "detail": "摘要一致，页面字节与清单吻合"}
  ],
  "warnings": []
}
```

`trusted` 为整批结论；为 `false` 时逐项查看 `items[].status`
（`digest_mismatch` / `fetch_failed` / `redirected` / `conflicting_digests` /
`foreign_url` / `invalid_entry`）与 `warnings`。

### 内置验真样例（`sample-site/manifest/`）

| 清单 | 场景 | 预期结果 |
| --- | --- | --- |
| `batch-ok.json` / `.sig` | 正常批次：官方密钥签名，摘要与页面一致 | `trusted=true` |
| `batch-forged.json` / `.sig` | 伪造批次：摘要与网页**完全吻合**，但签名来自攻击者密钥 | `trusted=false`，`signature_valid=false`，未抓详情 |
| `batch-changed.json` / `.sig` | 官方签名有效，但 `g004` 页面签发后被改动（截止时间 12:00→17:00 等） | `trusted=false`，对应项 `digest_mismatch` |

演示公钥见 `sample-site/manifest/public.key`。重新生成样例（离线、结果可重现）：

```bash
python scripts/generate_manifest_samples.py
```

> 演示密钥对的 seed 固定在 `scripts/generate_manifest_samples.py` 中，仅用于本地
> 演示与测试；生产环境必须使用离线保管的真实密钥重新签发清单。

## 目录结构

```
.
├── app/
│   ├── main.py        # FastAPI 入口、路由、浏览器演示页
│   ├── collector.py   # 采集编排：列表发现 → 并发抓取 → 归属判定 → 合并
│   ├── verifier.py    # 批次验真：验签 → 清单解析 → 去重抓取 → 摘要核对
│   ├── parser.py      # HTML 解析：同站链接发现、三层字段提取、取消识别
│   ├── merger.py      # 业务合并规则（时间继承、延期覆盖、取消、待核实）
│   └── models.py      # 请求/响应 Pydantic 模型（含清单格式）
├── sample-site/       # 本地示例公告站点（nginx 静态托管）
│   ├── list.html      # 公告列表页（含外站/登录干扰链接）
│   ├── detail/        # 各项目的原公告/更正/取消详情页（含内容已变更的 g004）
│   └── manifest/      # 验真样例：正常/伪造/内容变更批次 + 演示公钥
├── scripts/generate_manifest_samples.py  # 重新生成验真样例（可重现）
├── nginx/default.conf # 示例站点 nginx 配置（缺失页面返回真实 404）
├── tests/             # 解析/合并单测 + 采集与验真端到端测试（48 个用例）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 一键启动（Docker Compose）

```bash
docker compose up --build
```

启动后：

| 服务 | 地址 | 说明 |
| --- | --- | --- |
| 公告采集 API | http://localhost:8000 | Swagger 文档：http://localhost:8000/docs |
| 浏览器演示页 | http://localhost:8000/ | 填表即可发起采集 |
| 示例公告站点 | http://localhost:8080/list.html | nginx 托管的静态采购公告 |

停止：`docker compose down`。

## API 用法

### POST（推荐）

```bash
curl -X POST http://localhost:8000/api/v1/collect \
  -H 'Content-Type: application/json' \
  -d '{"list_url":"http://localhost:8080/list.html","project_code":"GSB-2026-001"}'
```

### GET（便于浏览器快速验证）

```bash
curl "http://localhost:8000/api/v1/collect?list_url=http://localhost:8080/list.html&project_code=GSB-2026-001"
```

响应关键字段：

```json
{
  "project_code": "GSB-2026-001",
  "status": "open",
  "can_bid": true,
  "effective_deadline": "2026-11-15T14:00:00",
  "cancelled": false,
  "notices": [ { "kind": "original", "published_at": "...", "deadline": "..." } ],
  "sources": [ { "role": "list", "url": "..." }, { "role": "correction", "url": "..." } ],
  "warnings": []
}
```

## 示例站点内置的三个演示项目

| 项目编号 | 场景 | 预期结果 |
| --- | --- | --- |
| `GSB-2026-001` | 原公告 → 澄清更正（**未提截止时间，沿用原时间**）→ 延期更正（**新时间覆盖**） | `open`，有效截止时间 `2026-11-15 14:00` |
| `GSB-2026-002` | 原公告 → 取消公告（预算收回） | `closed`，不可投标，无有效截止时间 |
| `GSB-2026-003` | 原公告 → 更正页**已下线（404）** | `pending` 待核实，`effective_deadline=null`，来源中列出失败链接 |

另外列表页还包含：外站链接、登录导航链接、其他项目公告（`GSB-2026-099`）、
无关项目的坏链接（`GSB-2025-888`），用于验证同站过滤、项目归属判定与失败隔离。

## 详情页解析策略（三层回退）

1. **结构化标记**：`data-field="published-at|deadline|cancelled|..."` 元素或
   `<meta property="article:published_time">`；
2. **标签匹配**：`发布时间 / 投标截止时间 / 响应文件递交截止时间 / 取消原因` 等
   中文标签，兼容 `th/td`、`dt/dd`、`li/p` 等布局，支持
   `2026-11-10 09:30`、`2026年11月15日 14时00分` 等常见写法；
3. **正文正则兜底**：在含“截止/递交/提交/受理”等时限语义的块级元素中识别日期，
   并排除“发布时间”句、资质业绩说明中的历史日期（如“近三年（2023年1月1日起）”）。

取消采购识别支持 `data-field="cancelled"` 标记、取消原因标签以及
“本项目取消采购 / 终止本次招标”等显式句式。

> 接入真实采购平台时，若页面结构不同，优先在详情页模板中补 `data-field` 标记，
> 或在 `app/parser.py` 顶部的标签/关键词元组中登记该平台的字段叫法。

## 本地开发与测试（不使用 Docker）

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 终端 A：托管示例公告页
cd sample-site && python -m http.server 8080
# 终端 B：启动 API
uvicorn app.main:app --reload --port 8000

# 测试（自带静态服务器，无需外部依赖）
pytest -q
```

## 设计说明

- 列表页抓取失败直接返回 `502`；详情页失败不影响整体响应，而是按业务规则沉淀为
  `pending` + 失败来源链接，便于投标专员人工核实。
- 关联归属判定结合详情页项目编号与列表行上下文（含编号列），
  即使详情页下线（只能看到列表行）也能正确判定失败是否与目标项目相关；
  无关项目的坏链接不会污染查询结果。
- 采集链路详情页并发抓取（上限 5），统一超时、自定义 UA、跟随重定向。
- 验真链路相反：**任何重定向都判为不可信**——镜像站常靠跳转把请求引到被篡改的
  副本，因此验真时清单、签名、详情页一律不跟随 3xx。
- 验真响应永远只包含 URL 与摘要等元数据；未通过核对的页面正文不进入响应，
  避免调用方在不知情时采信被篡改的内容。
