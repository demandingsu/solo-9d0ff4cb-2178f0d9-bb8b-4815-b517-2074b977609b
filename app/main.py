"""FastAPI 入口：公告采集 API + 批次验真 API。

端点：
* GET  /                     演示页（可直接在浏览器发起采集 / 验真）
* POST /api/v1/collect       传入列表页 URL 与项目编号，返回合并后的投标状态
* GET  /api/v1/collect       同上的查询参数形式，便于浏览器/curl 快速演示
* POST /api/v1/verify-batch  批次验真：Ed25519 验签 + 清单摘要逐页核对
* GET  /healthz              健康检查
"""

from __future__ import annotations

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

from app.collector import collect
from app.models import FetchRequest, FetchResponse, VerifyRequest, VerifyResponse
from app.verifier import verify_batch

app = FastAPI(
    title="采购公告采集 API",
    description=(
        "抓取同站点原公告与更正公告，按发布时间合并，输出投标状态与有效截止时间；"
        "并提供基于 Ed25519 签名清单的批次验真，识别镜像站点上冒充正式发布的公告批次。"
    ),
    version="1.1.0",
)


_DEMO_PAGE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>采购公告采集 / 批次验真 API 演示</title>
<style>
body { font-family: system-ui, "PingFang SC", "Microsoft YaHei", sans-serif; margin: 2rem; max-width: 960px; }
input { width: 32rem; max-width: 80vw; padding: .4rem; }
button { padding: .45rem 1.2rem; cursor: pointer; }
pre { background: #f4f4f6; padding: 1rem; border-radius: 8px; overflow:auto; max-height: 60vh; }
.hint { color: #666; font-size: .9rem; }
fieldset { margin-bottom: 1.5rem; border: 1px solid #ddd; border-radius: 8px; }
legend { font-weight: 600; }
</style>
</head>
<body>
<h1>采购公告采集 / 批次验真 API 演示</h1>
<p class="hint">示例站点由 docker compose 中的 nginx 提供，默认地址 <code>http://localhost:8080/list.html</code>；
在 Docker Compose 网络内调用时请改用 <code>http://sample-site/</code> 作为站点地址。</p>

<fieldset>
<legend>公告采集</legend>
<form id="collect-form">
  <p><label>列表页 URL <input id="list_url" value="http://localhost:8080/list.html"></label></p>
  <p><label>项目编号 <input id="project_code" value="GSB-2026-001"></label></p>
  <button type="submit">采集并合并</button>
</form>
</fieldset>

<fieldset>
<legend>批次验真（识别镜像站点伪造公告）</legend>
<form id="verify-form">
  <p><label>清单 URL <input id="manifest_url" value="http://localhost:8080/manifest/batch-ok.json"></label></p>
  <p><label>签名 URL <input id="signature_url" value="http://localhost:8080/manifest/batch-ok.sig"></label></p>
  <p><label>公钥（Base64） <input id="public_key" value="A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="></label></p>
  <p class="hint">可换成 <code>batch-forged.json/.sig</code>（伪造签名）或
  <code>batch-changed.json/.sig</code>（内容已变更）体验不可信判定；演示公钥见
  <code>sample-site/manifest/public.key</code>。</p>
  <button type="submit">验证批次</button>
</form>
</fieldset>

<pre id="out">响应将显示在这里……</pre>
<script>
async function post(url, payload) {
  const out = document.getElementById('out');
  out.textContent = '请求中……';
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    out.textContent = JSON.stringify(await resp.json(), null, 2);
  } catch (err) {
    out.textContent = '请求失败：' + err;
  }
}
document.getElementById('collect-form').addEventListener('submit', (e) => {
  e.preventDefault();
  post('/api/v1/collect', {
    list_url: document.getElementById('list_url').value,
    project_code: document.getElementById('project_code').value
  });
});
document.getElementById('verify-form').addEventListener('submit', (e) => {
  e.preventDefault();
  post('/api/v1/verify-batch', {
    manifest_url: document.getElementById('manifest_url').value,
    signature_url: document.getElementById('signature_url').value,
    public_key: document.getElementById('public_key').value
  });
});
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def demo_page() -> str:
    return _DEMO_PAGE


@app.get("/healthz", tags=["ops"])
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/collect", response_model=FetchResponse, tags=["collect"])
async def collect_post(req: FetchRequest) -> FetchResponse:
    return await collect(req)


@app.get("/api/v1/collect", response_model=FetchResponse, tags=["collect"])
async def collect_get(
    list_url: str = Query(..., description="采购公告列表页 URL"),
    project_code: str = Query(..., description="项目编号"),
    timeout: float = Query(10.0, ge=1.0, le=60.0),
) -> FetchResponse:
    return await collect(FetchRequest(list_url=list_url, project_code=project_code, timeout=timeout))


@app.post("/api/v1/verify-batch", response_model=VerifyResponse, tags=["verify"])
async def verify_batch_post(req: VerifyRequest) -> VerifyResponse:
    """批次验真：先验签（签名覆盖清单原始字节），再逐页核对清单声明的 SHA-256。

    任何环节失败都返回 ``trusted=false`` 并逐项说明原因与来源；
    响应不包含未经验证的页面正文。
    """
    return await verify_batch(req)
