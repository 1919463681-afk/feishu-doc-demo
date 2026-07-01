# 飞书文档行为采集 Demo

基于飞书开放平台 API 的云文档用户行为采集示例服务。通过 **Webhook 实时事件**、**定时轮询** 与 **客户端埋点** 三种方式，采集文档的创建、编辑、评论、权限变更、分享、删除等行为，并统一写入本地活动日志。

> 仓库地址：https://github.com/1919463681-afk/feishu-doc-demo

---

## 功能概览

| 行为 | 采集字段 | 数据来源 |
|------|----------|----------|
| 创建 | 文档名、创建人、时间、知识库 | Webhook + 元数据 API |
| 查看 | 访问人、时间、停留时长、浏览页数 | `POST /track/view` 埋点 |
| 编辑 | 编辑人、时间、段落级变更摘要 | Webhook + 内容快照 diff |
| 评论 | 评论人、内容、划词引用、@ 用户 | 轮询 / Webhook + 评论 API |
| 下载 | 下载人、时间、导出格式 | `POST /track/download` 埋点 |
| 转发 | 转发人、目标、链接类型 | 协作者添加事件 / 轮询 |
| 分享 | 链接权限、是否对外 | 轮询公开权限 API |
| 删除 | 删除人、时间、回收站/永久 | Webhook + 轮询 |

完整字段说明：`GET /activities/schema`

---

## 环境要求

- Python 3.8+
- 依赖：`flask`、`requests`

```bash
pip install flask requests
```

---

## 快速开始

### 1. 克隆仓库

```bash
git clone https://github.com/1919463681-afk/feishu-doc-demo.git
cd feishu-doc-demo
```

### 2. 配置密钥

```bash
copy local_config.example.py local_config.py   # Windows
# cp local_config.example.py local_config.py   # Linux / macOS
```

编辑 `local_config.py`，填写飞书应用凭证与监听文件夹：

```python
APP_ID = "cli_xxxxxxxx"
APP_SECRET = "xxxxxxxx"
AUDIT_ROOT_FOLDER_TOKEN = "文件夹 token"   # 云盘文件夹 URL 中的 token
```

> `local_config.py` 已在 `.gitignore` 中，**不会提交到 Git**。

也可用环境变量（适合服务器部署）：

| 环境变量 | 说明 |
|----------|------|
| `FEISHU_APP_ID` | 应用 App ID |
| `FEISHU_APP_SECRET` | 应用 App Secret |
| `FEISHU_AUDIT_FOLDER_TOKEN` | 监听文件夹 token |
| `FEISHU_WIKI_SEED_NODE` | Wiki 节点 token（可选） |
| `FEISHU_AUDIT_DOC_TOKENS` | 额外文档 token，逗号分隔 |

### 3. 初始化快照（首次部署必做）

```bash
python demo.py snapshot-init
```

建立内容、权限、评论等基线，后续轮询才能检测变更。

### 4. 启动服务

```bash
python demo.py
```

默认监听 `http://0.0.0.0:3000`。

启动后会自动：

- 订阅共享文件夹及已有文件的文档事件
- 订阅用户评论通知（`drive.notice.comment_add_v1`）
- 启动后台轮询线程（默认每 300 秒）

---

## 飞书开放平台配置

在 [飞书开放平台](https://open.feishu.cn/) 创建企业自建应用，并完成以下配置。

### 权限（按需开通）

| 能力 | 建议权限 |
|------|----------|
| 文档事件订阅 | `docs:event:subscribe` |
| 文件夹新建事件 | `space:document.event:read` |
| 评论读取 | `docs:document.comment:read` |
| 协作者权限 | `docs:permission.member:retrieve` |
| 文档删除事件 | `docs:event.document_deleted:read` |
| 文档内容读取 | `docs:document.content:read` 等 |

### 事件订阅

**请求地址**（需公网可达，见下文内网穿透）：

```
https://你的域名/webhook
```

建议勾选的事件：

| 事件 | 说明 |
|------|------|
| `drive.file.created_in_folder_v1` | 文件夹内新建文件 |
| `drive.file.edit_v1` | 文档编辑 |
| `drive.file.permission_member_added_v1` | 添加协作者 |
| `drive.file.permission_member_removed_v1` | 移除协作者 |
| `drive.file.trashed_v1` / `drive.file.deleted_v1` | 删除 |
| `drive.notice.comment_add_v1` | 评论/回复通知 |

配置完成后点击 **发布**。

### 应用协作

- 将应用添加为监听文件夹内文档的 **可管理** 或 **可编辑** 协作者
- 应用对文件夹需有访问权限（共享文件夹给应用或所在群组）

### 内网穿透（本地开发）

飞书 Webhook 需要公网 URL，本地开发可用 [cpolar](https://www.cpolar.com/) 等工具：

```bash
cpolar http 3000
```

将生成的 HTTPS 地址配置到飞书「事件订阅 → Request URL」，例如：

```
https://xxxx.cpolar.top/webhook
```

---

## HTTP 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 服务状态、上次 Webhook 时间 |
| GET | `/diagnose` | 事件监听诊断 |
| POST | `/webhook` | 飞书事件回调（平台配置用） |
| GET | `/activities` | 查询行为记录，支持 `?activity_type=edit&limit=20` |
| GET | `/activities/schema` | 采集表字段说明 |
| POST | `/track/view` | 埋点：文档查看 |
| POST | `/track/download` | 埋点：文档下载/导出 |
| GET/POST | `/poll` | 手动触发一轮轮询 |
| GET/POST | `/snapshot/init` | 初始化快照基线 |
| GET | `/comments/fetch` | 调试：拉取单条评论详情 |
| GET | `/events` | 原始事件日志 |

### 埋点示例

**查看：**

```bash
curl -X POST http://localhost:3000/track/view \
  -H "Content-Type: application/json" \
  -d "{\"file_token\":\"doc_token\",\"file_type\":\"docx\",\"visitor\":{\"user_id\":\"ou_xxx\"},\"duration_seconds\":120,\"pages_viewed\":3}"
```

**下载：**

```bash
curl -X POST http://localhost:3000/track/download \
  -H "Content-Type: application/json" \
  -d "{\"file_token\":\"doc_token\",\"file_type\":\"docx\",\"downloader\":{\"user_id\":\"ou_xxx\"},\"export_format\":\"pdf\"}"
```

---

## 命令行

```bash
python demo.py                          # 启动 Flask 服务
python demo.py snapshot-init            # 初始化快照
python demo.py poll                     # 手动轮询
python demo.py activities 20 comment    # 查看最近 20 条评论活动
python demo.py diagnose                 # 诊断配置
python demo.py fetch-comment <token> <comment_id> docx   # 调试评论解析
python demo.py subscribe-all            # 订阅文件夹内所有文件
python demo.py audit-all                # 全量内容审核（敏感词）
```

---

## 数据存储

运行时会在项目目录生成以下文件（已在 `.gitignore` 中，不提交 Git）：

| 文件 | 说明 |
|------|------|
| `document_events.jsonl` | 统一活动日志（最多 2000 条） |
| `content_snapshot.json` | 文档正文快照（用于 diff） |
| `permission_snapshot.json` | 协作者权限快照 |
| `comment_snapshot.json` | 评论快照 |
| `public_permission_snapshot.json` | 公开链接权限快照 |
| `webhook_debug.jsonl` | Webhook 原始报文调试日志 |
| `local_config.py` | 本地密钥配置 |

---

## 架构说明

```
飞书云文档
    │
    ├─ Webhook（实时）─────► POST /webhook ──► document_events.jsonl
    │     新建 / 编辑 / 删除 / 评论通知
    │
    ├─ 轮询（每 300s）────► poll_* 函数 ────► document_events.jsonl
    │     权限变更 / 分享 / 评论 / 文件消失
    │
    └─ 客户端埋点 ────────► /track/* ─────► document_events.jsonl
          查看 / 下载（API 无法感知）
```

### 采集能力说明

- **编辑**：Webhook 触发后拉取文档正文，与快照对比生成段落级变更摘要
- **评论**：轮询稳定可用；Webhook（`drive.notice.comment_add_v1`）为通知类事件，仅当飞书会给用户发 App 内通知时才推送，自己评论自己可能无 Webhook
- **查看 / 下载**：飞书开放 API 不提供用户级事件，需业务侧调用埋点接口
- **分享链接有效期**：当前公开权限 API 未返回过期时间，字段可能为空

---

## 项目结构

```
feishu-doc-demo/
├── demo.py                  # 主程序（Flask 服务 + CLI）
├── local_config.example.py  # 配置模板（提交到 Git）
├── local_config.py          # 本地密钥（不提交）
├── .gitignore
└── README.md
```

---

## 常见问题

**Q: 收不到 Webhook？**

1. 确认 cpolar / 内网穿透与 Flask 同时运行
2. 飞书事件订阅 Request URL 指向当前 cpolar 地址 + `/webhook`
3. 事件已勾选并 **发布**
4. 访问 `GET /health` 查看 `last_webhook_at`

**Q: 评论只有轮询没有 Webhook？**

评论是通知类事件。建议用另一账号评论或 @ 协作者测试；服务启动时会自动调用用户订阅接口。

**Q: 权限 / 删除事件收不到？**

应用仅为文档「可管理」协作者时，飞书可能只推送编辑类事件。权限与删除依赖轮询或应用为文档所有者。

**Q: 国内访问 GitHub 慢？**

可配置 Git 代理，或同步一份到 Gitee 供团队使用。

---

## 安全提示

- 切勿将 `local_config.py` 或含 `APP_SECRET` 的文件提交到公开仓库
- 若密钥曾泄露，请在飞书开放平台 **重置 App Secret**
- 生产环境建议使用 WSGI 服务器（如 gunicorn）而非 Flask 开发服务器

---

## License

MIT（可按需修改）
