# 复制本文件为 local_config.py 并填写真实值。
# local_config.py 已加入 .gitignore，不会提交到 Git。

# 飞书开放平台 → 应用凭证
APP_ID = "cli_xxxxxxxx"
APP_SECRET = "xxxxxxxxxxxxxxxxxxxxxxxx"

# 监听的共享文件夹 token（云盘文件夹 URL 中的 token）
AUDIT_ROOT_FOLDER_TOKEN = ""

# 知识库：可填多个 space_id；或填一个 wiki 节点 token 自动解析
AUDIT_WIKI_SPACE_IDS = []
AUDIT_WIKI_SEED_NODE = ""

# 额外要审核的文档 token 列表
AUDIT_DOC_TOKENS = []

# ---------- 审核未通过时的处理策略 ----------
# 可选动作（可组合，逗号分隔或列表）：
#   log_only  — 仅记录（默认）
#   highlight — docx 敏感词高亮
#   replace   — docx 敏感词替换为占位符
#   lock      — 文档加锁（可选同时关闭链接分享）
#   notify    — 飞书 IM 通知负责人
AUDIT_POLICY_ACTIONS = ["log_only"]

# replace 时使用的占位符
AUDIT_MASK_TEXT = "***"

# 通知接收人 open_id 列表；留空则自动取文档所有者 / 可管理协作者
AUDIT_NOTIFY_USER_IDS = []

# 高亮背景色（飞书 text_element_style.background_color 枚举，3 为黄色）
AUDIT_HIGHLIGHT_COLOR = 3

# lock 时是否同时收紧链接分享：closed / tenant_readable / 留空表示仅加锁
AUDIT_LOCK_RESTRICT_SHARE = "closed"
