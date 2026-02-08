# Tailscale Webhook 转发到钉钉（阿里云函数计算）

本项目提供一个最小实现：在阿里云函数计算（FC）中接收 Tailscale 的 Webhook，校验 Tailscale Webhook Secret，并将事件转发到 **钉钉群机器人（加签模式）**。

## 功能点

- 校验 Tailscale Webhook Secret（HMAC-SHA256）
- 支持钉钉群机器人加签（timestamp + secret）
- 适配阿里云函数计算 HTTP 触发器

## 部署步骤（阿里云函数计算）

1. 创建函数
   - Runtime：Python 3.9（或 3.10）
   - 触发器：HTTP 触发器（POST）
   - 入口函数：`handler.handler`
2. 配置环境变量
   - `TAILSCALE_WEBHOOK_SECRET`：Tailscale Webhook Secret
   - `DINGTALK_WEBHOOK_URL`：钉钉群机器人 Webhook URL（不带 sign 与 timestamp）
   - `DINGTALK_SIGNING_SECRET`：钉钉群机器人加签密钥
3. 依赖
   - `requests`
4. 将 `handler.py` 与 `requirements.txt` 上传部署
5. 在 Tailscale 管理台设置 Webhook URL 为函数的公网 HTTP 触发器地址

## 事件内容

函数默认将 Tailscale Webhook 原始 JSON 内容压缩为一行文本，并附带 `event_type` 字段（若存在），发送到钉钉。

## 安全校验说明

- **Tailscale Webhook Secret**：通过请求头 `X-Tailscale-Signature` 校验。签名格式为 `sha256=<hex>`，使用 `TAILSCALE_WEBHOOK_SECRET` 对原始请求体进行 HMAC-SHA256。
- **钉钉加签**：使用 `timestamp + "\n" + secret` 进行 HMAC-SHA256，并进行 Base64 + URL 编码。

## 本地调试（可选）

你可以用 curl 模拟请求：

```bash
curl -X POST "$FC_HTTP_URL" \
  -H "Content-Type: application/json" \
  -H "X-Tailscale-Signature: sha256=<your-signature>" \
  -d '{"event_type":"test","message":"hello"}'
```

> 注意：签名必须基于**原始请求体**计算。

## 文件说明

- `handler.py`：函数入口逻辑
- `requirements.txt`：依赖列表
