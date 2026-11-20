# ADR 0004: Authentication & Security

- **背景**：严禁明文传输 Token 或默认信任未认证客户端，且需防止内网穿透被滥用为开放代理。
- **最终决定**：
  1. 服务端下发随机 Nonce + 时间戳 Challenge，客户端使用 `HMAC-SHA256` 签名响应，服务端校验时间窗与常量时间签名。
  2. 支持 TLS 1.3 加密传输。
  3. 客户端强制通过 `TargetValidator` 校验 `allowed_targets` 白名单（默认仅允许回环地址）。
- **影响范围**：`internal/security/`、`internal/server/service`、`internal/client/service`。
