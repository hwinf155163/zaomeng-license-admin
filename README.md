# zaomeng-license-admin

卡密（激活码）授权后台 —— 给浏览器扩展 / 桌面软件做「输入卡密才能用、到期立即失效、一卡一机」的授权服务端。

基于 **Netlify Functions + Netlify Blobs**，零服务器，部署即用。

## 功能

- 卡密签发（分钟 / 小时 / 天 / 月 / 永久 五种时效）
- 一卡一机（设备指纹绑定，SHA-256）
- 60 秒短期令牌 + 30 秒心跳续租（ECDSA P-256 签名）
- 运行参数动态下发（AES-GCM 加密）
- 管理后台：生成 / 续费 / 禁用 / 解绑 / 删除（带回收站，90 天可恢复）
- 完整性基线上报
- 北京时间校时（防改本地时钟）

## 安全模型

```
卡密本体    HMAC-SHA256 签名（服务端密钥 CARD_KEY）
参数包      AES-256-GCM 加密（服务端密钥 TOKEN_KEY）
短期令牌    ECDSA P-256 签名（60 秒有效，私钥只在服务端）
管理会话    ECDSA 签名（1 小时）
```

所有密钥通过**环境变量**注入，仓库里没有任何密钥。加密强度不依赖代码保密，只依赖密钥保密。

## 部署到 Netlify

1. Fork / Clone 本仓库
2. 在 Netlify 新建站点，连接仓库（或用 CLI 上传 `api.js` 到 functions）
3. 配置环境变量（Site configuration → Environment variables）：

```
NETLIFY_BLOBS_SITE_ID = <你的 Blobs site ID>
NETLIFY_BLOBS_TOKEN   = <你的 Blobs token>
ZM_CARD_KEY           = <32 字节 hex，签卡密>
ZM_TOKEN_KEY          = <32 字节 hex，加密参数包>
ZM_PASS_HASH          = <管理密码的 SHA-256>
ZM_ECDSA_PRIV         = <EC P-256 私钥 JWK 的 JSON 字符串>
ZM_ECDSA_PUB          = <EC P-256 公钥 JWK 的 JSON 字符串>
```

生成密钥：

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # CARD_KEY / TOKEN_KEY
node -e "console.log(require('crypto').createHash('sha256').update('你的管理密码'.trim()).digest('hex'))"  # PASS_HASH
node -e "const{generateKeyPairSync}=require('crypto');const{publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});console.log(privateKey.export({format:'jwk'}));console.log(publicKey.export({format:'jwk'}))"
```

4. 部署，访问 `https://你的站点/.netlify/functions/api/pubkey` 验证

## API 一览

| 路径 | 方法 | 说明 |
|---|---|---|
| `/api/pubkey` | GET | ECDSA 公钥 |
| `/api/time` | GET | 服务器时间 |
| `/api/activate` | POST | 激活卡密 |
| `/api/renew` | POST | 心跳续租（30 秒） |
| `/api/integrity` | POST | 完整性上报 |
| `/api/admin/*` | GET/POST | 管理接口（登录 / 生成 / 续费 / 禁用 / 解绑 / 删除 / 回收站） |

## 客户端对接

客户端（如浏览器扩展）需要：

1. 持有 ECDSA 公钥（验令牌 / 验 requestPrefix）
2. 激活后把令牌存内存，30 秒调一次 `/api/renew`
3. 用令牌里的 `rk` 解密参数包
4. 到期 / 禁用 / 删除时收到 403 立即停用

## 许可

GPL-3.0-or-later
