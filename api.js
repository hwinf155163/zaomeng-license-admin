/**
 * 造梦2.0 卡密授权 API v3
 *
 * 新架构：
 *   · 卡密 = 激活码，内含「时长」而非「到期时间」
 *   · 首次激活时服务端记录激活时间，才开始计时
 *   · 支持续费、删除（拉黑）、查询激活记录
 *   · 数据存 Netlify Blobs
 */

const crypto = require("node:crypto");
const { getStore } = require("@netlify/blobs");
const BLOBS_SITE_ID = process.env.NETLIFY_BLOBS_SITE_ID;
const BLOBS_TOKEN = process.env.NETLIFY_BLOBS_TOKEN;

/* ========== 密钥 ========== */
const CARD_KEY = process.env.ZM_CARD_KEY;
const TOKEN_KEY = process.env.ZM_TOKEN_KEY;
const ADMIN_PASS_HASH = process.env.ZM_PASS_HASH;

/* ========== ECDSA 密钥（关键：私钥只在服务端，客户端只有公钥） ========== */
const ECDSA_PRIV_JWK = process.env.ZM_ECDSA_PRIV ? JSON.parse(process.env.ZM_ECDSA_PRIV) : null;
const ECDSA_PUB_JWK = process.env.ZM_ECDSA_PUB ? JSON.parse(process.env.ZM_ECDSA_PUB) : null;
// 环境变量自检：缺任何一个直接抛错（在 Netlify 后台 Site configuration → Environment variables 里配置）
if (!BLOBS_SITE_ID || !BLOBS_TOKEN || !CARD_KEY || !TOKEN_KEY || !ADMIN_PASS_HASH || !ECDSA_PRIV_JWK) {
  throw new Error("缺少环境变量：需要 NETLIFY_BLOBS_SITE_ID / NETLIFY_BLOBS_TOKEN / ZM_CARD_KEY / ZM_TOKEN_KEY / ZM_PASS_HASH / ZM_ECDSA_PRIV");
}
const ecdsaPriv = crypto.createPrivateKey({ key: ECDSA_PRIV_JWK, format: "jwk" });

const TOKEN_TTL = 60;
const SESSION_TTL = 3600;
const B32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const TYPE_CODE = { "体验": 1, "标准": 2, "专业": 3, "永久": 4 };
const CODE_TYPE = {};
for (const k in TYPE_CODE) CODE_TYPE[TYPE_CODE[k]] = k;

/* ========== 工具 ========== */
function toB32(bytes) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function fromB32(str) {
  let bits = 0, value = 0;
  const out = [];
  for (const c of String(str).toUpperCase()) {
    const idx = B32.indexOf(c);
    if (idx < 0) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function mac(key, data, len) {
  return crypto.createHmac("sha256", key).update(data).digest().slice(0, len);
}
function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

/* ========== 卡密编解码（改：存时长，不存到期时间） ========== */
const UNIT_CODE = { minute: 1, hour: 2, day: 3, month: 4, forever: 5 };
const CODE_UNIT = {};
for (const k in UNIT_CODE) CODE_UNIT[UNIT_CODE[k]] = k;

/**
 * 卡密载荷（11 字节）：
 *   [0] 版本
 *   [1] 类型码
 *   [2] 时长单位
 *   [3-6] 时长数值（uint32）
 *   [7-9] 随机ID
 *   [10] 保留
 */
function encodeCard({ type = "通用", unit = "day", amount = 30 }) {
  const buf = Buffer.alloc(11);
  buf[0] = 2;
  buf[1] = TYPE_CODE[type] || 2;
  buf[2] = UNIT_CODE[unit] || 3;
  buf.writeUInt32BE(unit === "forever" ? 0 : (amount >>> 0), 3);
  crypto.randomBytes(3).copy(buf, 7);
  return "ZMDB-" + toB32(buf) + "-" + toB32(mac(CARD_KEY, buf, 8));
}
function decodeCard(card) {
  const m = /^ZMDB-([A-Z0-9]+)-([A-Z0-9]+)$/.exec(String(card || "").trim().toUpperCase());
  if (!m) return { ok: false, code: "BAD_FORMAT", message: "卡密格式不正确" };
  const data = fromB32(m[1]);
  const tag = fromB32(m[2]);
  if (data.length < 11 || tag.length < 8) return { ok: false, code: "BAD_FORMAT", message: "卡密内容损坏" };
  if (!crypto.timingSafeEqual(mac(CARD_KEY, data, 8), tag.slice(0, 8))) {
    return { ok: false, code: "BAD_SIGNATURE", message: "卡密无效" };
  }
  if (data[0] !== 2) return { ok: false, code: "BAD_VERSION", message: "卡密版本不支持，请用新生成的卡密" };
  const unit = CODE_UNIT[data[2]] || "day";
  const amount = data.readUInt32BE(3);
  return {
    ok: true,
    payload: {
      type: CODE_TYPE[data[1]] || "标准",
      unit,
      amount,
      id: data.slice(7, 10).toString("hex")
    }
  };
}

/* ========== 时长计算 ========== */
function durationMs(unit, amount) {
  if (unit === "forever") return Infinity;
  const map = { minute: 60000, hour: 3600000, day: 86400000, month: 2592000000 };
  return amount * (map[unit] || 86400000);
}

/* ========== 令牌 ========== */
// 令牌用 ECDSA 私钥签（客户端只有公钥，无法伪造）
function signToken(p) {
  const data = Buffer.from(JSON.stringify(p), "utf8");
  return crypto.sign("sha256", data, { key: ecdsaPriv, dsaEncoding: "ieee-p1363" }).toString("base64url");
}
function verifyToken(p, sig) {
  try {
    const pub = crypto.createPublicKey({ key: ECDSA_PUB_JWK, format: "jwk" });
    const data = Buffer.from(JSON.stringify(p), "utf8");
    return crypto.verify("sha256", data, { key: pub, dsaEncoding: "ieee-p1363" },
      Buffer.from(String(sig).replace(/-/g, "+").replace(/_/g, "/"), "base64"));
  } catch (_) { return false; }
}

/* ========== 参数加密 ========== */
function encryptParams(obj, rk) {
  const key = crypto.createHash("sha256").update(String(rk)).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(obj), "utf8"), cipher.final()]);
  return { data: enc.toString("base64"), iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
}

function issue(card, device, rec) {
  const now = Math.floor(Date.now() / 1000);
  const rk = crypto.randomBytes(24).toString("base64url");
  const token = { v: 1, jti: crypto.randomUUID(), card, device, iat: now, exp: now + TOKEN_TTL, rk };
  const sig = signToken(token);
  // 关键：requestPrefix 带服务端签名，客户端验证真伪
  const requestPrefix = crypto.randomUUID();
  const prefixSig = crypto.sign("sha256",
    Buffer.from("prefix|" + requestPrefix + "|" + card, "utf8"),
    { key: ecdsaPriv, dsaEncoding: "ieee-p1363" }).toString("base64url");
  const params = encryptParams({
    requestPrefix,
    prefixSig,          // 服务端签名，客户端验签
    grid: { gap: 192, perRow: 10 },
    canvasNodeTitle: "视频",
    draftKind: "video",
    issuedFor: card,
    issuedAt: Date.now()
  }, rk);
  return {
    token, sig, params, serverTime: now, ttl: TOKEN_TTL,
    jitter: 8000 + Math.floor(Math.random() * 12000),
    type: rec.type,
    activatedAt: rec.activatedAt ? new Date(rec.activatedAt).toISOString() : null,
    expiresAt: rec.expiresAt === 0 ? null : (rec.expiresAt ? new Date(rec.expiresAt).toISOString() : null),
    permanent: rec.expiresAt === 0,
    remainMs: rec.expiresAt === 0 ? null : Math.max(0, rec.expiresAt - Date.now())
  };
}

/* ========== 限速 ========== */
const rateBuckets = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  let b = rateBuckets.get(key);
  if (!b || now - b.start > windowMs) { b = { start: now, count: 0 }; rateBuckets.set(key, b); }
  b.count++;
  return b.count <= max;
}

/* ========== 主处理 ========== */
exports.handler = async (event) => {
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff"
  };
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: cors, body: "" };

  const path = String(event.path || "").replace(/^.*\/api\/?/, "").replace(/\/+$/, "");
  const body = (() => { try { return JSON.parse(event.body || "{}"); } catch (_) { return {}; } })();
  const ip = event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || "0.0.0.0";
  const ok = (code, obj) => ({ statusCode: code, headers: cors, body: JSON.stringify(obj) });

  try {
    const store = getStore({ name: "zaomeng-cards", siteID: BLOBS_SITE_ID, token: BLOBS_TOKEN });

    /* ---------- 公钥 ---------- */
    if (path === "pubkey") return ok(200, {
      ok: true, alg: "ECDSA-P256-SHA256", ttl: TOKEN_TTL, pubJwk: ECDSA_PUB_JWK
    });

    /* ---------- 服务器时间（北京时间基准，防改本地时钟） ---------- */
    if (path === "time") {
      const now = Date.now();
      return ok(200, {
        ok: true,
        serverTime: now,
        // 北京时间字符串，方便直接显示
        beijing: new Date(now + 8 * 3600000).toISOString().replace("Z", "+08:00"),
        timezone: "Asia/Shanghai"
      });
    }

    /* ---------- 完整性校验 ---------- */
    if (path === "integrity" && event.httpMethod === "POST") {
      const hashes = body.hashes || {};
      const device = String(body.device || "").slice(0, 128);
      const baseline = await store.get("__baseline", { type: "json" });

      if (!baseline) {
        await store.setJSON("__baseline", { hashes, createdAt: Date.now(), device });
        return ok(200, { ok: true, message: "基线已建立" });
      }

      const bad = Object.keys(baseline.hashes || {}).filter(
        (k) => hashes[k] && hashes[k] !== baseline.hashes[k]
      );
      if (bad.length) {
        return ok(403, { ok: false, code: "TAMPERED", message: "文件被修改：" + bad.join("、") });
      }
      return ok(200, { ok: true });
    }

    /* ---------- 激活 ---------- */
    if (path === "activate" && event.httpMethod === "POST") {
      if (!rateLimit("act:" + ip, 10, 60000)) {
        return ok(429, { ok: false, code: "RATE_LIMIT", message: "尝试过于频繁，请 1 分钟后再试" });
      }
      const card = String(body.card || "").trim().toUpperCase();
      const device = String(body.device || "").trim().slice(0, 128);
      if (!card || !device) return ok(400, { ok: false, code: "BAD_REQUEST", message: "缺少卡密或设备码" });

      const dec = decodeCard(card);
      if (!dec.ok) return ok(400, { ok: false, code: dec.code, message: dec.message });
      const p = dec.payload;

      // 查服务端记录
      let rec = await store.get(card, { type: "json" });

      // 已删除/拉黑
      if (rec && rec.deleted) {
        return ok(403, { ok: false, code: "DELETED", message: "该卡密已被删除，请联系卖家" });
      }
      // 已禁用
      if (rec && rec.disabled) {
        return ok(403, { ok: false, code: "DISABLED", message: "该卡密已被禁用" });
      }
      // 已过期
      if (rec && rec.expiresAt !== 0 && rec.expiresAt && Date.now() > rec.expiresAt) {
        return ok(403, { ok: false, code: "EXPIRED", message: "卡密已到期，请续费" });
      }
      // 设备绑定校验
      if (rec && rec.device && rec.device !== device) {
        return ok(403, { ok: false, code: "DEVICE_MISMATCH", message: "该卡密已绑定其他设备，请联系卖家解绑" });
      }

      // 首次激活：记录激活时间，开始计时
      if (!rec) {
        const now = Date.now();
        const dur = durationMs(p.unit, p.amount);
        rec = {
          card,
          type: p.type,
          unit: p.unit,
          amount: p.amount,
          activatedAt: now,
          expiresAt: dur === Infinity ? 0 : now + dur,
          device,
          disabled: false,
          deleted: false,
          renewCount: 0,
          createdAt: now
        };
        await store.setJSON(card, rec);
      } else {
        // 已有记录：更新设备与最后活跃
        rec.device = device;
        rec.lastSeenAt = Date.now();
        await store.setJSON(card, rec);
      }

      return ok(200, { ok: true, licensed: true, ...issue(card, device, rec) });
    }

    /* ---------- 心跳 ---------- */
    if (path === "renew" && event.httpMethod === "POST") {
      if (!rateLimit("ren:" + ip, 30, 60000)) {
        return ok(429, { ok: false, code: "RATE_LIMIT", message: "心跳过于频繁" });
      }
      const payload = body.token || {};
      const sig = body.sig || "";
      const device = String(body.device || "").trim().slice(0, 128);
      if (!payload.card || !device || !sig) return ok(400, { ok: false, code: "BAD_REQUEST", message: "参数不全" });
      if (!verifyToken(payload, sig)) return ok(403, { ok: false, code: "BAD_SIGNATURE", message: "令牌签名无效" });
      if (payload.device !== device) return ok(403, { ok: false, code: "DEVICE_MISMATCH", message: "设备不匹配" });

      const rec = await store.get(payload.card, { type: "json" });
      if (!rec) {
        // 查回收站：区分「从未激活」和「已被删除」
        const bin = await store.get("__trash", { type: "json" });
        const inTrash = (bin?.items || []).some((x) => x.card === payload.card);
        if (inTrash) {
          return ok(403, { ok: false, code: "DELETED", message: "卡密已被删除，请联系卖家" });
        }
        return ok(403, { ok: false, code: "NOT_ACTIVATED", message: "卡密未激活或已被删除" });
      }
      if (rec.deleted) return ok(403, { ok: false, code: "DELETED", message: "该卡密已被删除" });
      if (rec.disabled) return ok(403, { ok: false, code: "DISABLED", message: "该卡密已被禁用" });
      if (rec.expiresAt !== 0 && rec.expiresAt && Date.now() > rec.expiresAt) {
        return ok(403, { ok: false, code: "EXPIRED", message: "卡密已到期，请续费" });
      }
      if (rec.device !== device) return ok(403, { ok: false, code: "DEVICE_MISMATCH", message: "设备不匹配" });

      rec.lastSeenAt = Date.now();
      await store.setJSON(payload.card, rec);
      return ok(200, { ok: true, licensed: true, ...issue(payload.card, device, rec) });
    }

    /* ---------- 管理登录 ---------- */
    if (path === "admin/login" && event.httpMethod === "POST") {
      if (!rateLimit("login:" + ip, 5, 60000)) {
        return ok(429, { ok: false, code: "RATE_LIMIT", message: "登录尝试过多，请稍后再试" });
      }
      const pwd = String(body.password || "");
      const h = crypto.createHash("sha256").update("zm-admin|" + pwd).digest("hex");
      const a = Buffer.from(h.padEnd(64, "0"));
      const b = Buffer.from(ADMIN_PASS_HASH.padEnd(64, "0"));
      if (!crypto.timingSafeEqual(a, b)) return ok(401, { ok: false, message: "密码错误" });

      const sess = { exp: Date.now() + SESSION_TTL * 1000, r: crypto.randomBytes(8).toString("hex") };
      const sessSig = crypto.sign("sha256", Buffer.from(JSON.stringify(sess), "utf8"), { key: ecdsaPriv, dsaEncoding: "ieee-p1363" }).toString("base64url");
      return ok(200, { ok: true, token: b64url(Buffer.from(JSON.stringify(sess))) + "." + sessSig, expiresIn: SESSION_TTL });
    }

    /* ---------- 管理接口鉴权 ---------- */
    const needAuth = path.startsWith("admin/") && path !== "admin/login";
    if (needAuth) {
      const auth = String(event.headers.authorization || "").replace(/^Bearer\s+/i, "");
      const [sessB64, sessSig] = auth.split(".");
      if (!sessB64 || !sessSig) return ok(401, { ok: false, message: "未登录" });
      let sess;
      try { sess = JSON.parse(Buffer.from(sessB64.replace(/-/g,"+").replace(/_/g,"/"), "base64").toString("utf8")); } catch (_) {
        return ok(401, { ok: false, message: "会话无效" });
      }
      // ECDSA 签名每次不同，必须用公钥验签（不能比对字符串）
      let sessOk = false;
      try {
        const pub = crypto.createPublicKey({ key: ECDSA_PUB_JWK, format: "jwk" });
        sessOk = crypto.verify("sha256", Buffer.from(JSON.stringify(sess), "utf8"),
          { key: pub, dsaEncoding: "ieee-p1363" },
          Buffer.from(String(sessSig).replace(/-/g, "+").replace(/_/g, "/"), "base64"));
      } catch (_) { sessOk = false; }
      if (!sessOk) return ok(401, { ok: false, message: "会话签名无效" });
      if (Date.now() > sess.exp) return ok(401, { ok: false, message: "会话已过期" });
    }

    /* ---------- 重置完整性基线 ---------- */
    if (path === "admin/reset-baseline" && event.httpMethod === "POST") {
      await store.delete("__baseline");
      return ok(200, { ok: true, message: "基线已重置，下次上报会重新建立" });
    }

    /* ---------- 生成卡密 ---------- */
    if (path === "admin/create" && event.httpMethod === "POST") {
      const unit = String(body.unit || "day");
      const amount = Number(body.amount || 0);
      const count = Math.min(Math.max(Number(body.count || 1), 1), 200);
      const type = String(body.type || "通用").slice(0, 10);
      if (!["minute", "hour", "day", "month", "forever"].includes(unit)) {
        return ok(400, { ok: false, message: "时间单位不正确" });
      }
      if (unit !== "forever" && (amount <= 0 || amount > 100000)) {
        return ok(400, { ok: false, message: "时长数值不正确" });
      }
      const created = [];
      for (let i = 0; i < count; i++) {
        const card = encodeCard({ type, unit, amount });
        created.push({
          card, type, unit, amount,
          durationText: unit === "forever" ? "永久" : amount + " " + ({ minute:"分钟", hour:"小时", day:"天", month:"月" }[unit]),
          activated: false,
          createdAt: Date.now()
        });
      }
      return ok(200, { ok: true, created, unit, amount, type });
    }

    /* ---------- 查询卡密状态 ---------- */
    if (path === "admin/status" && event.httpMethod === "POST") {
      const cards = Array.isArray(body.cards) ? body.cards : [body.card].filter(Boolean);
      const out = [];
      for (const c of cards) {
        const card = String(c).toUpperCase();
        const rec = await store.get(card, { type: "json" });
        out.push({ card, record: rec || null });
      }
      return ok(200, { ok: true, list: out });
    }

    /* ---------- 续费 ---------- */
    if (path === "admin/renew" && event.httpMethod === "POST") {
      const card = String(body.card || "").toUpperCase();
      const unit = String(body.unit || "day");
      const amount = Number(body.amount || 0);
      if (!card) return ok(400, { ok: false, message: "缺少卡密" });
      if (!["minute", "hour", "day", "month", "forever"].includes(unit)) {
        return ok(400, { ok: false, message: "时间单位不正确" });
      }

      const rec = await store.get(card, { type: "json" });
      if (!rec) return ok(404, { ok: false, message: "该卡密还没激活过，无法续费" });

      if (unit === "forever") {
        rec.expiresAt = 0;
      } else {
        const dur = durationMs(unit, amount);
        const base = Math.max(rec.expiresAt || 0, Date.now());
        rec.expiresAt = base + dur;
      }
      rec.renewCount = (rec.renewCount || 0) + 1;
      rec.lastRenewAt = Date.now();
      await store.setJSON(card, rec);
      return ok(200, {
        ok: true, card,
        expiresAt: rec.expiresAt === 0 ? null : new Date(rec.expiresAt).toISOString(),
        permanent: rec.expiresAt === 0,
        renewCount: rec.renewCount
      });
    }

    /* ---------- 删除（真删 + 回收站备份） ---------- */
    if (path === "admin/delete" && event.httpMethod === "POST") {
      const card = String(body.card || "").toUpperCase();
      if (!card) return ok(400, { ok: false, message: "缺少卡密" });
      // ① 先读原记录
      const rec = await store.get(card, { type: "json" });
      // ② 写进回收站（保留 90 天，可恢复）
      try {
        const bin = (await store.get("__trash", { type: "json" })) || { items: [] };
        bin.items = (bin.items || []).filter((x) => x.card !== card);
        bin.items.unshift({
          card,
          record: rec || null,
          deletedAt: Date.now(),
          deletedBy: "admin"
        });
        // 只留最近 500 条
        bin.items = bin.items.slice(0, 500);
        await store.setJSON("__trash", bin);
      } catch (e) {
        return ok(500, { ok: false, message: "写回收站失败：" + e.message });
      }
      // ③ 真删主记录
      try {
        await store.delete(card);
      } catch (e) {
        // 记录本来就不存在也当成功
      }
      // ④ 再写一条墓碑（防止已激活的客户端继续用 60 秒）
      try {
        await store.setJSON("__tomb_" + card, { card, deletedAt: Date.now() });
      } catch (_) {}
      return ok(200, { ok: true, message: "已删除（可在回收站恢复）" });
    }

    /* ---------- 回收站：查看 ---------- */
    if (path === "admin/trash" && event.httpMethod === "GET") {
      const bin = (await store.get("__trash", { type: "json" })) || { items: [] };
      const now = Date.now();
      // 只返回 90 天内的
      const items = (bin.items || []).filter((x) => now - (x.deletedAt || 0) < 90 * 86400 * 1000);
      return ok(200, { ok: true, items, total: items.length });
    }

    /* ---------- 回收站：恢复 ---------- */
    if (path === "admin/restore" && event.httpMethod === "POST") {
      const card = String(body.card || "").toUpperCase();
      if (!card) return ok(400, { ok: false, message: "缺少卡密" });
      const bin = (await store.get("__trash", { type: "json" })) || { items: [] };
      const hit = (bin.items || []).find((x) => x.card === card);
      if (!hit) return ok(404, { ok: false, message: "回收站里没有这张卡密" });
      if (hit.record) {
        await store.setJSON(card, hit.record);
      } else {
        await store.setJSON(card, { card, restored: true, restoredAt: Date.now() });
      }
      bin.items = (bin.items || []).filter((x) => x.card !== card);
      await store.setJSON("__trash", bin);
      try { await store.delete("__tomb_" + card); } catch (_) {}
      return ok(200, { ok: true, message: "已恢复" });
    }

    /* ---------- 回收站：彻底清除 ---------- */
    if (path === "admin/purge" && event.httpMethod === "POST") {
      const card = String(body.card || "").toUpperCase();
      const bin = (await store.get("__trash", { type: "json" })) || { items: [] };
      bin.items = (bin.items || []).filter((x) => x.card !== card);
      await store.setJSON("__trash", bin);
      return ok(200, { ok: true, message: "已彻底清除" });
    }

    /* ---------- 禁用/启用 ---------- */
    if ((path === "admin/disable" || path === "admin/enable") && event.httpMethod === "POST") {
      const card = String(body.card || "").toUpperCase();
      const rec = await store.get(card, { type: "json" });
      if (!rec) return ok(404, { ok: false, message: "该卡密还没激活过" });
      rec.disabled = path === "admin/disable";
      await store.setJSON(card, rec);
      return ok(200, { ok: true });
    }

    /* ---------- 解绑设备 ---------- */
    if (path === "admin/unbind" && event.httpMethod === "POST") {
      const card = String(body.card || "").toUpperCase();
      const rec = await store.get(card, { type: "json" });
      if (!rec) return ok(404, { ok: false, message: "该卡密还没激活过" });
      rec.device = null;
      rec.unboundAt = Date.now();
      await store.setJSON(card, rec);
      return ok(200, { ok: true });
    }

    /* ---------- 列表（所有已激活卡密） ---------- */
    if (path === "admin/list" && event.httpMethod === "GET") {
      const { blobs } = await store.list();
      const list = [];
      for (const b of blobs) {
        // 跳过内部记录（回收站/墓碑/基线等）
        if (String(b.key).startsWith("__")) continue;
        const rec = await store.get(b.key, { type: "json" });
        if (!rec) continue;
        // 跳过已标记删除的
        if (rec.deleted) continue;
        list.push(rec);
      }
      list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return ok(200, { ok: true, list, total: list.length });
    }

    return ok(404, { ok: false, message: "Not Found" });
  } catch (e) {
    return ok(500, { ok: false, message: e.message });
  }
};
