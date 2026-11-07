import { createHmac, randomBytes } from "node:crypto"

function sanitizeCategory(input) {
  const raw = String(input ?? "").trim()
  if (!raw) return "TEXT"
  const upper = raw.toUpperCase()
  const safe = upper.replace(/[^A-Z0-9_]/g, "_").replace(/_+/g, "_")
  if (!safe) return "TEXT"
  return safe
}

function toHexLower(buffer) {
  return Buffer.from(buffer).toString("hex")
}

/**
 * 会话内占位符映射管理器：
 * - 生成占位符：__VG_<CATEGORY>_<hash12>__（与 VibeGuard 一致）
 * - hash12：HMAC-SHA256(会话随机 secret, 原文) 的 12 位十六进制小写截断
 * - 维护 placeholder <-> original 的双向映射，用于工具执行前还原
 */
export class PlaceholderSession {
  /**
   * @param {{ prefix: string, ttlMs: number, maxMappings: number, secret?: Uint8Array }} options
   */
  constructor(options) {
    const prefix = String(options?.prefix ?? "__VG_")
    this.prefix = prefix
    this.ttlMs = Number.isFinite(options?.ttlMs) ? Number(options.ttlMs) : 60 * 60 * 1000
    this.maxMappings = Number.isFinite(options?.maxMappings) ? Number(options.maxMappings) : 100000
    this.secret = options?.secret ? Uint8Array.from(options.secret) : randomBytes(32)

    /** @type {Map<string,string>} */
    this.forward = new Map()
    /** @type {Map<string,string>} */
    this.reverse = new Map()
    /** @type {Map<string,number>} */
    this.created = new Map()
    /** Bumped on every mapping change; used by the persistence barrier. */
    this.revision = 0
  }

  cleanup(now = Date.now()) {
    if (!Number.isFinite(this.ttlMs) || this.ttlMs <= 0) return
    for (const [placeholder, createdAt] of this.created.entries()) {
      if (now - createdAt <= this.ttlMs) continue
      const original = this.forward.get(placeholder)
      this.forward.delete(placeholder)
      this.created.delete(placeholder)
      if (original !== undefined) this.reverse.delete(original)
    }
  }

  evictOldest() {
    let oldestPlaceholder = ""
    let oldestTime = Infinity
    for (const [placeholder, createdAt] of this.created.entries()) {
      if (createdAt >= oldestTime) continue
      oldestTime = createdAt
      oldestPlaceholder = placeholder
    }
    if (!oldestPlaceholder) return
    const original = this.forward.get(oldestPlaceholder)
    this.forward.delete(oldestPlaceholder)
    this.created.delete(oldestPlaceholder)
    if (original !== undefined) this.reverse.delete(original)
  }

  lookup(placeholder) {
    return this.forward.get(placeholder)
  }

  lookupReverse(original) {
    return this.reverse.get(original)
  }

  /**
   * 与 VibeGuard 一致：placeholder = `${prefix}${CATEGORY}_${hash12}__`
   * @param {string} original
   * @param {string} category
   */
  generatePlaceholder(original, category) {
    const cat = sanitizeCategory(category)
    const h = createHmac("sha256", this.secret)
    h.update(String(original))
    const sum = h.digest()
    const hash12 = toHexLower(sum).slice(0, 12)
    const base = `${this.prefix}${cat}_${hash12}`
    return `${base}__`
  }

  /**
   * 获取或创建占位符，并注册映射。
   * 设计目标：同一会话内，同一 original 始终映射到同一 placeholder。
   * @param {string} original
   * @param {string} category
   */
  getOrCreatePlaceholder(original, category) {
    const existing = this.lookupReverse(original)
    if (existing) {
      // Sliding TTL: reuse counts as activity, so long sessions do not orphan
      // placeholders that are still being referenced.
      this.created.set(existing, Date.now())
      this.revision += 1
      return existing
    }

    const now = Date.now()
    this.cleanup(now)

    if (Number.isFinite(this.maxMappings) && this.maxMappings > 0 && this.forward.size >= this.maxMappings) {
      // Never silently evict: a dropped mapping can strand placeholders that are
      // still present in retained history. Refuse instead; the caller fails closed.
      throw new Error("Vibeguard: placeholder capacity reached; start a new conversation")
    }

    const base = this.generatePlaceholder(original, category)
    const current = this.forward.get(base)
    if (current === undefined) {
      this.forward.set(base, original)
      this.reverse.set(original, base)
      this.created.set(base, now)
      this.revision += 1
      return base
    }

    if (current === original) {
      this.reverse.set(original, base)
      this.created.set(base, now)
      this.revision += 1
      return base
    }

    // 极低概率：hash12 冲突。追加 _N 后缀保证唯一性（与 VibeGuard 一致的策略）。
    const withoutSuffix = base.slice(0, -2) // 去掉末尾 "__"
    for (let i = 2; ; i++) {
      const candidate = `${withoutSuffix}_${i}__`
      const prev = this.forward.get(candidate)
      if (prev === undefined) {
        this.forward.set(candidate, original)
        this.reverse.set(original, candidate)
        this.created.set(candidate, now)
        this.revision += 1
        return candidate
      }
      if (prev === original) {
        this.reverse.set(original, candidate)
        this.created.set(candidate, now)
        this.revision += 1
        return candidate
      }
    }
  }

  /** Storage-safe snapshot of the live mappings. */
  snapshot() {
    const entries = []
    for (const [placeholder, original] of this.forward.entries()) {
      entries.push([placeholder, original, this.created.get(placeholder) ?? 0])
    }
    return { v: 1, entries }
  }

  /**
   * Replace mappings with a validated snapshot.
   * Returns false (leaving state untouched) on any malformed input.
   */
  hydrate(raw) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false
    if (raw.v !== 1 || !Array.isArray(raw.entries)) return false
    if (Number.isFinite(this.maxMappings) && this.maxMappings > 0 && raw.entries.length > this.maxMappings) return false
    const escaped = String(this.prefix).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    const shape = new RegExp(`^${escaped}[A-Z0-9_]+_[a-f0-9]{12}(?:_\\d+)?__$`)
    const forward = new Map()
    const reverse = new Map()
    const created = new Map()
    for (const entry of raw.entries) {
      if (!Array.isArray(entry) || entry.length !== 3) return false
      const [placeholder, original, at] = entry
      if (typeof placeholder !== "string" || !shape.test(placeholder)) return false
      if (typeof original !== "string" || original.length === 0) return false
      if (!Number.isFinite(at) || at < 0) return false
      if (forward.has(placeholder) || reverse.has(original)) return false
      forward.set(placeholder, original)
      reverse.set(original, placeholder)
      created.set(placeholder, at)
    }
    this.forward = forward
    this.reverse = reverse
    this.created = created
    this.revision = 0
    return true
  }
}

export function getPlaceholderRegex(prefix) {
  const escaped = String(prefix).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  // Pattern: __VG_CATEGORY_HASH12__ or __VG_CATEGORY_HASH12_N__
  return new RegExp(`${escaped}[A-Za-z0-9_]+_[a-f0-9A-F]{12}(?:_\\d+)?__`, "g")
}
