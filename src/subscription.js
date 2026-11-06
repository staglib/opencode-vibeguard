export const DEFAULT_SUBSCRIPTION_URL =
  "https://raw.githubusercontent.com/link-seek/opencode-vibeguard/main/rules.json"

const MAX_DOC_BYTES = 256 * 1024
const MAX_REMOTE_RULES = 1000

function parseRefreshMs(input, fallback) {
  const raw = String(input ?? "").trim()
  if (!raw) return fallback
  const m = raw.match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d)$/)
  if (!m) return fallback
  const value = Number(m[1])
  if (!Number.isFinite(value) || value <= 0) return fallback
  const mult = { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2]]
  return value * mult
}

export function normalizeSubscription(raw) {
  const cfg = raw && typeof raw === "object" ? raw : {}
  // 缺省开启订阅：拉失败自动 fail-closed 用本地规则，不影响现有行为
  const enabled = cfg.enabled === undefined ? false : Boolean(cfg.enabled)
  const url = typeof cfg.url === "string" && cfg.url ? cfg.url : DEFAULT_SUBSCRIPTION_URL
  const refreshMs = parseRefreshMs(cfg.refresh ?? "24h", 24 * 3600000)
  const timeoutMs =
    Number.isFinite(cfg.timeoutMs) && Number(cfg.timeoutMs) > 0 ? Number(cfg.timeoutMs) : 8000
  return { enabled, url, refreshMs, timeoutMs }
}

function isDocShape(doc) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return false
  if (typeof doc.version !== "number") return false
  const p = doc.patterns
  if (!p || typeof p !== "object" || Array.isArray(p)) return false
  for (const k of ["keywords", "regex", "builtin", "exclude"]) {
    if (p[k] !== undefined && !Array.isArray(p[k])) return false
  }
  return true
}

function countRules(patterns) {
  return (
    (patterns.keywords?.length ?? 0) +
    (patterns.regex?.length ?? 0) +
    (patterns.builtin?.length ?? 0) +
    (patterns.exclude?.length ?? 0)
  )
}

// 校验远端 regex 可编译，防止坏规则拖慢/打断引擎
function cleanPatterns(patterns) {
  const out = { keywords: [], regex: [], builtin: [], exclude: [] }
  for (const x of patterns.keywords ?? []) {
    if (x && typeof x === "object" && typeof x.value === "string" && x.value) {
      out.keywords.push({ value: String(x.value), category: String(x.category ?? "") })
    }
  }
  for (const x of patterns.regex ?? []) {
    if (!x || typeof x !== "object" || typeof x.pattern !== "string" || !x.pattern) continue
    try {
      new RegExp(x.pattern, typeof x.flags === "string" ? x.flags : "")
    } catch {
      continue
    }
    out.regex.push({
      pattern: x.pattern,
      flags: typeof x.flags === "string" ? x.flags : "",
      category: String(x.category ?? ""),
    })
  }
  for (const x of patterns.builtin ?? []) {
    if (typeof x === "string" && x) out.builtin.push(x)
  }
  for (const x of patterns.exclude ?? []) out.exclude.push(String(x ?? ""))
  return out
}

import { createHash } from "node:crypto"

export async function fetchRulesDoc(url, timeoutMs, fetchImpl, conditional) {
  const fetchFn = fetchImpl ?? globalThis.fetch
  if (typeof fetchFn !== "function") throw new Error("fetch unavailable")
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const headers = { Accept: "application/json" }
    if (conditional?.etag) headers["If-None-Match"] = conditional.etag
    if (conditional?.lastModified) headers["If-Modified-Since"] = conditional.lastModified
    const res = await fetchFn(url, { signal: ctrl.signal, headers })
    if (res.status === 304) return { notModified: true }
    if (!res.ok) throw new Error(`rules subscription HTTP ${res.status}`)
    const text = await res.text()
    if (text.length > MAX_DOC_BYTES) throw new Error("rules doc too large")
    await verifyChecksum(url, text, timeoutMs, fetchFn, ctrl.signal)
    const doc = JSON.parse(text)
    if (!isDocShape(doc)) throw new Error("rules doc shape invalid")
    if (countRules(doc.patterns) > MAX_REMOTE_RULES) throw new Error("rules doc too many rules")
    return {
      version: doc.version,
      updated: doc.updated,
      patterns: cleanPatterns(doc.patterns),
      etag: res.headers?.get?.("etag") ?? undefined,
      lastModified: res.headers?.get?.("last-modified") ?? undefined,
    }
  } finally {
    clearTimeout(timer)
  }
}

// 完整性校验：与 rules.json 同目录发布 rules.json.sha256（`sha256sum` 单行格式）。
// 校验文件缺失（404）则放行（仅 TLS 保障），存在但不匹配则拒收。
async function verifyChecksum(url, text, timeoutMs, fetchFn, signal) {
  let res
  try {
    res = await fetchFn(`${url}.sha256`, { signal })
  } catch {
    return
  }
  if (res.status === 404) return
  if (!res.ok) return
  const line = (await res.text()).trim().split(/\s+/)[0] ?? ""
  if (!/^[0-9a-fA-F]{64}$/.test(line)) throw new Error("checksum file malformed")
  const actual = createHash("sha256").update(text, "utf8").digest("hex")
  if (actual.toLowerCase() !== line.toLowerCase()) throw new Error("checksum mismatch")
}

// 合并：本地优先，去重键 kind:value|pattern；远端只补充本地没有的
export function mergePatterns(local, remote) {
  const seen = new Set()
  const out = { keywords: [], regex: [], builtin: new Set(), exclude: new Set() }
  const push = (kind, entry, key) => {
    if (seen.has(key)) return
    seen.add(key)
    if (kind === "builtin") out.builtin.add(entry)
    else if (kind === "exclude") out.exclude.add(entry)
    else out[kind].push(entry)
  }
  for (const x of local.keywords ?? []) push("keywords", x, `kw:${x.value}`)
  for (const x of local.regex ?? []) push("regex", x, `re:${x.pattern}`)
  for (const x of local.builtin ?? []) push("builtin", x, `bi:${x}`)
  for (const x of local.exclude ?? []) push("exclude", x, `ex:${x}`)
  for (const x of remote.keywords ?? []) push("keywords", x, `kw:${x.value}`)
  for (const x of remote.regex ?? []) push("regex", x, `re:${x.pattern}`)
  for (const x of remote.builtin ?? []) push("builtin", x, `bi:${x}`)
  for (const x of remote.exclude ?? []) push("exclude", x, `ex:${x}`)
  return {
    keywords: out.keywords,
    regex: out.regex,
    builtin: [...out.builtin],
    exclude: [...out.exclude],
  }
}

const CACHE_KEY = "vibeguard:rules-doc"

/**
 * 订阅管理器：启动先读缓存即时生效，再拉新；定时刷新；全程 fail-closed。
 * storage 为 ctx.storage（V2），没有则只用内存（进程内有效）。
 */
export function createSubscription({ sub, localPatterns, buildPatternSet, storage, debug, log }) {
  const ref = { current: buildPatternSet(localPatterns) }
  let timer = null
  let stopped = false
  let conditional = null

  const apply = (remotePatterns, source) => {
    ref.current = buildPatternSet(mergePatterns(localPatterns, remotePatterns))
    if (debug) log(`[opencode-vibeguard] 规则订阅已更新（${source}）`)
  }

  const saveCache = async (entry) => {
    if (!storage) return
    await storage.set(CACHE_KEY, entry).catch(() => {})
  }

  const refresh = async () => {
    if (stopped) return
    try {
      const doc = await fetchRulesDoc(sub.url, sub.timeoutMs, undefined, conditional)
      if (doc.notModified) {
        if (storage) {
          try {
            const cached = await storage.get(CACHE_KEY)
            if (cached) await saveCache({ ...cached, fetchedAt: Date.now() })
          } catch {
            // 忽略
          }
        }
        if (debug) log("[opencode-vibeguard] 规则订阅无变化（304）")
        return
      }
      conditional = { etag: doc.etag, lastModified: doc.lastModified }
      apply(doc.patterns, `远端 v${doc.version}`)
      await saveCache({ fetchedAt: Date.now(), url: sub.url, doc, conditional })
    } catch (err) {
      if (debug) log(`[opencode-vibeguard] 规则订阅刷新失败，沿用现有规则：${err?.message ?? err}`)
    }
  }

  const start = async () => {
    if (storage) {
      try {
        const cached = await storage.get(CACHE_KEY)
        if (cached && cached.url === sub.url && cached.doc && isDocShape(cached.doc)) {
          apply(cleanPatterns(cached.doc.patterns), "本地缓存")
          if (cached.conditional) conditional = cached.conditional
        }
      } catch {
        // 忽略缓存读取失败
      }
    }
    await refresh()
    if (sub.refreshMs > 0) {
      timer = setInterval(refresh, sub.refreshMs)
      if (typeof timer.unref === "function") timer.unref()
    }
  }

  const stop = () => {
    stopped = true
    if (timer) clearInterval(timer)
    timer = null
  }

  return { ref, start, stop, refresh }
}
