import { existsSync } from "node:fs"
import * as fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { normalizeSubscription } from "./subscription.js"

function parseDurationMs(input) {
  const raw = String(input ?? "").trim()
  if (!raw) return 60 * 60 * 1000

  const m = raw.match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d)$/)
  if (!m) return 60 * 60 * 1000

  const value = Number(m[1])
  const unit = m[2]
  if (!Number.isFinite(value) || value < 0) return 60 * 60 * 1000

  if (unit === "ms") return value
  if (unit === "s") return value * 1000
  if (unit === "m") return value * 60 * 1000
  if (unit === "h") return value * 60 * 60 * 1000
  if (unit === "d") return value * 24 * 60 * 60 * 1000

  return 60 * 60 * 1000
}

function readJson(filepath) {
  return fs
    .readFile(filepath, "utf8")
    .then((s) => JSON.parse(s))
    .catch(() => null)
}

function normalizeConfig(raw) {
  const cfg = raw && typeof raw === "object" ? raw : {}

  const enabled = Boolean(cfg.enabled)
  const debug = Boolean(cfg.debug)
  const prefix = typeof cfg.placeholder_prefix === "string" && cfg.placeholder_prefix ? cfg.placeholder_prefix : "__VG_"

  const session = cfg.session && typeof cfg.session === "object" ? cfg.session : {}
  const ttlMs = parseDurationMs(session.ttl ?? "1h")
  const maxMappings =
    Number.isFinite(session.max_mappings) && Number(session.max_mappings) > 0 ? Number(session.max_mappings) : 100000

  const patterns = cfg.patterns && typeof cfg.patterns === "object" ? cfg.patterns : {}

  return {
    enabled,
    debug,
    prefix,
    ttlMs,
    maxMappings,
    patterns,
    subscription: normalizeSubscription(cfg.subscription),
  }
}

export function getConfigCandidates(directory) {
  const dir = String(directory ?? process.cwd())
  const home = os.homedir()
  const globalConfig = path.join(home, ".config", "opencode", "vibeguard.config.json")
  const projectRoot = path.join(dir, "vibeguard.config.json")
  const projectLocal = path.join(dir, ".opencode", "vibeguard.config.json")

  const env = process.env.OPENCODE_VIBEGUARD_CONFIG
  if (env) return [path.resolve(dir, env), projectRoot, projectLocal, globalConfig]

  return [projectRoot, projectLocal, globalConfig]
}

/**
 * 加载插件配置：
 * - 找不到配置或解析失败：返回 enabled=false（插件 no-op）
 * - 只做轻量校验，避免引入额外依赖
 */
export async function loadConfig(directory) {
  const candidates = getConfigCandidates(directory)
  for (const file of candidates) {
    if (!file) continue
    if (!existsSync(file)) continue
    const raw = await readJson(file)
    if (!raw) continue
    const cfg = normalizeConfig(raw)
    return { ...cfg, loadedFrom: file }
  }
  const cfg = normalizeConfig({ enabled: false })
  return { ...cfg, loadedFrom: "" }
}

// Personal values are read locally and never logged.
export async function loadPersonalRules(file = process.env.VIBEGUARD_PERSONAL_RULES || path.join(os.homedir(), ".config", "opencode", "vibeguard-personal.json")) {
  let content
  try { content = await fs.readFile(file, "utf8") }
  catch { throw new Error("Unable to read Vibeguard personal rules") }
  let data
  try { data = JSON.parse(content) }
  catch { throw new Error("Invalid JSON in Vibeguard personal rules") }
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Invalid Vibeguard personal rules format")
  const entries = []
  for (const [key, category] of [["names", "NAME"], ["addresses", "ADDRESS"], ["other", "PERSONAL"]]) {
    if (!Array.isArray(data[key])) throw new Error(`Vibeguard personal rules: ${key} must be an array`)
    for (const value of data[key]) {
      if (typeof value !== "string" || value.trim().length < 3) throw new Error(`Vibeguard personal rules: ${key} entries must be strings with at least 3 characters`)
      entries.push({ value: value.trim(), category, boundary: true })
    }
  }
  return entries
}
