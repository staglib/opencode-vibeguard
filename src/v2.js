import { loadConfig, loadPersonalRules } from "./config.js"
import { buildPatternSet } from "./patterns.js"
import { PlaceholderSession, getPlaceholderRegex } from "./session.js"
import { redactText } from "./engine.js"
import { redactDeep, restoreDeep } from "./deep.js"
import { createSubscription } from "./subscription.js"

/**
 * V2 setup (`Plugin.define({ id, setup })` 形态，`Plugin.define` 是透传，
 * 所以这里直接返回 `{ id, setup }` 所需的 setup 函数，不依赖 `@opencode/plugin`)。
 *
 * 映射关系（见迁移指南）：
 * - V1 `experimental.chat.messages.transform` -> `ctx.session.hook("context" | "compaction" | "generate" | "title")`，改 `event.messages / event.system`
 * - V1 `chat.message`（用户原文） -> `ctx.session.hook("prompt")`，改 `event.prompt.text`（落库即占位符）
 * - V1 `tool.execute.before` -> `ctx.tool.hook("execute.before")`，还原占位符保证本地执行拿到真值
 * - V1 `tool.execute.after`（新增，原来没有）-> `ctx.tool.hook("execute.after")`，工具输出重新脱敏，避免明文落库
 *
 * 说明：
 * - `reasoning.encrypted` / `compaction.encrypted` 是 provider 签名，原样透传，绝不改写。
 * - V1 的 `experimental.text.complete`（输出还原展示）在 V2 没有对应钩子；这里刻意不还原
 *   持久化内容，DB 里保持占位符更安全。工具执行前由 `execute.before` 还原，不影响功能。
 */
export async function setupV2(ctx) {
  const directory = ctx?.location?.directory ?? process.cwd()
  const config = await loadConfig(directory)
  const debug = Boolean(process.env.OPENCODE_VIBEGUARD_DEBUG) || Boolean(config.debug)

  if (debug) {
    const from = config.loadedFrom ? config.loadedFrom : "未找到（插件将 no-op）"
    console.log(`[opencode-vibeguard] 配置：${from} enabled=${config.enabled}`)
  }

  let personalRules = []
  let personalError
  try { personalRules = await loadPersonalRules() } catch (error) { personalError = error.message }
  if (!config.enabled || personalError) {
    console.error("[opencode-vibeguard] Protection unavailable: configuration or personal rules invalid; model requests will be blocked if hooks are active.")
    const block = () => { throw new Error(personalError || "Vibeguard protection unavailable: configuration missing, invalid, or disabled") }
    for (const kind of ["prompt", "context", "compaction", "generate", "title"]) await ctx.session.hook(kind, block)
    await ctx.tool.hook("execute.before", block)
    return
  }
  config.patterns = { ...config.patterns, keywords: [...(config.patterns.keywords ?? []), ...personalRules] }

  // 规则订阅（V2）：本地规则 + 远端订阅合并，本地优先；拉失败 fail-closed。
  // patternsRef.current 在刷新时原地替换，所有钩子实时生效。
  const sub = config.subscription
  const subscription = sub.enabled
    ? createSubscription({
        sub,
        localPatterns: config.patterns,
        buildPatternSet,
        storage: ctx?.storage,
        debug,
        log: (...args) => console.log(...args),
      })
    : null
  if (subscription) await subscription.start()
  const patternsRef = subscription ? subscription.ref : { current: buildPatternSet(config.patterns) }
  const live = () => patternsRef.current
  const sessions = new Map()
  const hydrations = new Map()
  const saveChains = new Map()
  const storeKey = (id) => `vibeguard.session.${id}`
  const storePrefix = "vibeguard.session."

  // Best-effort pruning of mappings whose session no longer exists. Runs once at
  // setup; logs counts only (never values). A scan/list failure stops silently,
  // because pruning is housekeeping, not protection.
  const pruneOrphans = async () => {
    if (!ctx.storage?.scan || !ctx.session?.list) return
    try {
      let live = new Set()
      try {
        const list = await ctx.session.list()
        for (const s of list) if (s?.id) live.add(String(s.id))
      } catch (error) {
        if (debug) console.warn("[opencode-vibeguard] session list unavailable; pruning skipped", error)
        return
      }
      if (live.size === 0) return
      let removed = 0
      let kept = 0
      let after
      do {
        const result = await ctx.storage.scan({ prefix: storePrefix, after, limit: 200 })
        const entries = result?.entries ?? []
        for (const entry of entries) {
          const id = entry.key.slice(storePrefix.length)
          if (id && !live.has(id)) {
            try { await ctx.storage.remove(entry.key); removed++ } catch { /* leave it */ }
          } else {
            kept++
          }
        }
        after = result?.next
      } while (after)
      if (debug) console.log(`[opencode-vibeguard] pruning: removed ${removed} orphaned mapping(s), kept ${kept}`)
    } catch (error) {
      if (debug) console.warn("[opencode-vibeguard] pruning failed", error)
    }
  }

  const makeSession = () =>
    new PlaceholderSession({
      prefix: config.prefix,
      ttlMs: config.ttlMs,
      maxMappings: config.maxMappings,
    })

  // Single-flight hydration: no hook ever sees a partially loaded session, and a
  // process restart re-reads mappings that were already persisted.
  const getSession = (sessionID) => {
    const key = String(sessionID ?? "")
    if (!key) return null
    const existing = sessions.get(key)
    if (existing) return existing
    let pending = hydrations.get(key)
    if (!pending) {
      pending = (async () => {
        const created = makeSession()
        if (ctx.storage) {
          const raw = await ctx.storage.get(storeKey(key))
          if (raw && !created.hydrate(raw) && debug) {
            console.warn("[opencode-vibeguard] invalid stored mapping ignored; starting empty")
          }
        }
        sessions.set(key, created)
        hydrations.delete(key)
        return created
      })().catch((error) => {
        hydrations.delete(key)
        throw error
      })
      hydrations.set(key, pending)
    }
    return pending
  }

  // Durability barrier: serialize writes per session, and keep rewriting until a
  // snapshot taken after the write matches the current revision. Failures reject,
  // so the calling hook fails closed rather than emitting an unpersisted mapping.
  const persist = (sessionID, session) => {
    if (!ctx.storage) return Promise.resolve()
    const key = String(sessionID ?? "")
    const previous = saveChains.get(key) ?? Promise.resolve()
    const next = previous.catch(() => {}).then(async () => {
      for (;;) {
        const revision = session.revision
        const snapshot = session.snapshot()
        await ctx.storage.set(storeKey(key), snapshot)
        if (session.revision === revision) return
      }
    })
    saveChains.set(key, next)
    return next
  }

  const redactString = (value, session) => {
    if (typeof value !== "string" || !value) return value
    return redactText(value, live(), session).text
  }

  // tool-result 的 result 是 { type, value } 联合体：text/error 的 string value 直接脱敏，
  // json / 对象型 value 走深度脱敏，content 型数组逐条脱敏 text 条目。
  const redactResultValue = (result, session) => {
    if (!result || typeof result !== "object") return
    const { type, value } = result
    if (type === "content" && Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item === "object" && item.type === "text" && typeof item.text === "string") {
          item.text = redactString(item.text, session)
        }
      }
      return
    }
    if (typeof value === "string") {
      result.value = redactString(value, session)
      return
    }
    if (value && typeof value === "object") redactDeep(value, live(), session)
  }

  // V2 Message.content: text | reasoning | tool-call | tool-result | compaction | effort | media
  const redactContent = (content, session) => {
    if (!Array.isArray(content)) return 0
    let changed = 0
    for (const part of content) {
      if (!part || typeof part !== "object") continue
      if (part.type === "text" && typeof part.text === "string") {
        const after = redactString(part.text, session)
        if (after !== part.text) {
          part.text = after
          changed++
        }
      } else if (part.type === "reasoning" && typeof part.text === "string") {
        const after = redactString(part.text, session)
        if (after !== part.text) {
          part.text = after
          changed++
        }
        // part.encrypted 是 provider 签名，保持原样
      } else if (part.type === "tool-call" && part.input && typeof part.input === "object") {
        redactDeep(part.input, live(), session)
      } else if (part.type === "tool-result" && part.result && typeof part.result === "object") {
        redactResultValue(part.result, session)
      } else if (part.type === "compaction" && typeof part.text === "string") {
        const after = redactString(part.text, session)
        if (after !== part.text) {
          part.text = after
          changed++
        }
      }
    }
    return changed
  }

  const redactRequest = async (event) => {
    const session = await getSession(event?.sessionID)
    if (!session) throw new Error("Vibeguard: missing session ID")
    session.cleanup()
    let changed = 0
    if (Array.isArray(event.system)) {
      for (const part of event.system) {
        if (part && typeof part === "object" && typeof part.text === "string") {
          const after = redactString(part.text, session)
          if (after !== part.text) {
            part.text = after
            changed++
          }
        }
      }
    }
    if (Array.isArray(event.messages)) {
      for (const msg of event.messages) {
        if (msg && typeof msg === "object") changed += redactContent(msg.content, session)
      }
    }
    if (debug && changed > 0) console.log(`[opencode-vibeguard] 出站请求脱敏：已修改 ${changed} 处文本片段`)
    if (changed > 0) await persist(event?.sessionID, session)
  }

  // prompt 在入库前脱敏：DB 里存占位符，provider 永远见不到真值。
  // 改写 text 会让 files/agents/skills 的 mention 偏移失效，直接清除。
  await ctx.session.hook("prompt", async (event) => {
    const session = await getSession(event?.sessionID)
    if (!session) return
    session.cleanup()
    if (typeof event.prompt?.text === "string") {
      const before = event.prompt.text
      const after = redactString(before, session)
      if (after !== before) {
        event.prompt.text = after
        for (const f of event.prompt.files ?? []) {
          if (f && typeof f === "object" && "mention" in f) f.mention = undefined
        }
        for (const a of event.prompt.agents ?? []) {
          if (a && typeof a === "object" && "mention" in a) a.mention = undefined
        }
        for (const s of event.prompt.skills ?? []) {
          if (s && typeof s === "object" && "mention" in s) s.mention = undefined
        }
        if (debug) console.log("[opencode-vibeguard] prompt 入库前脱敏：已替换 1 处文本")
        await persist(event?.sessionID, session)
      }
    }
  })

  await pruneOrphans()

  // 发往模型前的各路请求统一脱敏（只影响本次出站，不改持久化历史）。
  await ctx.session.hook("context", redactRequest)
  await ctx.session.hook("compaction", redactRequest)
  await ctx.session.hook("generate", redactRequest)
  await ctx.session.hook("title", redactRequest)

  // Only restore explicitly classified PATH values into the local read tool.
  // All other tools keep values masked; shell and write calls with placeholders
  // are blocked rather than risking exfiltration or corrupt writes.
  await ctx.tool.hook("execute.before", async (event) => {
    const session = await getSession(event?.sessionID)
    if (!session) throw new Error("Vibeguard: missing session ID")
    session.cleanup()
    const input = structuredClone(event.input)
    const matches = []
    const collect = (value) => {
      if (typeof value === "string") matches.push(...value.matchAll(getPlaceholderRegex(session.prefix)))
      else if (Array.isArray(value)) value.forEach(collect)
      else if (value && typeof value === "object") Object.values(value).forEach(collect)
    }
    collect(input)

    const external = ["websearch", "webfetch", "experimental_image_generate"].includes(event.tool)
    if (external) {
      const revisionBefore = session.revision
      redactDeep(input, live(), session)
      // These mappings must be durable before the request leaves the machine.
      if (session.revision !== revisionBefore) await persist(event?.sessionID, session)
      event.input = input
      return
    }

    // Resolve the whole input before restoring anything. Unknown tokens mean the
    // mapping is gone (expired, or minted by another session/process); fail closed
    // rather than passing a literal placeholder into a local tool.
    const known = matches.filter((match) => session.lookup(match[0]) !== undefined)
    const unknown = matches.filter((match) => session.lookup(match[0]) === undefined)
    if (unknown.length > 0) {
      throw new Error("Vibeguard: placeholder mapping unavailable (expired or from another session). Start a new conversation and re-supply the original value.")
    }
    if (event.tool === "read" && known.length > 0 && known.every((match) => match[0].startsWith(`${session.prefix}PATH_`))) {
      restoreDeep(input, session)
    } else if (known.length > 0) {
      throw new Error("Vibeguard: placeholder restoration is not permitted for this tool")
    }
    event.input = input
  })

  // 工具执行后重新脱敏：输出入库前变回占位符，避免明文落库。
  await ctx.tool.hook("execute.after", async (event) => {
    const session = await getSession(event?.sessionID)
    if (!session) return
    session.cleanup()
    const revisionBefore = session.revision
    if (event.status === "completed" && event.result && typeof event.result === "object") {
      const { output, content, metadata } = event.result
      if (output && typeof output === "object") redactDeep(output, live(), session)
      else if (typeof output === "string") event.result.output = redactString(output, session)
      if (typeof content === "string") event.result.content = redactString(content, session)
      else if (Array.isArray(content)) {
        for (const item of content) {
          if (item && typeof item === "object" && item.type === "text" && typeof item.text === "string") {
            item.text = redactString(item.text, session)
          }
        }
      }
      if (metadata && typeof metadata === "object") redactDeep(metadata, live(), session)
    } else if (event.status === "error" && event.error) {
      if (typeof event.error.message === "string") {
        event.error.message = redactString(event.error.message, session)
      }
      if (event.error.metadata && typeof event.error.metadata === "object") {
        redactDeep(event.error.metadata, live(), session)
      }
    }
    if (session.revision !== revisionBefore) await persist(event?.sessionID, session)
  })

  // Experimental test-only readiness marker. This is not an attestation that
  // every sensitive value was detected, nor a boundary against other plugins.
  if (process.env.VIBEGUARD_TEST_GATE_TOKEN) {
    await ctx.session.hook("model.request", (event) => {
      event.headers["x-vibeguard-test-ready"] = process.env.VIBEGUARD_TEST_GATE_TOKEN
    })
  }

  // Exposed only after all protection hooks have registered successfully.
  // Readiness is not a guarantee of complete anonymization.
  if (ctx.rpc) {
    const { VibeguardHealth } = await import("./health-rpc.js")
    await ctx.rpc.register(VibeguardHealth, {
      status: async () => ({ ready: true, version: "test-fork" }),
    })
  }

  if (debug) console.log("[opencode-vibeguard] v2 hooks 已注册：prompt/context/compaction/generate/title + tool execute.before/after")

  if (subscription) return () => subscription.stop()
}
