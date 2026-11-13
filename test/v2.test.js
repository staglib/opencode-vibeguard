import { describe, it, before, after } from "node:test"
import assert from "node:assert/strict"
import os from "node:os"
import path from "node:path"
import * as fs from "node:fs/promises"
import { setupV2 } from "../src/v2.js"

const FAKE = "cfut_" + "A".repeat(30)

let dir = ""
const ENV_KEY = "OPENCODE_VIBEGUARD_CONFIG"
const OLD_ENV = process.env[ENV_KEY]

function mockCtx() {
  const sessionHooks = new Map()
  const toolHooks = new Map()
  return {
    ctx: {
      location: { directory: dir },
      session: {
        hook: async (name, cb) => {
          sessionHooks.set(name, cb)
          return { dispose: async () => void sessionHooks.delete(name) }
        },
      },
      tool: {
        hook: async (name, cb) => {
          toolHooks.set(name, cb)
          return { dispose: async () => void toolHooks.delete(name) }
        },
      },
    },
    sessionHooks,
    toolHooks,
  }
}

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), "vg-v2-"))
  process.env.VIBEGUARD_PERSONAL_RULES = path.join(dir, "vibeguard-personal.json")
  await fs.writeFile(process.env.VIBEGUARD_PERSONAL_RULES, JSON.stringify({ names: ["Joe"], addresses: [], other: [] }))
  await fs.writeFile(
    path.join(dir, "vibeguard.config.json"),
    JSON.stringify({
      enabled: true,
      placeholder_prefix: "__VG_",
      session: { ttl: "1h", max_mappings: 1000 },
      patterns: {
        regex: [{ pattern: "\\bcfut_[A-Za-z0-9_-]{30,}\\b", category: "CLOUDFLARE_USER_TOKEN" }],
        builtin: [],
        keywords: [{ value: "/fake-private/Joe/path", category: "PATH" }],
        exclude: [],
      },
      subscription: { enabled: false },
    }),
  )
  process.env[ENV_KEY] = path.join(dir, "vibeguard.config.json")
})

after(async () => {
  if (OLD_ENV === undefined) delete process.env[ENV_KEY]
  else process.env[ENV_KEY] = OLD_ENV
  delete process.env.VIBEGUARD_PERSONAL_RULES
  await fs.rm(dir, { recursive: true, force: true })
})

describe("v2 setup", () => {
  it("registers prompt/context/compaction/generate/title + tool before/after", async () => {
    const m = mockCtx()
    await setupV2(m.ctx)
    for (const h of ["prompt", "context", "compaction", "generate", "title"]) {
      assert.ok(m.sessionHooks.has(h), `missing session hook ${h}`)
    }
    assert.ok(m.toolHooks.has("execute.before"))
    assert.ok(m.toolHooks.has("execute.after"))
  })

  it("blocks registered hooks when disabled", async () => {
    const off = path.join(dir, "off.json")
    await fs.writeFile(off, JSON.stringify({ enabled: false }))
    process.env[ENV_KEY] = off
    const m = mockCtx()
    await setupV2(m.ctx)
    assert.throws(() => m.sessionHooks.get("context")({}), /protection unavailable/i)
    assert.throws(() => m.sessionHooks.get("prompt")({}), /protection unavailable/i)
    assert.throws(() => m.toolHooks.get("execute.before")({}), /protection unavailable/i)
    process.env[ENV_KEY] = path.join(dir, "vibeguard.config.json")
  })

  it("prompt/context redact, encrypted untouched, tool before restores, tool after redacts", async () => {
    const m = mockCtx()
    await setupV2(m.ctx)
    const prompt = m.sessionHooks.get("prompt")
    const context = m.sessionHooks.get("context")
    const before = m.toolHooks.get("execute.before")
    const after = m.toolHooks.get("execute.after")

    // prompt：入库前脱敏
    const pe = { sessionID: "s1", prompt: { text: `key is ${FAKE}`, files: [], agents: [], skills: [] }, delivery: "steer" }
    await prompt(pe)
    assert.doesNotMatch(pe.prompt.text, /cfut_/)
    const ph = pe.prompt.text.match(/__VG_CLOUDFLARE_USER_TOKEN_[0-9a-f]{12}__/)
    assert.ok(ph, "expected placeholder in prompt")

    // context：system/messages 脱敏，encrypted 原样
    const ce = {
      sessionID: "s1",
      system: [{ type: "text", text: `sys ${FAKE}` }],
      messages: [
        { role: "user", content: [{ type: "text", text: `hi ${FAKE}` }] },
        {
          role: "assistant",
          content: [
            { type: "reasoning", text: `think ${FAKE}`, encrypted: "ENC-SIGNATURE" },
            { type: "tool-call", id: "1", name: "bash", input: { command: `echo ${FAKE}` } },
          ],
        },
      ],
    }
    await context(ce)
    assert.doesNotMatch(JSON.stringify(ce), new RegExp(FAKE))
    assert.equal(ce.messages[1].content[0].encrypted, "ENC-SIGNATURE")

    // tool before：占位符还原，真值执行
    const be = { sessionID: "s1", tool: "bash", input: { command: `echo ${ph[0]}` } }
    await assert.rejects(before(be), /not permitted/)
    const web = { sessionID: "s1", tool: "websearch", input: Object.freeze({ query: ph[0] }) }
    await before(web)
    assert.equal(web.input.query, ph[0])
    const rawWeb = { sessionID: "s1", tool: "websearch", input: { query: FAKE } }
    await before(rawWeb)
    assert.doesNotMatch(rawWeb.input.query, /cfut_/)
    await assert.rejects(before({ sessionID: "other", tool: "read", input: { filePath: ph[0] } }), /mapping unavailable/)
    const pathEvent = { sessionID: "s1", prompt: { text: "/fake-private/Joe/path", files: [], agents: [], skills: [] } }
    await prompt(pathEvent)
    const read = { sessionID: "s1", tool: "read", input: Object.freeze({ path: pathEvent.prompt.text }) }
    await before(read)
    assert.equal(read.input.path, "/fake-private/Joe/path")

    // tool after：输出重新脱敏
    const ae = {
      sessionID: "s1",
      tool: "bash",
      status: "completed",
      input: {},
      result: { output: `out ${FAKE}`, content: `c ${FAKE}`, metadata: {} },
    }
    await after(ae)
    assert.doesNotMatch(JSON.stringify(ae.result), new RegExp(FAKE))
  })

  it("restores a PATH placeholder for read-only path tools only", async () => {
    const m = mockCtx()
    await setupV2(m.ctx)
    const prompt = m.sessionHooks.get("prompt")
    const before = m.toolHooks.get("execute.before")
    const mint = async (sessionID, text) => {
      const event = { sessionID, prompt: { text, files: [], agents: [], skills: [] } }
      await prompt(event)
      return event.prompt.text
    }

    // grep: PATH placeholder in path is restored
    const grepPh = await mint("grep-session", "/fake-private/Joe/path")
    assert.match(grepPh, /^__VG_PATH_[0-9a-f]{12}__$/)
    const grep = { sessionID: "grep-session", tool: "grep", input: { path: grepPh, pattern: "Joe" } }
    await before(grep)
    assert.equal(grep.input.path, "/fake-private/Joe/path")

    // glob: PATH placeholder in path is restored
    const globPh = await mint("glob-session", "/fake-private/Joe/path")
    const glob = { sessionID: "glob-session", tool: "glob", input: { path: globPh, pattern: "**/*.js" } }
    await before(glob)
    assert.equal(glob.input.path, "/fake-private/Joe/path")

    // grep: PATH placeholder outside path is still refused
    const patternPh = await mint("grep-pattern-session", "/fake-private/Joe/path")
    const grepPattern = { sessionID: "grep-pattern-session", tool: "grep", input: { path: "/tmp", pattern: patternPh } }
    await assert.rejects(before(grepPattern), /not permitted/)

    // bash: PATH placeholder still refused
    const bashPh = await mint("bash-session", "/fake-private/Joe/path")
    const bash = { sessionID: "bash-session", tool: "bash", input: { command: `ls ${bashPh}` } }
    await assert.rejects(before(bash), /not permitted/)

    // read: non-PATH placeholder refused
    const namePh = await mint("read-name-session", "hello Joe")
    assert.match(namePh, /^hello __VG_NAME_[0-9a-f]{12}__$/)
    const readName = { sessionID: "read-name-session", tool: "read", input: { path: namePh } }
    await assert.rejects(before(readName), /not permitted/)
  })

  it("blocks a placeholder from a prior plugin instance after restart", async () => {
    const first = mockCtx()
    await setupV2(first.ctx)
    const event = { sessionID: "restart-session", prompt: { text: "/fake-private/Joe/path" } }
    first.sessionHooks.get("prompt")(event)
    const second = mockCtx()
    await setupV2(second.ctx)
    await assert.rejects(second.toolHooks.get("execute.before")({
      sessionID: "restart-session", tool: "read", input: { path: event.prompt.text },
    }), /mapping unavailable/)
  })
})
