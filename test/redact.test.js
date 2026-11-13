import { describe, it } from "node:test"
import assert from "node:assert/strict"
import os from "node:os"
import path from "node:path"
import * as fs from "node:fs/promises"
import { buildPatternSet } from "../src/patterns.js"
import { PlaceholderSession } from "../src/session.js"
import { redactText } from "../src/engine.js"
import { loadPersonalRules } from "../src/config.js"
import { redactDeep, restoreDeep } from "../src/deep.js"
import { restoreText } from "../src/restore.js"

const FAKE = "cfut_" + "A".repeat(30)

function fixture() {
  const patterns = buildPatternSet({
    regex: [{ pattern: "\\bcfut_[A-Za-z0-9_-]{30,}\\b", category: "CLOUDFLARE_USER_TOKEN" }],
    builtin: [],
    keywords: [],
    exclude: [],
  })
  const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 3600000, maxMappings: 1000 })
  return { patterns, session }
}

describe("redact/restore round-trip", () => {
  it("replaces secret with placeholder and restores it", () => {
    const { patterns, session } = fixture()
    const out = redactText(`token=${FAKE} end`, patterns, session)
    assert.match(out.text, /__VG_CLOUDFLARE_USER_TOKEN_[0-9a-f]{12}__/)
    assert.doesNotMatch(out.text, /cfut_/)
    assert.equal(restoreText(out.text, session), `token=${FAKE} end`)
  })

  it("same secret maps to same placeholder within a session", () => {
    const { patterns, session } = fixture()
    const a = redactText(FAKE, patterns, session).text
    const b = redactText(`x ${FAKE} y`, patterns, session).text
    assert.ok(b.includes(a))
  })

  it("redactDeep/restoreDeep handle tool args objects", () => {
    const { patterns, session } = fixture()
    const args = { command: `curl -H "Authorization: Bearer ${FAKE}" https://x` }
    redactDeep(args, patterns, session)
    assert.doesNotMatch(args.command, /cfut_/)
    restoreDeep(args, session)
    assert.ok(args.command.includes(FAKE))
  })

  it("unknown placeholders are left as-is on restore", () => {
    const { session } = fixture()
    assert.equal(restoreText("__VG_NOPE_abcdef123456__", session), "__VG_NOPE_abcdef123456__")
  })
})


describe("personal literal matching", () => {
  it("redacts a standalone short name without mangling ordinary words", () => {
    const patterns = buildPatternSet({
      keywords: [{ value: "Joe", category: "NAME", boundary: true }],
    })
    const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 0, maxMappings: 1000 })
    const out = redactText("Joey met Joe, then Joe's colleague.", patterns, session)

    assert.match(out.text, /^Joey met __VG_NAME_[0-9a-f]{12}__, then __VG_NAME_[0-9a-f]{12}__'s colleague\.$/)
    assert.equal(out.matches.length, 2)
    assert.equal(restoreText(out.text, session), "Joey met Joe, then Joe's colleague.")
  })

  it("prefers a full PATH match over an embedded personal name", () => {
    const path = "/home/Joe/project"
    const patterns = buildPatternSet({
      keywords: [
        { value: path, category: "PATH" },
        { value: "Joe", category: "NAME", boundary: true },
      ],
    })
    const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 0, maxMappings: 1000 })
    const out = redactText(path, patterns, session)

    assert.match(out.text, /^__VG_PATH_[0-9a-f]{12}__$/)
    assert.equal(out.matches.length, 1)
    assert.equal(out.matches[0].category, "PATH")
    assert.equal(restoreText(out.text, session), path)
  })
})

describe("personal rule boundary policy", () => {
  it("uses plain substring matching for values of 5+ characters", async () => {
    const file = path.join(os.tmpdir(), `vg-personal-${process.pid}-${Date.now()}.json`)
    await fs.writeFile(file, JSON.stringify({ names: ["Marcus", "Joe"], addresses: [], other: [] }))
    try {
      const rules = await loadPersonalRules(file)
      const marcus = rules.find((rule) => rule.value === "Marcus")
      const joe = rules.find((rule) => rule.value === "Joe")
      assert.equal(marcus.boundary, false)
      assert.equal(joe.boundary, true)
    } finally {
      await fs.rm(file, { force: true })
    }
  })

  it("matches long values glued to underscores and letters", () => {
    const patterns = buildPatternSet({ keywords: [{ value: "Marcus", category: "NAME" }] })
    const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 0, maxMappings: 1000 })
    for (const text of ["Marcus_Report.pdf", "Report_Marcus.pdf", "FMarcus_Report.pdf"]) {
      const out = redactText(text, patterns, session)
      const names = out.matches.filter((m) => m.category === "NAME")
      assert.equal(names.length, 1, `expected one NAME match in ${text}`)
      assert.equal(restoreText(out.text, session), text)
    }
  })

  it("keeps token boundaries for short values", () => {
    const patterns = buildPatternSet({
      keywords: [{ value: "Joe", category: "NAME", boundary: true }],
    })
    const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 0, maxMappings: 1000 })
    const glued = redactText("Joe_Report.pdf", patterns, session)
    assert.equal(glued.matches.filter((m) => m.category === "NAME").length, 1)
    const word = redactText("Joey", patterns, session)
    assert.equal(word.matches.filter((m) => m.category === "NAME").length, 0)

    // Documented residual: short values glued to letters are not redacted.
    const residual = redactText("FJoe_Report.pdf", patterns, session)
    assert.equal(residual.matches.filter((m) => m.category === "NAME").length, 0)
  })
})
