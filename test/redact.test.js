import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { buildPatternSet } from "../src/patterns.js"
import { PlaceholderSession } from "../src/session.js"
import { redactText } from "../src/engine.js"
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
