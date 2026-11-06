import { Rpc } from "@opencode/plugin/rpc"

export const VibeguardHealth = Rpc.define({
  id: "vibeguard-health",
  methods: {
    status: {
      input: { type: "object", additionalProperties: false },
      output: {
        type: "object",
        properties: { ready: { type: "boolean" }, version: { type: "string" } },
        required: ["ready", "version"],
        additionalProperties: false,
      },
      errors: {},
    },
  },
  events: {},
})
