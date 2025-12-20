// tools/zp-decision-bridge/src/index.ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import * as fs from "fs";
import * as path from "path";

const DECISIONS_DIR = process.env.ZP_DECISIONS_DIR || "./docs/decisions";
const PENDING_DIR = path.join(DECISIONS_DIR, "pending");

// Ensure directories exist
if (!fs.existsSync(DECISIONS_DIR)) fs.mkdirSync(DECISIONS_DIR, { recursive: true });
if (!fs.existsSync(PENDING_DIR)) fs.mkdirSync(PENDING_DIR, { recursive: true });

const server = new Server(
  { name: "zp-decision-bridge", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "create_escalation",
      description: "Create a new DA escalation request",
      inputSchema: {
        type: "object",
        properties: {
          component: { type: "string", description: "Which crate/module" },
          spec_section: { type: "string", description: "Relevant spec section" },
          question: { type: "string", description: "The specific question" },
          options: { type: "array", items: { type: "string" }, description: "Options considered" },
          blocking: { type: "boolean", description: "Is this blocking work?" }
        },
        required: ["component", "spec_section", "question", "options", "blocking"]
      }
    },
    {
      name: "get_decision",
      description: "Get a specific DA decision by ID",
      inputSchema: {
        type: "object",
        properties: {
          id: { type: "string", description: "Decision ID (e.g., DA-0001)" }
        },
        required: ["id"]
      }
    },
    {
      name: "list_decisions",
      description: "List decisions by status",
      inputSchema: {
        type: "object",
        properties: {
          status: { type: "string", enum: ["pending", "resolved", "all"] }
        },
        required: ["status"]
      }
    },
    {
      name: "search_decisions",
      description: "Search decisions by keyword",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search term" }
        },
        required: ["query"]
      }
    }
  ]
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "create_escalation": {
      const { component, spec_section, question, options, blocking } = args as any;
      const id = generateNextId();
      const content = formatEscalation(id, component, spec_section, question, options, blocking);
      const filepath = path.join(PENDING_DIR, `DA-${id}.md`);
      fs.writeFileSync(filepath, content);
      return {
        content: [{ type: "text", text: `Created escalation DA-${id} at ${filepath}` }]
      };
    }

    case "get_decision": {
      const { id } = args as any;
      const normalizedId = id.toUpperCase().replace("DA-", "");
      const pendingPath = path.join(PENDING_DIR, `DA-${normalizedId}.md`);
      const resolvedPath = path.join(DECISIONS_DIR, `DA-${normalizedId}.md`);

      if (fs.existsSync(resolvedPath)) {
        return {
          content: [{ type: "text", text: fs.readFileSync(resolvedPath, "utf-8") }]
        };
      } else if (fs.existsSync(pendingPath)) {
        return {
          content: [{ type: "text", text: `DA-${normalizedId} is PENDING:\n\n${fs.readFileSync(pendingPath, "utf-8")}` }]
        };
      }
      return {
        content: [{ type: "text", text: `DA-${normalizedId} not found` }]
      };
    }

    case "list_decisions": {
      const { status } = args as any;
      const results: string[] = [];

      if (status === "pending" || status === "all") {
        const pending = fs.readdirSync(PENDING_DIR).filter(f => f.endsWith(".md"));
        results.push(...pending.map(f => `[PENDING] ${f}`));
      }
      if (status === "resolved" || status === "all") {
        const resolved = fs.readdirSync(DECISIONS_DIR)
          .filter(f => f.startsWith("DA-") && f.endsWith(".md"));
        results.push(...resolved.map(f => `[RESOLVED] ${f}`));
      }

      return {
        content: [{ type: "text", text: results.length > 0 ? results.join("\n") : "No decisions found" }]
      };
    }

    case "search_decisions": {
      const { query } = args as any;
      const results: string[] = [];
      const searchDirs = [DECISIONS_DIR, PENDING_DIR];

      for (const dir of searchDirs) {
        if (!fs.existsSync(dir)) continue;
        for (const file of fs.readdirSync(dir)) {
          if (!file.endsWith(".md")) continue;
          const content = fs.readFileSync(path.join(dir, file), "utf-8");
          if (content.toLowerCase().includes(query.toLowerCase())) {
            const status = dir === PENDING_DIR ? "PENDING" : "RESOLVED";
            results.push(`[${status}] ${file}`);
          }
        }
      }

      return {
        content: [{ type: "text", text: results.length > 0 ? results.join("\n") : "No matches" }]
      };
    }

    default:
      return { content: [{ type: "text", text: `Unknown tool: ${name}` }] };
  }
});

function generateNextId(): string {
  const allFiles = [
    ...fs.readdirSync(DECISIONS_DIR).filter(f => f.startsWith("DA-")),
    ...fs.readdirSync(PENDING_DIR).filter(f => f.startsWith("DA-"))
  ];
  const ids = allFiles.map(f => parseInt(f.match(/DA-(\d+)/)?.[1] || "0"));
  const maxId = Math.max(0, ...ids);
  return String(maxId + 1).padStart(4, "0");
}

function formatEscalation(
  id: string,
  component: string,
  spec_section: string,
  question: string,
  options: string[],
  blocking: boolean
): string {
  const date = new Date().toISOString().split("T")[0];
  return `# DA-${id}: Pending Escalation

**Date:** ${date}
**Status:** PENDING
**Component:** ${component}
**Spec Section:** ${spec_section}
**Blocking:** ${blocking ? "Yes" : "No"}

## Question

${question}

## Options Considered

${options.map((o, i) => `${i + 1}. ${o}`).join("\n")}

## DA Decision

*Awaiting DA response*
`;
}

// Start server
const transport = new StdioServerTransport();
server.connect(transport);
console.error("zp-decision-bridge MCP running");