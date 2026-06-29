// Optimizely MCP — IP restriction tester
// Authenticates two remote MCP servers via OAuth, keeps the tokens, and lets you
// re-run authenticated calls on demand. Switch networks (e.g. mobile hotspot) and
// hit "Test" again to see the IP restriction kick in.

import express from "express";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 4000;
const REDIRECT_URI = `http://localhost:${PORT}/oauth/callback`;
const STATE_FILE = path.join(__dirname, ".mcp-demo-state.json");

const SERVERS = {
  cms: {
    label: "Optimizely CMS",
    mcpUrl: "https://cms.mcp.opal.optimizely.com/mcp",
    resource: "https://cms.mcp.opal.optimizely.com",
    prm: "https://cms.mcp.opal.optimizely.com/.well-known/oauth-protected-resource",
  },
  exp: {
    label: "Optimizely Experimentation",
    mcpUrl: "https://exp.mcp.opal.optimizely.com/mcp",
    resource: "https://exp.mcp.opal.optimizely.com",
    prm: "https://exp.mcp.opal.optimizely.com/.well-known/oauth-protected-resource",
  },
};
const SCOPE = "openid profile email offline_access mcp:tools";

// ---- persisted state: dynamic-client registrations + tokens ----
let store = { clients: {}, tokens: {} };
try {
  if (fs.existsSync(STATE_FILE)) store = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
} catch {}
function save() {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(store, null, 2));
  } catch {}
}

const discoveryCache = {}; // server -> { authorization_endpoint, token_endpoint, registration_endpoint }
const pending = {}; // state -> { server, verifier }

async function discover(server) {
  if (discoveryCache[server]) return discoveryCache[server];
  const cfg = SERVERS[server];
  const prm = await (await fetch(cfg.prm)).json();
  const as = prm.authorization_servers[0];
  let meta;
  for (const url of [
    `${as}/.well-known/oauth-authorization-server`,
    `${as}/.well-known/openid-configuration`,
  ]) {
    const r = await fetch(url);
    if (r.ok) {
      meta = await r.json();
      break;
    }
  }
  if (!meta) throw new Error("could not load authorization server metadata");
  discoveryCache[server] = meta;
  return meta;
}

// Dynamic Client Registration (once per server, persisted)
async function ensureClient(server) {
  if (store.clients[server]) return store.clients[server];
  const meta = await discover(server);
  const res = await fetch(meta.registration_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Optimizely MCP IP Demo",
      redirect_uris: [REDIRECT_URI],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
      scope: SCOPE,
    }),
  });
  if (!res.ok) throw new Error(`DCR failed (${res.status}): ${await res.text()}`);
  const reg = await res.json();
  store.clients[server] = { client_id: reg.client_id, client_secret: reg.client_secret || null };
  save();
  return store.clients[server];
}

const b64url = (buf) => buf.toString("base64url");

// ---- Streamable HTTP MCP call: initialize -> initialized -> tools/list ----
function parseMcpBody(text, contentType) {
  if (contentType && contentType.includes("text/event-stream")) {
    const msgs = [];
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^data:\s?(.*)$/);
      if (m && m[1].trim()) {
        try {
          msgs.push(JSON.parse(m[1]));
        } catch {}
      }
    }
    return msgs;
  }
  try {
    return [JSON.parse(text)];
  } catch {
    return [];
  }
}

async function mcpRequest(url, token, sessionId, payload) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    Authorization: `Bearer ${token}`,
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(payload) });
  const text = await res.text();
  return {
    status: res.status,
    sessionId: res.headers.get("mcp-session-id") || sessionId,
    contentType: res.headers.get("content-type") || "",
    text,
  };
}

async function testServer(server) {
  const cfg = SERVERS[server];
  const tok = store.tokens[server];
  const t0 = Date.now();
  if (!tok) return { ok: false, stage: "auth", error: "Not connected — click Connect first." };

  // initialize
  const init = await mcpRequest(cfg.mcpUrl, tok.access_token, null, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "ip-demo", version: "1.0" },
    },
  });
  if (init.status === 401 || init.status === 403) {
    return {
      ok: false,
      stage: "initialize",
      httpStatus: init.status,
      error: init.text,
      ms: Date.now() - t0,
    };
  }
  const initMsgs = parseMcpBody(init.text, init.contentType);
  const initErr = initMsgs.find((m) => m.error);
  if (init.status >= 400 || initErr) {
    return {
      ok: false,
      stage: "initialize",
      httpStatus: init.status,
      error: initErr ? JSON.stringify(initErr.error) : init.text,
      ms: Date.now() - t0,
    };
  }

  // notifications/initialized
  await mcpRequest(cfg.mcpUrl, tok.access_token, init.sessionId, {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  });

  // tools/list
  const list = await mcpRequest(cfg.mcpUrl, tok.access_token, init.sessionId, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
    params: {},
  });
  if (list.status >= 400) {
    return {
      ok: false,
      stage: "tools/list",
      httpStatus: list.status,
      error: list.text,
      ms: Date.now() - t0,
    };
  }
  const listMsgs = parseMcpBody(list.text, list.contentType);
  const result = listMsgs.find((m) => m.result)?.result;
  const defs = result?.tools || [];
  return {
    ok: true,
    httpStatus: list.status,
    tools: defs.map((t) => t.name),
    toolDefs: defs.map((t) => ({
      name: t.name,
      description: t.description || "",
      inputSchema: t.inputSchema || null,
    })),
    serverInfo: initMsgs.find((m) => m.result)?.result?.serverInfo,
    ms: Date.now() - t0,
  };
}

// Authenticated tools/call round-trip (initialize -> initialized -> tools/call)
async function callTool(server, toolName, args) {
  const cfg = SERVERS[server];
  const tok = store.tokens[server];
  const t0 = Date.now();
  if (!tok) return { ok: false, stage: "auth", error: "Not connected — click Connect first." };

  const init = await mcpRequest(cfg.mcpUrl, tok.access_token, null, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "ip-demo", version: "1.0" },
    },
  });
  if (init.status >= 400) {
    return { ok: false, stage: "initialize", httpStatus: init.status, error: init.text, ms: Date.now() - t0 };
  }
  const initMsgs = parseMcpBody(init.text, init.contentType);
  const initErr = initMsgs.find((m) => m.error);
  if (initErr) {
    return { ok: false, stage: "initialize", httpStatus: init.status, error: JSON.stringify(initErr.error), ms: Date.now() - t0 };
  }

  await mcpRequest(cfg.mcpUrl, tok.access_token, init.sessionId, {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  });

  const call = await mcpRequest(cfg.mcpUrl, tok.access_token, init.sessionId, {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: toolName, arguments: args || {} },
  });
  if (call.status >= 400) {
    return { ok: false, stage: "tools/call", httpStatus: call.status, error: call.text, ms: Date.now() - t0 };
  }
  const msgs = parseMcpBody(call.text, call.contentType);
  const err = msgs.find((m) => m.error);
  if (err) {
    return { ok: false, stage: "tools/call", httpStatus: call.status, error: JSON.stringify(err.error), ms: Date.now() - t0 };
  }
  return { ok: true, httpStatus: call.status, result: msgs.find((m) => m.result)?.result, ms: Date.now() - t0 };
}

async function egressIp() {
  try {
    const r = await fetch("https://api.ipify.org?format=json", { signal: AbortSignal.timeout(6000) });
    return (await r.json()).ip;
  } catch {
    return null;
  }
}

// ----------------- HTTP API -----------------
const app = express();
app.use(express.json());
// Always serve fresh UI — this is an iterated demo app, stale cached JS causes confusion.
app.use(
  express.static(path.join(__dirname, "public"), {
    etag: false,
    lastModified: false,
    setHeaders: (res) => res.setHeader("Cache-Control", "no-store"),
  })
);

app.get("/api/ip", async (_req, res) => res.json({ ip: await egressIp() }));

app.get("/api/state", (_req, res) => {
  const out = {};
  for (const s of Object.keys(SERVERS)) {
    const tok = store.tokens[s];
    out[s] = {
      label: SERVERS[s].label,
      connected: !!tok,
      connectedIp: tok?.obtained_ip || null,
      connectedAt: tok?.obtained_at || null,
    };
  }
  res.json(out);
});

app.get("/api/:server/login", async (req, res) => {
  const server = req.params.server;
  if (!SERVERS[server]) return res.status(404).json({ error: "unknown server" });
  try {
    const meta = await discover(server);
    const client = await ensureClient(server);
    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
    const state = b64url(crypto.randomBytes(16));
    pending[state] = { server, verifier };
    const u = new URL(meta.authorization_endpoint);
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", client.client_id);
    u.searchParams.set("redirect_uri", REDIRECT_URI);
    u.searchParams.set("scope", SCOPE);
    u.searchParams.set("state", state);
    u.searchParams.set("code_challenge", challenge);
    u.searchParams.set("code_challenge_method", "S256");
    u.searchParams.set("resource", SERVERS[server].resource);
    res.json({ authUrl: u.toString() });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.get("/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;
  const done = (msg, ok) =>
    res.send(
      `<!doctype html><meta charset=utf8><body style="font-family:system-ui;background:#0b1020;color:#e6eaf2;display:grid;place-items:center;height:100vh;margin:0">
       <div style="text-align:center"><div style="font-size:42px">${ok ? "✅" : "⚠️"}</div>
       <h2>${msg}</h2><p style="opacity:.7">You can close this window and return to the demo.</p></div>
       <script>try{window.opener&&window.opener.postMessage('oauth-done','*')}catch(e){};setTimeout(()=>window.close(),1200)</script>`
    );
  if (error) return done(`Authorization failed: ${error_description || error}`, false);
  const p = pending[state];
  if (!p) return done("Unknown or expired login state.", false);
  delete pending[state];
  try {
    const meta = await discover(p.server);
    const client = store.clients[p.server];
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: client.client_id,
      code_verifier: p.verifier,
      resource: SERVERS[p.server].resource,
    });
    if (client.client_secret) body.set("client_secret", client.client_secret);
    const r = await fetch(meta.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!r.ok) return done(`Token exchange failed (${r.status})`, false);
    const tok = await r.json();
    store.tokens[p.server] = {
      access_token: tok.access_token,
      refresh_token: tok.refresh_token || null,
      expires_in: tok.expires_in || null,
      obtained_at: new Date().toISOString(),
      obtained_ip: await egressIp(),
    };
    save();
    done(`Connected to ${SERVERS[p.server].label}`, true);
  } catch (e) {
    done(`Error: ${String(e.message || e)}`, false);
  }
});

app.post("/api/:server/test", async (req, res) => {
  const server = req.params.server;
  if (!SERVERS[server]) return res.status(404).json({ error: "unknown server" });
  try {
    const result = await testServer(server);
    result.egressIp = await egressIp();
    res.json(result);
  } catch (e) {
    res.json({ ok: false, stage: "network", error: String(e.message || e), egressIp: await egressIp() });
  }
});

app.post("/api/:server/call", async (req, res) => {
  const server = req.params.server;
  if (!SERVERS[server]) return res.status(404).json({ error: "unknown server" });
  const { tool, args } = req.body || {};
  if (!tool) return res.status(400).json({ ok: false, error: "no tool selected" });
  try {
    const result = await callTool(server, tool, args || {});
    result.egressIp = await egressIp();
    res.json(result);
  } catch (e) {
    res.json({ ok: false, stage: "network", error: String(e.message || e), egressIp: await egressIp() });
  }
});

app.post("/api/:server/disconnect", (req, res) => {
  delete store.tokens[req.params.server];
  save();
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`\n  MCP IP demo → http://localhost:${PORT}\n`));
