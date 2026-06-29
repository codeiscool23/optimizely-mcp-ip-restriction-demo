# Optimizely MCP IP Restriction Demo

A small local app that proves an MCP server's **IP allow-list is enforced** — by
authenticating once on a trusted network, then re-running the *same authenticated
calls* after you switch networks (e.g. to a mobile hotspot).

It connects to two remote [MCP](https://modelcontextprotocol.io) servers, each with
its **own OAuth login**:

| Server | Endpoint |
| --- | --- |
| Optimizely CMS | `https://cms.mcp.opal.optimizely.com/mcp` |
| Optimizely Experimentation | `https://exp.mcp.opal.optimizely.com/mcp` |

Both delegate to the same authorization server (`auth.mcp.opal.optimizely.com`) but
are distinct, audience-bound protected resources.

## What it demonstrates

- **Standards-based MCP OAuth 2.1** — protected-resource metadata discovery, Dynamic
  Client Registration, PKCE, authorization-code flow, and RFC 8707 `resource`
  (audience) binding so each token is scoped to one server.
- **Two independent auth sessions** side by side in one screen.
- **IP enforcement** — tokens are kept in the backend and reused verbatim across a
  network change, so the *only* variable between a passing and a failing call is your
  source IP.

## How it works

A tiny Node/Express backend performs the OAuth flow (its loopback redirect handles the
browser callback), stores the resulting tokens, and proxies MCP calls
(`initialize` → `notifications/initialized` → `tools/list` / `tools/call`) over the
Streamable HTTP transport. The single-page frontend shows two server cards and a live
egress-IP readout. Because the backend runs on your machine, its egress IP **is** your
network's IP — switch networks and the calls go out from the new address.

## Run it

```bash
npm install
npm start
# open http://localhost:4000
```

Requires Node 18+ (uses the global `fetch`).

## Demo script

1. On your trusted Wi-Fi, click **Connect** on each card and complete the login.
2. Click **Test connection** — both go green and load their tool lists. Optionally
   **Call a tool** (the args box auto-fills the simplest valid request).
3. Switch your machine to the **mobile hotspot**, then click **↻ Reload IP** — the IP
   turns amber while the baseline stays fixed.
4. Click **Test connection** / **Call tool** again — same tokens, new IP, so a
   restricted server returns an auth/forbidden error.

## Security notes

- OAuth tokens and the dynamically-registered client secret are written to
  `.mcp-demo-state.json`, which is **git-ignored** — it is never committed. Delete it
  to reset all connections.
- This is a local demo/testing tool: it binds to `localhost`, has no auth of its own,
  and is not intended to be deployed.

## Layout

```
server.js            # Express backend: OAuth + MCP proxy
public/index.html    # Single-page UI
```
