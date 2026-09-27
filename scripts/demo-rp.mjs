#!/usr/bin/env node
// A relying party the way a browser or native app is one: public client, authorization code with
// PKCE (S256), state and nonce checked, then the id_token's claims and /userinfo. No dependencies;
// Node 18 or later. Usage: node scripts/demo-rp.mjs <client_id>   (from create-public-client.sh)
import { createServer } from "node:http";
import { randomBytes, createHash } from "node:crypto";

const clientId = process.argv[2];
if (!clientId) {
  console.error("usage: node scripts/demo-rp.mjs <client_id>");
  process.exit(1);
}
const issuer = process.env.HYDRA_ISSUER ?? "http://127.0.0.1:14444/";
const port = 5556;
const redirectUri = `http://127.0.0.1:${port}/callback`;
const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const flows = new Map(); // state -> { verifier, nonce }

const discovery = await (await fetch(new URL(".well-known/openid-configuration", issuer))).json();

createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  if (url.pathname === "/") {
    const verifier = b64url(randomBytes(32));
    const state = b64url(randomBytes(16));
    const nonce = b64url(randomBytes(16));
    flows.set(state, { verifier, nonce });
    const auth = new URL(discovery.authorization_endpoint);
    auth.search = new URLSearchParams({
      client_id: clientId, response_type: "code", scope: "openid offline profile",
      redirect_uri: redirectUri, state, nonce,
      code_challenge: b64url(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256",
    }).toString();
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<h1>Demo public relying party</h1><p><a href="${auth}">Sign in with Homebase</a></p>`);
    return;
  }
  if (url.pathname === "/callback") {
    const flow = flows.get(url.searchParams.get("state"));
    if (!flow) { res.writeHead(400); res.end("unknown state"); return; }
    if (url.searchParams.get("error")) {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(`sign-in refused: ${url.searchParams.get("error")}: ${url.searchParams.get("error_description") ?? ""}`);
      return;
    }
    const token = await (await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", code: url.searchParams.get("code"),
        redirect_uri: redirectUri, client_id: clientId, code_verifier: flow.verifier,
      }),
    })).json();
    if (!token.id_token) { res.writeHead(500); res.end(JSON.stringify(token, null, 2)); return; }
    const claims = JSON.parse(Buffer.from(token.id_token.split(".")[1], "base64url").toString());
    if (claims.nonce !== flow.nonce) { res.writeHead(400); res.end("nonce mismatch"); return; }
    const userinfo = await (await fetch(discovery.userinfo_endpoint, { headers: { authorization: `Bearer ${token.access_token}` } })).json();
    const report = { subject: claims.sub, id_token: claims, userinfo, refresh_token: !!token.refresh_token };
    console.log(JSON.stringify(report, null, 2));
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<h1>Signed in as ${claims.sub}</h1><pre>${JSON.stringify(report, null, 2)}</pre><p><a href="/">Again</a></p>`);
    return;
  }
  res.writeHead(404); res.end();
}).listen(port, "127.0.0.1", () => console.log(`demo relying party: http://127.0.0.1:${port}/`));
