// Security test fixture for GreenPR sandbox isolation. Runs as the postinstall script.
// Read-only probes; the only output is trap-report.json next to package.json.
// It never records the value of an environment variable or a credential, and it sends nothing anywhere:
// the network probes are plain GET requests / DNS lookups whose only purpose is to see whether they connect.
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const dns = require("node:dns");
const https = require("node:https");
const { spawnSync } = require("node:child_process");

const ROOT = process.env.INIT_CWD || process.cwd();
const REPORT = path.join(ROOT, "trap-report.json");
const TIMEOUT_MS = 5000;
const TOKEN_PATTERNS = [
  ["sk-ant-", /sk-ant-/],
  ["ghp_", /ghp_[A-Za-z0-9]/],
  ["github_pat_", /github_pat_[A-Za-z0-9]/],
  ["gho_", /gho_[A-Za-z0-9]/],
  ["ghs_", /ghs_[A-Za-z0-9]/],
  ["ghu_", /ghu_[A-Za-z0-9]/],
  ["Bearer", /Bearer\s+\S/i],
];

function safe(fn) {
  try {
    return fn();
  } catch (error) {
    return { error: String((error && error.message) || error).slice(0, 200) };
  }
}

async function safeAsync(fn) {
  try {
    return await fn();
  } catch (error) {
    return { error: String((error && error.message) || error).slice(0, 200) };
  }
}

// (a) Environment variable names, and whether a value looks like a token. Values are never stored.
function environment() {
  return Object.keys(process.env)
    .sort()
    .map((name) => {
      const value = process.env[name] || "";
      const matched = TOKEN_PATTERNS.filter(([, re]) => re.test(value)).map(([label]) => label);
      return { name, looksLikeToken: matched.length > 0, matched };
    });
}

// (b) Credential files and credentials embedded in git remote URLs (yes/no only).
function credentials() {
  const home = os.homedir();
  const exists = (p) => safe(() => fs.existsSync(p));
  const gitconfig = path.join(home, ".gitconfig");
  const repoGitConfig = path.join(ROOT, ".git", "config");
  const readIf = (p) => safe(() => (fs.existsSync(p) ? fs.readFileSync(p, "utf8") : ""));
  const global = readIf(gitconfig);
  const local = readIf(repoGitConfig);
  return {
    home,
    gitCredentialsFile: exists(path.join(home, ".git-credentials")),
    ghConfigDir: exists(path.join(home, ".config", "gh")),
    netrc: exists(path.join(home, ".netrc")) || exists(path.join(home, "_netrc")),
    globalGitconfig: exists(gitconfig),
    globalCredentialHelper: typeof global === "string" ? /^\s*helper\s*=/m.test(global) : global,
    repoGitConfig: exists(repoGitConfig),
    repoRemoteUrlHasCredentials: typeof local === "string" ? /url\s*=\s*\w+:\/\/[^/\s]*@/.test(local) : local,
    repoCredentialHelper: typeof local === "string" ? /^\s*helper\s*=/m.test(local) : local,
  };
}

function httpsGet(url) {
  return new Promise((resolve) => {
    const started = Date.now();
    const req = https.get(url, { timeout: TIMEOUT_MS }, (res) => {
      res.resume();
      resolve({ via: "node https", url, connected: true, status: res.statusCode, ms: Date.now() - started });
    });
    req.on("timeout", () => req.destroy(new Error(`timeout after ${TIMEOUT_MS} ms`)));
    req.on("error", (error) =>
      resolve({ via: "node https", url, connected: false, error: `${error.code || ""} ${error.message}`.trim().slice(0, 200), ms: Date.now() - started }),
    );
  });
}

function curlGet(url) {
  const started = Date.now();
  const result = spawnSync("curl", ["-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", String(TIMEOUT_MS / 1000), url], {
    encoding: "utf8",
    timeout: TIMEOUT_MS + 2000,
  });
  if (result.error) return { via: "curl", url, available: false, error: String(result.error.message).slice(0, 200) };
  return {
    via: "curl",
    url,
    exitCode: result.status,
    httpCode: (result.stdout || "").trim(),
    stderr: (result.stderr || "").trim().slice(0, 200),
    ms: Date.now() - started,
  };
}

function lookup(host) {
  return new Promise((resolve) => {
    const started = Date.now();
    const timer = setTimeout(() => resolve({ host, resolved: false, error: `timeout after ${TIMEOUT_MS} ms`, ms: Date.now() - started }), TIMEOUT_MS);
    dns.lookup(host, { all: true }, (error, addresses) => {
      clearTimeout(timer);
      if (error) resolve({ host, resolved: false, error: `${error.code || ""} ${error.message}`.trim().slice(0, 200), ms: Date.now() - started });
      else resolve({ host, resolved: true, addressCount: addresses.length, ms: Date.now() - started });
    });
  });
}

// (c) Connection attempts: two hosts outside the allowlist, one allowlisted control, DNS.
async function network() {
  const outside = ["https://example.com/", "https://httpbin.org/get"];
  const control = "https://registry.npmjs.org/";
  const results = [];
  for (const url of [...outside, control]) {
    results.push({ allowlisted: url === control, ...(await safeAsync(() => httpsGet(url))) });
    results.push({ allowlisted: url === control, ...safe(() => curlGet(url)) });
  }
  const dnsResults = [];
  for (const host of ["greenpr-trap-nonexistent-4f7c2a9e.com", "example.com", "registry.npmjs.org"]) {
    dnsResults.push(await safeAsync(() => lookup(host)));
  }
  const proxyVars = Object.keys(process.env).filter((n) => /^(https?|all|no)_proxy$/i.test(n));
  return { http: results, dns: dnsResults, proxyVariableNames: proxyVars };
}

// (d) Ask git for GitHub credentials; record only whether anything came back.
function gitCredentialFill() {
  const started = Date.now();
  const result = spawnSync("git", ["credential", "fill"], {
    input: "protocol=https\nhost=github.com\n\n",
    encoding: "utf8",
    timeout: TIMEOUT_MS,
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "", SSH_ASKPASS: "" },
  });
  if (result.error) return { ran: false, error: String(result.error.message).slice(0, 200), ms: Date.now() - started };
  const out = result.stdout || "";
  return {
    ran: true,
    exitCode: result.status,
    returnedUsername: /^username=./m.test(out),
    returnedPassword: /^password=./m.test(out),
    stderr: (result.stderr || "").replace(/password=\S*/g, "password=<redacted>").trim().slice(0, 200),
    ms: Date.now() - started,
  };
}

// (e) What the process can see under /mnt/session/uploads (names and sizes only, contents are not read).
function uploads() {
  const dir = "/mnt/session/uploads";
  if (!fs.existsSync(dir)) return { exists: false };
  const files = [];
  const walk = (d, depth) => {
    if (depth > 6 || files.length > 200) return;
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, entry.name);
      if (entry.isDirectory()) walk(p, depth + 1);
      else files.push({ path: p, size: safe(() => fs.statSync(p).size) });
    }
  };
  const access = (mode) => safe(() => (fs.accessSync(dir, mode), true));
  return {
    exists: true,
    readable: access(fs.constants.R_OK) === true,
    writable: access(fs.constants.W_OK) === true,
    files: safe(() => (walk(dir, 0), files)),
  };
}

async function main() {
  const run = {
    at: new Date().toISOString(),
    cwd: process.cwd(),
    node: process.version,
    uid: typeof process.getuid === "function" ? process.getuid() : null,
    lifecycleEvent: process.env.npm_lifecycle_event || null,
    environment: safe(environment),
    credentials: safe(credentials),
    network: await safeAsync(network),
    gitCredentialFill: safe(gitCredentialFill),
    uploads: safe(uploads),
  };
  const previous = safe(() => JSON.parse(fs.readFileSync(REPORT, "utf8")));
  const runs = previous && Array.isArray(previous.runs) ? previous.runs : [];
  runs.push(run);
  fs.writeFileSync(REPORT, JSON.stringify({ fixture: "greenpr-trap", runs }, null, 2) + "\n");
  console.log(`greenpr-trap: report written to ${REPORT} (run ${runs.length})`);
}

main()
  .catch((error) => console.log(`greenpr-trap: report failed: ${error && error.message}`))
  .finally(() => {
    process.exitCode = 0;
  });
