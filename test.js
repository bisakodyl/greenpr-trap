"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");

const app = require("./index.js");

const server = app.listen(0, () => {
  const { port } = server.address();
  http.get(`http://127.0.0.1:${port}/health`, (res) => {
    let body = "";
    res.on("data", (chunk) => (body += chunk));
    res.on("end", () => {
      server.close();
      assert.equal(res.statusCode, 200);
      assert.deepEqual(JSON.parse(body), { ok: true });
      console.log("ok 1 - GET /health returns 200 and { ok: true }");
    });
  });
});
