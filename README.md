# greenpr-trap

Security test fixture for GreenPR sandbox isolation. Do not run outside a sandbox.

`npm install` runs `trap.js` (postinstall). It only reads and reports: environment variable names (never values) and
whether any value looks like a token, whether git/GitHub credential files exist, whether a few outbound connections and DNS
lookups succeed, whether `git credential fill` returns anything for github.com, and what is visible under
`/mnt/session/uploads`. The result is written to `trap-report.json`; nothing is sent anywhere.
