#!/usr/bin/env node
// Thin launcher for the prebuilt Terminus binary. Keeps stdio inherited so
// --json output and exit codes pass through untouched.
"use strict";
const { spawnSync } = require("child_process");
const path = require("path");

if (process.platform !== "win32") {
  console.error("terminus: prebuilt binaries currently ship for Windows x64 only.");
  console.error("Linux/macOS support is planned; build from source: https://github.com/terminus-shell/terminus");
  process.exit(1);
}

const exe = path.join(__dirname, "Terminus.exe");
const result = spawnSync(exe, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(`terminus: failed to launch bundled binary: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
