#!/usr/bin/env node
// Thin launcher for the prebuilt Terminus binary. Keeps stdio inherited so
// --json output and exit codes pass through untouched.
"use strict";
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// <process.platform>-<process.arch> -> binary shipped next to this file.
const binaries = {
  "win32-x64": "Terminus.exe",
  "linux-x64": "terminus-linux-x64",
  "linux-arm64": "terminus-linux-arm64",
  "darwin-x64": "terminus-darwin-x64",
  "darwin-arm64": "terminus-darwin-arm64",
};

const key = `${process.platform}-${process.arch}`;
const name = binaries[key];
if (!name) {
  console.error(`terminus: no prebuilt binary for ${key}.`);
  console.error("Supported: " + Object.keys(binaries).join(", ") + ". Build from source: https://github.com/yuanmao1/Terminus");
  process.exit(1);
}

const exe = path.join(__dirname, name);
if (process.platform !== "win32") {
  // npm only marks the `bin` entry executable, not the native binary beside it.
  try {
    fs.accessSync(exe, fs.constants.X_OK);
  } catch {
    try {
      fs.chmodSync(exe, 0o755);
    } catch (err) {
      console.error(`terminus: cannot make ${exe} executable: ${err.message}`);
      process.exit(1);
    }
  }
}

const result = spawnSync(exe, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(`terminus: failed to launch bundled binary: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
