#!/usr/bin/env node
/* eslint-disable no-console */
const fs = require("fs");
const fsp = require("fs/promises");
const https = require("https");
const os = require("os");
const path = require("path");
const { spawn, spawnSync } = require("child_process");
const readline = require("readline");

const ROOT = path.resolve(__dirname, "..");
const VERSION = fs.readFileSync(path.join(ROOT, "VERSION"), "utf8").trim() || "0.0.5";
const OWNER = process.env.H3RETIK_RELEASE_OWNER || "nativ3ai";
const REPO = process.env.H3RETIK_RELEASE_REPO || "h3retik";
const TAG = process.env.H3RETIK_RELEASE_TAG || `v${VERSION}`;
const IS_WINDOWS = process.platform === "win32";
const GLOBAL_LAUNCHER = path.join(os.homedir(), ".local", "bin", "h3retik");
let windowsContainer = process.env.H3RETIK_KALI_CONTAINER || "h3retik-kali";
let windowsImage = process.env.H3RETIK_KALI_IMAGE || `h3retik/kali:v${VERSION}`;
const COMPOSE_FILE = path.join(ROOT, "docker-compose.yml");

function hasCommand(command) {
  const out = spawnSync(command, ["--version"], { stdio: "ignore" });
  return out.status === 0;
}

function mapPlatform() {
  if (process.platform === "darwin") return "darwin";
  if (process.platform === "linux") return "linux";
  if (process.platform === "win32") return "windows";
  return "";
}

function mapArch() {
  if (process.arch === "x64") return "amd64";
  if (process.arch === "arm64") return "arm64";
  return "";
}

function releaseAssetName() {
  const goos = mapPlatform();
  const goarch = mapArch();
  if (!goos || !goarch) return "";
  return `juicetui_${VERSION}_${goos}_${goarch}.tar.gz`;
}

function releaseAssetURL(asset) {
  return `https://github.com/${OWNER}/${REPO}/releases/download/${TAG}/${asset}`;
}

function downloadFile(url, destination) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(downloadFile(res.headers.location, destination));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`download failed (${res.statusCode}) ${url}`));
      }
      const out = fs.createWriteStream(destination);
      res.pipe(out);
      out.on("finish", () => out.close(resolve));
      out.on("error", reject);
      return undefined;
    });
    req.on("error", reject);
  });
}

function runOrThrow(command, args, opts = {}) {
  const out = spawnSync(command, args, { stdio: "inherit", ...opts });
  if (out.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed`);
  }
}

function ensureTelemetryDirs() {
  for (const rel of ["bin", "telemetry", "artifacts"]) {
    const dir = path.join(ROOT, rel);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }
}

async function ensurePrebuiltBinary() {
  const binDir = path.join(ROOT, "bin");
  const binPath = path.join(binDir, IS_WINDOWS ? "juicetui.exe" : "juicetui");
  const asset = releaseAssetName();
  if (!asset) return;

  await fsp.mkdir(binDir, { recursive: true });
  const tmpFile = path.join(os.tmpdir(), `h3retik-${asset}`);

  try {
    await downloadFile(releaseAssetURL(asset), tmpFile);
    const extract = spawnSync("tar", ["-xzf", tmpFile, "-C", binDir], { stdio: "pipe" });
    if (extract.status !== 0) {
      throw new Error(extract.stderr?.toString("utf8") || "tar extract failed");
    }
    if (!IS_WINDOWS) {
      await fsp.chmod(binPath, 0o755);
    }
    return;
  } catch (error) {
    if (fs.existsSync(binPath)) return;

    if (hasCommand("go")) {
      const binaryTarget = IS_WINDOWS ? "bin/juicetui.exe" : "bin/juicetui";
      const build = spawnSync("go", ["build", "-o", binaryTarget, "./cmd/juicetui"], {
        cwd: ROOT,
        stdio: "inherit"
      });
      if (build.status === 0) return;
    }

    throw new Error(
      `unable to provision juicetui binary (release asset: ${asset}). ` +
      `Create release ${TAG} assets first, or install Go to build locally.`
    );
  } finally {
    try { await fsp.unlink(tmpFile); } catch (_) {}
  }
}

function runInstallScript() {
  const installScript = path.join(ROOT, "scripts", "install_h3retik.sh");
  const out = spawnSync("bash", [installScript], { cwd: ROOT, stdio: "inherit" });
  if (out.status !== 0) {
    process.exit(out.status || 1);
  }
}

function runUnixLauncher(args) {
  const launcher = fs.existsSync(GLOBAL_LAUNCHER) ? GLOBAL_LAUNCHER : path.join(ROOT, "h3retik");
  const child = spawn(launcher, args, { stdio: "inherit", env: process.env });
  child.on("exit", (code) => process.exit(code ?? 0));
}

function unixLauncherPath() {
  return fs.existsSync(GLOBAL_LAUNCHER) ? GLOBAL_LAUNCHER : path.join(ROOT, "h3retik");
}

function runUnixLauncherSync(args, envExtra = {}) {
  const launcher = unixLauncherPath();
  runOrThrow(launcher, args, {
    env: { ...process.env, ...envExtra }
  });
}

function runUnixLauncherAsync(args, envExtra = {}) {
  const launcher = unixLauncherPath();
  const child = spawn(launcher, args, {
    stdio: "inherit",
    env: { ...process.env, ...envExtra }
  });
  child.on("exit", (code) => process.exit(code ?? 0));
}

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(String(answer || "").trim());
    });
  });
}

function printInstallProfiles() {
  console.log(`h3retik v${VERSION} modular setup\n`);
  console.log("Choose install profile:");
  console.log("  1) TUI only (no Docker auto-up)");
  console.log("  2) Full Docker runtime + TUI");
  console.log("  3) Headless CLI only (no TUI launch)");
  console.log("  4) Custom (open native setup wizard)");
}

async function chooseProfileInteractive() {
  printInstallProfiles();
  const ans = (await ask("Select profile [1-4] (default 2): ")).toLowerCase();
  if (ans === "" || ans === "2" || ans === "full") return "full";
  if (ans === "1" || ans === "tui" || ans === "tui-only") return "tui-only";
  if (ans === "3" || ans === "headless" || ans === "cli") return "headless";
  return "custom";
}

function parseProfileArg(args) {
  const idx = args.findIndex((arg) => arg === "--profile");
  if (idx === -1) return { profile: "", args };
  const value = (args[idx + 1] || "").trim().toLowerCase();
  const next = [...args.slice(0, idx), ...args.slice(idx + 2)];
  if (value === "tui-only" || value === "tui") return { profile: "tui-only", args: next };
  if (value === "full" || value === "docker") return { profile: "full", args: next };
  if (value === "headless" || value === "cli") return { profile: "headless", args: next };
  if (value === "custom" || value === "wizard") return { profile: "custom", args: next };
  return { profile: "", args: next };
}

function parseYesArg(args) {
  const next = [];
  let yes = false;
  for (const arg of args) {
    if (arg === "--yes" || arg === "-y") {
      yes = true;
      continue;
    }
    next.push(arg);
  }
  return { yes, args: next };
}

async function runGuidedInstallUnix(rawArgs) {
  const yesParsed = parseYesArg(rawArgs);
  const parsed = parseProfileArg(yesParsed.args);
  const profile = parsed.profile || (yesParsed.yes ? "full" : await chooseProfileInteractive());
  runInstallScript();
  if (profile === "custom") {
    runUnixLauncherAsync(["setup"]);
    return;
  }
  if (profile === "tui-only") {
    console.log("profile=tui-only :: launching TUI without docker auto-up");
    runUnixLauncherAsync(["--skip-up", "tui"]);
    return;
  }
  if (profile === "headless") {
    console.log("profile=headless :: preparing runtime only");
    runUnixLauncherSync(["up"]);
    console.log("runtime ready. next:");
    console.log("  h3retik doctor");
    console.log("  h3retik pipeline --target <url> --profile quick");
    return;
  }
  console.log("profile=full :: preparing docker runtime + launching TUI");
  runUnixLauncherSync(["up"]);
  runUnixLauncherAsync(["tui"]);
}

function windowsUsage() {
  console.log(`h3retik v${VERSION}\n`);
  console.log("Windows npm launcher commands:");
  console.log("  h3retik                # start kali + launch TUI");
  console.log("  h3retik init           # guided modular install/profile setup");
  console.log("  h3retik setup          # alias of init");
  console.log("  h3retik tui            # launch TUI");
  console.log("  h3retik up             # docker compose up -d kali");
  console.log("  h3retik down           # docker compose down");
  console.log("  h3retik shell          # shell in kali container");
  console.log("  h3retik kali <cmd...>  # execute command in kali");
  console.log("  h3retik doctor         # runtime checks");
  console.log("  h3retik version        # print version");
}

function ensureDockerAvailable() {
  const check = spawnSync("docker", ["info"], { stdio: "ignore" });
  if (check.status !== 0) {
    throw new Error("Docker Desktop is required and must be running");
  }
}

function windowsEnsureRuntime() {
  ensureDockerAvailable();

  const inspect = spawnSync("docker", ["inspect", windowsContainer], { stdio: "ignore" });
  if (inspect.status === 0) {
    const running = spawnSync("docker", ["inspect", "-f", "{{.State.Running}}", windowsContainer], { stdio: "pipe" });
    const isRunning = running.status === 0 && /true/i.test((running.stdout || "").toString());
    if (!isRunning) {
      runOrThrow("docker", ["start", windowsContainer]);
    }
    return;
  }

  runOrThrow("docker", ["compose", "-f", COMPOSE_FILE, "up", "-d", "kali"], {
    cwd: ROOT,
    env: {
      ...process.env,
      H3RETIK_KALI_CONTAINER: windowsContainer,
      H3RETIK_KALI_IMAGE: windowsImage
    }
  });
}

function windowsRunTUI(extraArgs) {
  const binPath = path.join(ROOT, "bin", "juicetui.exe");
  if (!fs.existsSync(binPath)) {
    throw new Error("missing bin/juicetui.exe");
  }
  const child = spawn(binPath, extraArgs, {
    stdio: "inherit",
    cwd: ROOT,
    env: {
      ...process.env,
      H3RETIK_ROOT: ROOT,
      H3RETIK_KALI_CONTAINER: windowsContainer,
      H3RETIK_KALI_IMAGE: windowsImage
    }
  });
  child.on("exit", (code) => process.exit(code ?? 0));
}

async function runWindowsEntry(rawArgs) {
  ensureTelemetryDirs();
  await ensurePrebuiltBinary();

  let args = [...rawArgs];
  let skipUp = false;
  while (args.length > 0) {
    const cur = args[0];
    if (cur === "--skip-up") {
      skipUp = true;
      args.shift();
      continue;
    }
    if (cur === "--kali-container") {
      if (!args[1]) throw new Error("--kali-container requires a value");
      windowsContainer = args[1];
      args.splice(0, 2);
      continue;
    }
    if (cur === "--kali-image") {
      if (!args[1]) throw new Error("--kali-image requires a value");
      windowsImage = args[1];
      args.splice(0, 2);
      continue;
    }
    break;
  }

  const cmd = args[0] || "tui";
  const rest = args.slice(1);

  switch (cmd) {
    case "init":
    case "setup": {
      const yesParsed = parseYesArg(rest);
      const parsed = parseProfileArg(yesParsed.args);
      const profile = parsed.profile || (yesParsed.yes ? "full" : await chooseProfileInteractive());
      if (profile === "custom") {
        console.log("custom profile on Windows npm launcher is equivalent to full runtime flow.");
      }
      if (profile === "tui-only") {
        windowsRunTUI(parsed.args);
        return;
      }
      if (profile === "headless") {
        windowsEnsureRuntime();
        console.log("runtime ready. next:");
        console.log("  h3retik doctor");
        console.log("  h3retik kali \"<cmd>\"");
        return;
      }
      windowsEnsureRuntime();
      windowsRunTUI(parsed.args);
      return;
    }
    case "tui":
      if (!skipUp) windowsEnsureRuntime();
      windowsRunTUI(rest);
      return;
    case "up":
      windowsEnsureRuntime();
      return;
    case "down":
      ensureDockerAvailable();
      runOrThrow("docker", ["compose", "-f", COMPOSE_FILE, "down"], { cwd: ROOT });
      return;
    case "shell":
      windowsEnsureRuntime();
      runOrThrow("docker", ["exec", "-it", windowsContainer, "bash"]);
      return;
    case "kali":
      windowsEnsureRuntime();
      if (rest.length === 0) {
        runOrThrow("docker", ["exec", "-it", windowsContainer, "bash"]);
        return;
      }
      runOrThrow("docker", ["exec", windowsContainer, "bash", "-lc", rest.join(" ")]);
      return;
    case "doctor":
      ensureDockerAvailable();
      console.log(`h3retik version: ${VERSION}`);
      console.log(`root: ${ROOT}`);
      runOrThrow("docker", ["version"]);
      return;
    case "version":
      console.log(VERSION);
      return;
    case "help":
    case "--help":
    case "-h":
      windowsUsage();
      return;
    case "update":
      console.log("Run: npm i -g @h1dr4/h3retik@latest");
      return;
    default:
      throw new Error(`unsupported command on native Windows npm launcher: ${cmd}`);
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = (argv[0] || "").toLowerCase();
  if (!IS_WINDOWS) {
    await ensurePrebuiltBinary();
    if (!fs.existsSync(GLOBAL_LAUNCHER)) {
      runInstallScript();
    }
    if (cmd === "init" || cmd === "setup") {
      await runGuidedInstallUnix(argv.slice(1));
      return;
    }
    runUnixLauncher(argv);
    return;
  }
  await runWindowsEntry(argv);
}

main().catch((error) => {
  console.error(`h3retik npm bootstrap failed: ${error.message}`);
  process.exit(1);
});
