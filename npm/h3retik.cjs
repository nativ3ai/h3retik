#!/usr/bin/env node
/* eslint-disable no-console */
const fs = require("fs");
const fsp = require("fs/promises");
const https = require("https");
const os = require("os");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const VERSION = fs.readFileSync(path.join(ROOT, "VERSION"), "utf8").trim() || "0.0.4";
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

function windowsUsage() {
  console.log(`h3retik v${VERSION}\n`);
  console.log("Windows npm launcher commands:");
  console.log("  h3retik                # start kali + launch TUI");
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
  if (!IS_WINDOWS) {
    await ensurePrebuiltBinary();
    if (!fs.existsSync(GLOBAL_LAUNCHER)) {
      runInstallScript();
    }
    runUnixLauncher(process.argv.slice(2));
    return;
  }
  await runWindowsEntry(process.argv.slice(2));
}

main().catch((error) => {
  console.error(`h3retik npm bootstrap failed: ${error.message}`);
  process.exit(1);
});
