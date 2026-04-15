import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../..");
const uiRoot = path.resolve(repoRoot, "ui");

dotenv.config({ path: path.join(repoRoot, ".env") });
dotenv.config({ path: path.join(uiRoot, ".env") });

const manifestPath = path.join(uiRoot, "stitch-manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const reportPath = path.join(uiRoot, "assets", "stitch", "download-report.json");

const curlBinary = process.platform === "win32" ? "curl.exe" : "curl";

function inferExtension(url) {
  try {
    const pathname = new URL(url).pathname;
    const ext = path.extname(pathname);
    return ext || ".zip";
  } catch {
    return ".zip";
  }
}

function runCurl(url, outputFile) {
  return new Promise((resolve, reject) => {
    const child = spawn(curlBinary, ["-L", "--fail", "--silent", "--show-error", url, "-o", outputFile], {
      stdio: "inherit"
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve(undefined);
        return;
      }

      reject(new Error(`curl exited with code ${code}`));
    });
  });
}

const results = [];

for (const screen of manifest.screens) {
  const url = process.env[screen.urlEnvVar];
  const categoryDir = path.join(uiRoot, "assets", "stitch", screen.category);
  await mkdir(categoryDir, { recursive: true });

  if (!url) {
    console.log(`Skipping ${screen.name}: missing ${screen.urlEnvVar}`);
    results.push({
      ...screen,
      downloaded: false,
      reason: `Missing ${screen.urlEnvVar}`,
      filePath: null
    });
    continue;
  }

  const outputFile = path.join(categoryDir, `${screen.slug}${inferExtension(url)}`);
  console.log(`Downloading ${screen.name} -> ${path.relative(repoRoot, outputFile)}`);

  try {
    await runCurl(url, outputFile);
    results.push({
      ...screen,
      downloaded: true,
      reason: null,
      filePath: path.relative(repoRoot, outputFile)
    });
  } catch (error) {
    results.push({
      ...screen,
      downloaded: false,
      reason: error instanceof Error ? error.message : "Unknown curl failure",
      filePath: path.relative(repoRoot, outputFile)
    });
  }
}

await writeFile(
  reportPath,
  JSON.stringify(
    {
      projectId: manifest.projectId,
      generatedAt: new Date().toISOString(),
      screens: results
    },
    null,
    2
  )
);

const downloaded = results.filter((entry) => entry.downloaded).length;
console.log(`Stitch export complete: ${downloaded}/${results.length} downloads succeeded.`);
