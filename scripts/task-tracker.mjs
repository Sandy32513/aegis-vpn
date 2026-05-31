#!/usr/bin/env node

/**
 * Aegis VPN — Task Tracker
 *
 * Scans the codebase for TODO, FIXME, HACK, XXX, unimplemented!(), todo!()
 * and generates a summary report.
 *
 * Usage:
 *   node scripts/task-tracker.mjs              # Full scan + update TASK_MANAGER.md
 *   node scripts/task-tracker.mjs --scan-only  # Scan only, print to stdout
 *   node scripts/task-tracker.mjs --json       # Output as JSON
 */

import { readdir, readFile, writeFile, stat } from "fs/promises";
import { join, relative, extname } from "path";

const SCAN_DIR = join(import.meta.dirname, "..");
const OUTPUT_FILE = join(SCAN_DIR, "TASK_MANAGER.md");

const PATTERNS = [
  { label: "TODO", regex: /\bTODO\b/g },
  { label: "FIXME", regex: /\bFIXME\b/g },
  { label: "HACK", regex: /\bHACK\b/g },
  { label: "XXX", regex: /\bXXX\b/g },
  { label: "todo!()", regex: /todo!\(\)/g },
  { label: "unimplemented!()", regex: /unimplemented!\(\)/g },
  { label: "bypass_not_implemented", regex: /bypass_not_implemented/g },
  { label: 'Err(".*not implemented', regex: /Err\(["'].*not.*(implemented|available)/gi },
  { label: 'Err(".*stub', regex: /Err\(["'].*stub/gi },
  { label: 'Err(".*should be completed', regex: /Err\(["'].*should be (completed|validated)/gi },
  { label: "mock_", regex: /\bmock_\w+/g },
];

const IGNORE_DIRS = [
  "node_modules",
  "target",
  ".git",
  "dist",
  ".next",
  "coverage",
];

const SCAN_EXTENSIONS = [".rs", ".ts", ".tsx", ".mjs", ".js", ".toml"];

async function getFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (IGNORE_DIRS.includes(entry.name)) continue;
      files.push(...(await getFiles(fullPath)));
    } else if (SCAN_EXTENSIONS.includes(extname(entry.name))) {
      files.push(fullPath);
    }
  }

  return files;
}

function classifyPlatform(filePath) {
  const rel = relative(SCAN_DIR, filePath).replace(/\\/g, "/");
  if (rel.includes("vpn-platform-windows") || rel.includes("service_host") || rel.includes("service_installer") || rel.includes("wfp_native")) return "windows";
  if (rel.includes("vpn-platform-linux") || rel.includes("server_nat")) return "linux";
  if (rel.includes("vpn-platform-macos")) return "macos";
  if (rel.includes("vpn-platform-android")) return "android";
  if (rel.includes("ui/")) return "ui";
  return "global";
}

function classifySeverity(label) {
  if (["todo!()", "unimplemented!()", 'Err(".*not implemented', 'Err(".*should be completed', 'Err(".*stub'].includes(label)) return "critical";
  if (["FIXME", "bypass_not_implemented", "mock_"].includes(label)) return "high";
  if (["TODO", "HACK"].includes(label)) return "medium";
  return "low";
}

function truncateLine(line, max = 120) {
  const trimmed = line.trim();
  return trimmed.length > max ? trimmed.slice(0, max) + "..." : trimmed;
}

async function scanCodebase() {
  const files = await getFiles(SCAN_DIR);
  const findings = [];

  for (const filePath of files) {
    const content = await readFile(filePath, "utf-8");
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      for (const { label, regex } of PATTERNS) {
        const re = new RegExp(regex.source, regex.flags);
        if (re.test(lines[i])) {
          findings.push({
            file: relative(SCAN_DIR, filePath).replace(/\\/g, "/"),
            line: i + 1,
            pattern: label,
            content: truncateLine(lines[i]),
            platform: classifyPlatform(filePath),
            severity: classifySeverity(label),
          });
        }
      }
    }
  }

  return findings;
}

function generateReport(findings) {
  const byPlatform = {};
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const f of findings) {
    if (!byPlatform[f.platform]) byPlatform[f.platform] = [];
    byPlatform[f.platform].push(f);
    bySeverity[f.severity]++;
  }

  let report = "";
  report += `# Task Tracker Scan Report\n\n`;
  report += `**Generated:** ${new Date().toISOString()}\n`;
  report += `**Total findings:** ${findings.length}\n\n`;

  report += `## Summary\n\n`;
  report += `| Severity | Count |\n|---|---|\n`;
  for (const [sev, count] of Object.entries(bySeverity)) {
    report += `| ${sev.toUpperCase()} | ${count} |\n`;
  }

  report += `\n| Platform | Count |\n|---|---|\n`;
  for (const [platform, items] of Object.entries(byPlatform)) {
    report += `| ${platform} | ${items.length} |\n`;
  }

  report += `\n## Findings by Platform\n\n`;
  for (const [platform, items] of Object.entries(byPlatform)) {
    report += `### ${platform.toUpperCase()}\n\n`;
    report += `| Severity | Pattern | File | Line | Content |\n`;
    report += `|---|---|---|---|---|\n`;
    for (const f of items.sort((a, b) => a.severity.localeCompare(b.severity))) {
      report += `| ${f.severity} | ${f.pattern} | \`${f.file}\` | ${f.line} | ${f.content} |\n`;
    }
    report += `\n`;
  }

  return report;
}

function generateJson(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) bySeverity[f.severity]++;

  return JSON.stringify(
    {
      generated: new Date().toISOString(),
      total: findings.length,
      bySeverity,
      findings: findings.sort((a, b) =>
        a.severity.localeCompare(b.severity)
      ),
    },
    null,
    2
  );
}

async function main() {
  const args = process.argv.slice(2);
  const scanOnly = args.includes("--scan-only");
  const jsonOutput = args.includes("--json");

  console.log("[task-tracker] Scanning codebase...");
  const findings = await scanCodebase();

  if (jsonOutput) {
    console.log(generateJson(findings));
    return;
  }

  const report = generateReport(findings);

  if (scanOnly) {
    console.log(report);
    console.log(`[task-tracker] Found ${findings.length} items.`);
    return;
  }

  // Read existing TASK_MANAGER.md and inject scan results
  let taskManager = "";
  try {
    taskManager = await readFile(OUTPUT_FILE, "utf-8");
  } catch {
    console.log("[task-tracker] TASK_MANAGER.md not found, generating fresh report.");
  }

  const marker = "## AUTO-GENERATED SCAN RESULTS";
  const scanSection = `\n${marker}\n\n${report}\n`;

  if (taskManager.includes(marker)) {
    const idx = taskManager.indexOf(marker);
    const endIdx = taskManager.indexOf("\n## ", idx + marker.length);
    if (endIdx === -1) {
      taskManager = taskManager.slice(0, idx) + scanSection;
    } else {
      taskManager = taskManager.slice(0, idx) + scanSection + taskManager.slice(endIdx);
    }
  } else {
    taskManager += scanSection;
  }

  await writeFile(OUTPUT_FILE, taskManager, "utf-8");
  console.log(`[task-tracker] Updated ${OUTPUT_FILE} with ${findings.length} findings.`);
}

main().catch((err) => {
  console.error("[task-tracker] Error:", err.message);
  process.exit(1);
});
