const fs = require("node:fs");
const path = require("node:path");
const { sha256File } = require("./validation/dataset-c-lib.js");

function option(argv, name, fallback) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length) || fallback;
}

function jsonMetadata(filePath) {
  try {
    const value = JSON.parse(fs.readFileSync(filePath, "utf8"));
    if (Array.isArray(value)) return { record_count: value.length, embedded_timestamps: [] };
    const timestamps = new Set();
    if (value.created_at) timestamps.add(value.created_at);
    if (value.acquired_at) timestamps.add(value.acquired_at);
    if (Array.isArray(value.responses)) {
      for (const response of value.responses) {
        if (response.acquiredAt) timestamps.add(response.acquiredAt);
      }
    }
    let count = null;
    if (Array.isArray(value.records)) count = value.records.length;
    else if (Array.isArray(value.responses)) {
      count = value.responses.reduce((total, response) => {
        const items = response.data?.items;
        const bindings = response.data?.results?.bindings;
        return total + (Array.isArray(items) ? items.length : Array.isArray(bindings) ? bindings.length : 0);
      }, 0);
    }
    return { record_count: count, embedded_timestamps: [...timestamps].sort() };
  } catch {
    return { record_count: null, embedded_timestamps: [] };
  }
}

function textRecordCount(filePath) {
  const text = fs.readFileSync(filePath, "utf8");
  return text.split(/\r?\n/).filter((line) => line.trim()).length;
}

function inventory(rawDirectory) {
  const pending = [path.resolve(rawDirectory)];
  const files = [];
  while (pending.length) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(absolute);
      else if (entry.isFile() && entry.name !== "source-manifest.json") files.push(absolute);
    }
  }
  return files.sort().map((absolute) => {
    const stat = fs.statSync(absolute);
    const extension = path.extname(absolute).toLowerCase();
    const metadata = extension === ".json" ? jsonMetadata(absolute) : {
      record_count: [".txt", ".csv"].includes(extension) ? textRecordCount(absolute) : null,
      embedded_timestamps: []
    };
    return {
      path: path.relative(process.cwd(), absolute).replaceAll("\\", "/"),
      sha256: sha256File(absolute),
      bytes: stat.size,
      file_timestamp: stat.mtime.toISOString(),
      ...metadata
    };
  });
}

function main() {
  const argv = process.argv.slice(2);
  const rawDirectory = option(argv, "raw-dir", "evaluation/sources/dataset-c/raw");
  const output = option(argv, "output", "evaluation/sources/dataset-c/acquisition-manifest.json");
  const manifest = {
    schema_version: 1,
    status: "preparation-in-progress-not-sealed",
    created_at: new Date().toISOString(),
    detector_executed: false,
    raw_directory: rawDirectory.replaceAll("\\", "/"),
    files: inventory(rawDirectory)
  };
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify({ output, files: manifest.files.length }, null, 2));
}

if (require.main === module) main();

module.exports = { inventory, jsonMetadata, textRecordCount };
