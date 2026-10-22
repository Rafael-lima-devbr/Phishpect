const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
assert.equal(manifest.manifest_version, 3);
assert.deepEqual(manifest.permissions.sort(), ["storage", "webNavigation"]);
assert.deepEqual(manifest.host_permissions.sort(), ["http://*/*", "https://*/*"]);
assert.equal(Object.hasOwn(manifest, "content_security_policy"), false, "deve conservar CSP segura padrão do MV3");
assert.equal(Object.hasOwn(manifest, "externally_connectable"), false);

const warningHtml = fs.readFileSync(path.join(root, "warning.html"), "utf8");
const warningJs = fs.readFileSync(path.join(root, "warning.js"), "utf8");
const background = fs.readFileSync(path.join(root, "background.js"), "utf8");
for (const source of [warningHtml, warningJs, background]) {
  assert.equal(/\binnerHTML\b|\bouterHTML\b|eval\s*\(|new Function\s*\(/.test(source), false);
}
assert.equal(warningJs.includes('params.get("url")'), false);
assert.equal(warningJs.includes('get("reasons")'), false);
assert.equal(background.includes('searchParams.set("url"'), false);
assert.equal(background.includes('searchParams.set("reasons"'), false);
assert.equal(background.includes('searchParams.set("token"'), true);
assert.equal(background.includes("isWarningPageUrl(sender.url"), true);

console.log("Segurança da extensão V4: OK");
