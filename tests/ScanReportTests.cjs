const assert = require("node:assert/strict");
const report = require("../web/scan-report.js");

assert.equal(report.isComplete({ status: 0, report: { errors: 0, modules: [{ status: 0, errors: 0 }] } }), true);
for (const result of [
  { status: 3 },
  { status: 2 },
  { status: 0, report: { errors: 1 } },
  { status: 0, report: { modules: [{ status: 3 }] } },
  { status: 0, report: { modules: [{ status: 0, errors: 1 }] } },
  { type: "scanError", message: "Failure" }
]) {
  assert.equal(report.isComplete(result), false);
  assert.notEqual(report.label(result), "Проверка завершена");
}
assert.equal(report.label({ status: 2 }, "en"), "Scan failed");
assert.equal(report.moduleLabel(3), "Нет доступа");
assert.equal(report.moduleLabel(4, "en"), "Skipped");
console.log("Scan report regressions passed");

assert.equal(report.isComplete({ status: 0, report: { findingsTruncated: 1 } }), false);
const all = Array.from({ length: 5001 }, (_, id) => ({ id }));
const pending = report.beginChunks("scum", "full");
for (let offset = 0; offset < all.length; offset += 256) {
  report.appendChunk(pending, { profile: "scum", mode: "full", offset, findings: all.slice(offset, offset + 256) });
}
const result = { profile: "scum", mode: "full", status: 0, report: { findingsReturned: 5001 } };
assert.deepEqual(report.finishChunks(pending, result).findings, all);
assert.equal(report.isComplete(report.finishChunks(pending, result)), true);
assert.equal(report.isComplete(report.finishChunks(report.beginChunks("scum", "full"), result)), false);
const wrong = report.beginChunks("scum", "full");
report.appendChunk(wrong, { profile: "scum", mode: "full", offset: 256, findings: all.slice(256, 512) });
assert.equal(report.isComplete(report.finishChunks(wrong, result)), false);
assert.equal(report.isComplete(report.finishChunks(null, result)), false);
const empty = { profile: "scum", mode: "full", status: 0, report: { findingsReturned: 0 } };
assert.equal(report.isComplete(report.finishChunks(report.beginChunks("scum", "full"), empty)), true);
console.log("Chunk delivery regressions passed");

assert.deepEqual(report.issues({ status: 0, report: { modules: [
  { name: "Processes", status: 0, errors: 0, rootsLimited: 0, depthLimitedDirectories: 0, excludedDirectories: 0 }
] } }), []);
assert.equal(report.modeLabel("full"), "Основная проверка");
const notes = report.issues({ status: 3, report: { modules: [
  { name: "Files", status: 1, errors: 2, rootsLimited: 1, excludedDirectories: 0 }
] } });
assert.equal(notes.length, 1);
assert.ok(notes[0].startsWith("Файлы:"));
assert.ok(!notes[0].includes("исключено папок"));
assert.ok(notes[0].includes("ошибок: 2"));
console.log("Compact report regressions passed");
