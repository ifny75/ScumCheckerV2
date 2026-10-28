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
