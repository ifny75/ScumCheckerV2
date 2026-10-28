(function (root) {
  function isComplete(result) {
    return result?.status === 0 && !(result.report?.errors > 0) && !(result.report?.findingsTruncated > 0) &&
      (result.report?.modules || []).every(module => module.status === 0 && !module.errors);
  }

  function label(result, lang = "ru") {
    const ru = lang !== "en";
    if (isComplete(result)) return ru ? "Проверка завершена" : "Completed";
    if (result?.status === 1 || result?.status === 2 || result?.type === "scanError") {
      return ru ? "Ошибка проверки" : "Scan failed";
    }
    return ru ? "Проверка неполная" : "Incomplete scan";
  }

  function moduleLabel(status, lang = "ru") {
    const labels = lang === "en"
      ? ["Checked", "Partially checked", "Failed", "Access denied", "Skipped"]
      : ["Проверен", "Проверен частично", "Ошибка", "Нет доступа", "Пропущен"];
    return labels[status] || (lang === "en" ? "Unknown" : "Неизвестно");
  }

  function beginChunks(profile, mode) {
    return { profile, mode, findings: [], failed: false };
  }

  function appendChunk(pending, chunk) {
    if (!pending) return;
    if (pending.profile !== chunk.profile || pending.mode !== chunk.mode ||
        chunk.offset !== pending.findings.length || !Array.isArray(chunk.findings)) {
      pending.failed = true;
      return;
    }
    pending.findings.push(...chunk.findings);
  }

  function finishChunks(pending, result) {
    const findings = pending?.findings || [];
    const complete = pending && !pending.failed && pending.profile === result.profile &&
      pending.mode === result.mode && findings.length === result.report?.findingsReturned;
    if (complete) return { ...result, findings };
    return { ...result, findings, status: result.status === 0 ? 3 : result.status,
      report: { ...result.report, errors: (result.report?.errors || 0) + 1 },
      message: "Incomplete result delivery" };
  }

  const api = { isComplete, label, moduleLabel, beginChunks, appendChunk, finishChunks };
  root.ScanReport = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
