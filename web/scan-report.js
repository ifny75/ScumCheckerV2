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

  function modeLabel(mode, lang = "ru") {
    const labels = lang === "en"
      ? { full: "Main scan", steam: "Steam", history: "History", dma: "DMA / Network", seccfg: "Protection", kernel: "Kernel" }
      : { full: "Основная проверка", steam: "Steam", history: "История", dma: "DMA / Сеть", seccfg: "Защита", kernel: "Ядро" };
    return labels[mode] || mode;
  }

  function issues(result, lang = "ru") {
    const ru = lang !== "en";
    const lines = [];
    const names = { Files: "Файлы", Processes: "Процессы", Drivers: "Драйверы", Registry: "Реестр",
      History: "История", "Security configuration": "Защита", "Kernel provider": "Драйвер проверки" };
    for (const item of result.report?.modules || []) {
      const notes = [];
      if (item.errors) notes.push(ru ? `ошибок: ${item.errors}` : `errors: ${item.errors}`);
      if (item.rootsLimited) notes.push(ru ? `лимит обхода в ${item.rootsLimited} папках` : `entry limit in ${item.rootsLimited} roots`);
      if (item.depthLimitedDirectories) notes.push(ru ? `ограничена глубина: ${item.depthLimitedDirectories}` : `depth limited: ${item.depthLimitedDirectories}`);
      if (item.excludedDirectories) notes.push(ru ? `исключено папок: ${item.excludedDirectories}` : `excluded folders: ${item.excludedDirectories}`);
      if (item.status && !notes.length) notes.push(moduleLabel(item.status, lang));
      if (notes.length) lines.push(`${ru ? (names[item.name] || item.name) : item.name}: ${notes.join(", ")}`);
    }
    if (result.report?.findingsTruncated) lines.push(ru
      ? `Не получено находок: ${result.report.findingsTruncated}` : `Omitted findings: ${result.report.findingsTruncated}`);
    if (result.message) lines.push(result.message);
    if (!lines.length && result.report?.errors) lines.push(ru ? `Ошибок: ${result.report.errors}` : `Errors: ${result.report.errors}`);
    return lines;
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

  const api = { isComplete, label, moduleLabel, modeLabel, issues, beginChunks, appendChunk, finishChunks };
  root.ScanReport = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
