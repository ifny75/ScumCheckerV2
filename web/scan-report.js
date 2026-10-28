(function (root) {
  function isComplete(result) {
    return result?.status === 0 && !(result.report?.errors > 0) &&
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

  const api = { isComplete, label, moduleLabel };
  root.ScanReport = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
