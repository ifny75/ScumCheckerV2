const state = {
  profiles: [],
  activeProfile: null,
  activeFilter: "all",
  activePage: "dashboard",
  historyCategory: "all",
  findingsPageIndex: 0,
  findingsPageSize: 100,
  findingsFiltersOpen: false,
  lastFindings: [],
  scanReports: {},
  resultChunks: {},
  scanQueue: [],
  scanBusy: false,
  currentMode: null,
  completedModes: new Set(),
  autoRetryCount: {},
  steamView: "cards",
  steamProfiles: {},
  progressTimer: null,
  progressValue: 0,
  searches: {
    findings: "",
    steam: "",
    history: "",
    dma: "",
    seccfg: "",
    tools: "",
    hotkeys: ""
  }
};

const fallbackProfiles = [
  { id: "scum", name: "SCUM", status: "primary", enabled: true, note: "Основной профиль чекера" },
  { id: "minecraft", name: "Minecraft", status: "soon", enabled: false, note: "soon..." },
  { id: "cs", name: "CS", status: "soon", enabled: false, note: "soon..." }
];

const profileArt = {
  scum: "./assets/scum.png",
  minecraft: "./assets/minecraft.png",
  cs: "./assets/counter-strike.png"
};

const modeGroups = {
  steam: ["steam"],
  history: ["history"],
  dma: ["dma", "history"],
  seccfg: ["seccfg"],
  kernel: [],
  full: ["steam", "history", "dma", "findings"]
};

const startupScanModes = {
  scum: [
    { mode: "steam", label: "Steam accounts" },
    { mode: "full", label: "Full native scan" },
    { mode: "seccfg", label: "Security config" },
    { mode: "dma", label: "DMA / Network" }
  ],
  minecraft: []
};

const picker = document.querySelector("#picker");
const appShell = document.querySelector("#appShell");
const gameGrid = document.querySelector("#gameGrid");
const statusStrip = document.querySelector("#statusStrip");
const profileStatus = document.querySelector("#profileStatus");
const screenTitle = document.querySelector("#screenTitle");
const resultsList = document.querySelector("#resultsList");
const findingsPagination = document.querySelector("#findingsPagination");
const progressStage = document.querySelector("#progressStage");
const progressPercent = document.querySelector("#progressPercent");
const progressFill = document.querySelector("#progressFill");
const shaderCanvas = document.querySelector("#shaderCanvas");
const appShaderCanvas = document.querySelector("#appShaderCanvas");

const pickerNames = {
  scum: "Scum",
  minecraft: "Minecraft",
  cs: "Soon...."
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function bridge(message) {
  if (window.chrome?.webview) {
    window.chrome.webview.postMessage(JSON.stringify(message));
  } else {
    setStatus("WebView bridge is not available.");
  }
}

function setStatus(text) {
  statusStrip.textContent = text;
}

function setProgress(percent, stage) {
  const safe = Math.max(0, Math.min(100, Math.round(percent)));
  state.progressValue = safe;
  progressStage.textContent = stage || "Idle";
  progressPercent.textContent = `${safe}%`;
  progressFill.style.width = `${safe}%`;
  renderAstryxStatus();
}

function startProgress(mode) {
  stopProgress(false);
  const stages = {
    steam: ["Steam roots", "loginusers.vdf", "userdata history"],
    history: ["USB history", "BAM/DAM executions", "Device bus"],
    dma: ["PCIe devices", "Network connections", "ARP neighbours"],
    seccfg: ["Secure Boot", "Signature enforcement", "Defender / HVCI"],
    kernel: ["KSystemInformer", "KPH port", "Game handles", "Driver cross-checks"],
    full: ["Processes", "Files", "Drivers", "Registry", "Steam", "History"]
  }[mode] || ["Scanning"];

  let tick = 0;
  setProgress(4, stages[0]);
  state.progressTimer = window.setInterval(() => {
    tick += 1;
    const stage = stages[Math.min(stages.length - 1, Math.floor(tick / 5))];
    const step = mode === "full" ? 2 : 5;
    setProgress(Math.min(92, state.progressValue + step), stage);
  }, 420);
}

function stopProgress(done = true) {
  if (state.progressTimer) {
    window.clearInterval(state.progressTimer);
    state.progressTimer = null;
  }
  if (done) {
    setProgress(100, "Done");
    window.setTimeout(() => setProgress(0, "Idle"), 900);
  }
}

function profileById(id) {
  return (state.profiles.length ? state.profiles : fallbackProfiles).find(profile => profile.id === id);
}

function categoryGroup(category) {
  if (category === "Steam") return "steam";
  if (["UsbHistory", "ExecHistory", "DeviceHistory"].includes(category)) return "history";
  if (["PCIeDevice", "NetConn", "NetInfo", "NetArp"].includes(category)) return "dma";
  if (category === "SecurityConfig") return "seccfg";
  if (["KernelProvider", "KernelHandle"].includes(category)) return "findings";
  return "findings";
}

function profileAllowsCategory(category) {
  if (state.activeProfile === "minecraft") {
    return !["UsbHistory", "ExecHistory", "DeviceHistory", "PCIeDevice", "NetConn", "NetInfo", "NetArp"].includes(category);
  }
  return true;
}

function detectionBucket(item) {
  const cat = String(item.category || "").toLowerCase();
  const title = String(item.title || "").toLowerCase();
  if (cat.includes("process")) return { key: "processes", title: "Странные процессы", icon: "./assets/icons/executedprogramslist_ico.png" };
  if (cat.includes("file")) return { key: "files", title: "Странные файлы", icon: "./assets/icons/everything_ico.png" };
  if (cat.includes("driver") || cat.includes("pcie") || title.includes("thread") || title.includes("memory") || title.includes("module")) {
    return { key: "runtime", title: "Рантаймы / драйверы / память", icon: "./assets/icons/icon_native.png" };
  }
  return { key: "other", title: "Прочие индикаторы", icon: "./assets/icons/icon_scan.png" };
}

function findingMatches(item, query) {
  if (!query) return true;
  const q = query.toLowerCase();
  return [item.category, item.title, item.reason, item.details, item.evidencePath, item.severityName, item.score]
    .some(part => String(part ?? "").toLowerCase().includes(q));
}

function findingFilterMatches(item, filter) {
  if (!filter || filter === "all") return true;
  if (/^\d+$/.test(filter)) return String(item.severity) === filter;
  const text = textOf(item);
  const isFileLike = ["file", "process", "driverservice", "driver"].includes(String(item.category || "").toLowerCase());
  const systemName = /system-process|masquerad|system32|svchost|csrss|lsass|winlogon|services|explorer|runtimebroker/.test(text);
  const signed = /signature=valid|signed|valid signature|trusted signature/.test(text) && !/unsigned|invalid signature|signature=invalid/.test(text);
  const unsigned = /unsigned|invalid signature|signature=invalid|signature missing/.test(text);

  if (filter === "system-signed") return isFileLike && systemName && signed;
  if (filter === "system-unsigned") return isFileLike && systemName && unsigned;
  if (filter === "leaked-cert") return /leaked|abused code-signing|lapsus|certificate|known abused signer/.test(text);
  if (filter === "test-mode") return /testsigning|test-signing|test mode|nointegritychecks|disable_integrity_checks|dse|kernel debugging/.test(text);
  return true;
}

function visibleFindings() {
  return state.lastFindings.filter(item => profileAllowsCategory(item.category));
}

function bestEvidencePath(item) {
  const details = parseDetails(item.details);
  return item.evidencePath || details.Path || details.ProcessPath || details.ImagePath || "";
}

function activeGameLine(details) {
  if (state.activeProfile === "minecraft") {
    return { label: "Minecraft", value: "-" };
  }
  if (state.activeProfile === "cs") {
    return { label: "CS", value: details.CsLastPlayedLocal || "-" };
  }
  return { label: "SCUM", value: details.ScumLastPlayedLocal || "-" };
}

function setButtonsRunning(isRunning, mode = null) {
  document.querySelectorAll(".scan-action").forEach(button => {
    button.disabled = isRunning;
    button.classList.toggle("is-running", isRunning && button.dataset.mode === mode);
  });
}

function enqueueScan(mode, label = mode) {
  if (!state.activeProfile) return;
  if (state.currentMode === mode || state.scanQueue.some(item => item.mode === mode)) return;
  state.scanQueue.push({ mode, label });
  processScanQueue();
}

function processScanQueue() {
  if (state.scanBusy || !state.scanQueue.length || !state.activeProfile) return;
  const next = state.scanQueue.shift();
  state.scanBusy = true;
  state.currentMode = next.mode;
  setButtonsRunning(true, next.mode);
  setStatus(`Starting ${next.label}...`);
  startProgress(next.mode);
  bridge({ type: "scan", profile: state.activeProfile, mode: next.mode });
}

function finishScanStep(done = true) {
  state.scanBusy = false;
  state.currentMode = null;
  setButtonsRunning(false);
  stopProgress(done);
  processScanQueue();
}

function enqueueStartupScans(profileId) {
  const modes = startupScanModes[profileId] || [{ mode: "full", label: "Full native scan" }];
  for (const item of modes) {
    if (state.currentMode !== item.mode && !state.scanQueue.some(scan => scan.mode === item.mode)) {
      state.scanQueue.push(item);
    }
  }
  processScanQueue();
}

function groupHasData(group) {
  return visibleFindings().some(item => categoryGroup(item.category) === group);
}

function autoLoadPage(page) {
  const modeByPage = { steam: "steam", history: "history", dma: "dma", seccfg: "seccfg" };
  const mode = modeByPage[page];
  if (!mode || !state.activeProfile) return;
  if (page === "history" || page === "dma") {
    const button = document.querySelector(`.nav-button[data-page="${page}"]`);
    if (button && button.style.display === "none") return;
  }
  if (state.currentMode === mode || state.scanQueue.some(item => item.mode === mode)) return;
  if (groupHasData(mode)) return;
  if (state.completedModes.has(mode) && (state.autoRetryCount[mode] || 0) >= 3) return;
  state.autoRetryCount[mode] = (state.autoRetryCount[mode] || 0) + 1;
  enqueueScan(mode, `${page} auto scan`);
}

function refreshActivePageIfEmpty() {
  if (!state.activePage || state.scanBusy || state.scanQueue.length) return;
  window.setTimeout(() => autoLoadPage(state.activePage), 450);
}

function renderGamePicker() {
  gameGrid.innerHTML = "";
  const profiles = state.profiles.length ? state.profiles : fallbackProfiles;

  for (const profile of profiles) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `game-card game-${profile.id}`;
    button.disabled = !profile.enabled;
    const displayName = pickerNames[profile.id] || profile.name;
    button.innerHTML = `
      <img src="${profileArt[profile.id] || profileArt.scum}" alt="" onerror="this.closest('.game-card').classList.add('image-missing')">
      <div class="game-title">
        <span>${escapeHtml(displayName)}</span>
      </div>
      <div class="profile-note">${escapeHtml(profile.note || "")}</div>
    `;
    button.addEventListener("click", () => selectProfile(profile.id));
    gameGrid.appendChild(button);
  }
}

function initPickerShader(canvas = shaderCanvas) {
  const gl = canvas?.getContext("webgl", { antialias: true, alpha: false });
  if (!gl) return;

  const vertexSource = `
    attribute vec2 position;
    void main() {
      gl_Position = vec4(position, 0.0, 1.0);
    }
  `;

  const fragmentSource = `
    precision highp float;
    uniform vec2 resolution;
    uniform float time;

    float hash(vec2 p) {
      p = fract(p * vec2(123.34, 456.21));
      p += dot(p, p + 45.32);
      return fract(p.x * p.y);
    }

    float noise(vec2 p) {
      vec2 i = floor(p);
      vec2 f = fract(p);
      float a = hash(i);
      float b = hash(i + vec2(1.0, 0.0));
      float c = hash(i + vec2(0.0, 1.0));
      float d = hash(i + vec2(1.0, 1.0));
      vec2 u = f * f * (3.0 - 2.0 * f);
      return mix(a, b, u.x) + (c - a) * u.y * (1.0 - u.x) + (d - b) * u.x * u.y;
    }

    float fbm(vec2 p) {
      float value = 0.0;
      float amp = 0.5;
      for (int i = 0; i < 5; i++) {
        value += amp * noise(p);
        p *= 2.02;
        amp *= 0.5;
      }
      return value;
    }

    void main() {
      vec2 uv = gl_FragCoord.xy / resolution.xy;
      vec2 p = uv - 0.5;
      p.x *= resolution.x / resolution.y;

      float t = time * 0.06;
      float originX = sin(time * 0.05) * 0.03 + cos(time * 0.021) * 0.015;
      float dx = p.x - originX;

      float warp = fbm(vec2(dx * 3.0, uv.y * 2.5 - t * 4.0)) - 0.5;
      warp += 0.5 * (fbm(vec2(dx * 6.0 + 10.0, uv.y * 4.0 - t * 6.0)) - 0.5);
      float distortedX = dx + warp * 0.10 * (1.0 - uv.y * 0.4);

      float beamWidth = mix(0.045, 0.16, uv.y);
      float core = exp(-pow(distortedX / beamWidth, 2.0));
      float glowWidth = mix(0.18, 0.55, uv.y);
      float glow = exp(-pow(distortedX / glowWidth, 2.0));

      float split = smoothstep(0.0, 0.35, uv.y) * (1.0 - smoothstep(0.35, 0.75, uv.y));
      float lobe = exp(-pow((abs(distortedX) - 0.05 * split) / (beamWidth * 0.9), 2.0));
      core = max(core, lobe * 0.9);

      float vFalloff = smoothstep(1.05, -0.1, uv.y);
      float flicker = 0.92 + 0.08 * sin(time * 3.1 + fbm(vec2(uv.y * 5.0, t)) * 6.0);
      float intensity = (core * 1.05 + glow * 0.34) * vFalloff * flicker;

      vec3 ice = vec3(0.72, 0.88, 1.0);
      vec3 blue = vec3(0.10, 0.35, 0.95);
      vec3 deepBlue = vec3(0.015, 0.055, 0.18);
      vec3 black = vec3(0.0, 0.002, 0.012);

      vec3 color = mix(black, deepBlue, smoothstep(0.0, 0.42, intensity));
      color = mix(color, blue, smoothstep(0.32, 0.86, intensity));
      color = mix(color, ice, smoothstep(0.82, 1.65, intensity));

      float vignette = smoothstep(1.1, 0.25, length(p * vec2(1.0, 0.8)));
      color *= mix(0.6, 1.0, vignette);

      float grain = hash(gl_FragCoord.xy + time) - 0.5;
      color += grain * 0.018;
      color *= 0.52;

      gl_FragColor = vec4(clamp(color, 0.0, 1.0), 1.0);
    }
  `;

  function compile(type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) return null;
    return shader;
  }

  const vertex = compile(gl.VERTEX_SHADER, vertexSource);
  const fragment = compile(gl.FRAGMENT_SHADER, fragmentSource);
  if (!vertex || !fragment) return;

  const program = gl.createProgram();
  gl.attachShader(program, vertex);
  gl.attachShader(program, fragment);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return;

  const buffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]), gl.STATIC_DRAW);

  const position = gl.getAttribLocation(program, "position");
  const resolution = gl.getUniformLocation(program, "resolution");
  const time = gl.getUniformLocation(program, "time");
  let started = performance.now();

  function resize() {
    const scale = Math.min(window.devicePixelRatio || 1, 2);
    const width = Math.max(1, Math.floor(canvas.clientWidth * scale));
    const height = Math.max(1, Math.floor(canvas.clientHeight * scale));
    if (canvas.width !== width || canvas.height !== height) {
      canvas.width = width;
      canvas.height = height;
      gl.viewport(0, 0, width, height);
    }
  }

  function draw(now) {
    resize();
    gl.useProgram(program);
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.enableVertexAttribArray(position);
    gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);
    gl.uniform2f(resolution, canvas.width, canvas.height);
    gl.uniform1f(time, (now - started) / 1000);
    gl.drawArrays(gl.TRIANGLES, 0, 6);
    window.requestAnimationFrame(draw);
  }

  window.requestAnimationFrame(draw);
}

function selectProfile(profileId) {
  const profile = profileById(profileId);
  if (!profile || !profile.enabled) return;

  state.activeProfile = profile.id;
  state.lastFindings = [];
  state.scanReports = {};
  state.resultChunks = {};
  renderScanReports();
  state.steamProfiles = {};
  state.scanQueue = [];
  state.scanBusy = false;
  state.currentMode = null;
  state.completedModes = new Set();
  state.autoRetryCount = {};

  appShell.classList.remove("theme-scum", "theme-minecraft", "theme-cs");
  appShell.classList.add(`theme-${profile.id}`);
  applyProfileVisibility(profile.id);

  document.querySelector("#activeGameName").textContent = profile.name;
  document.querySelector("#activeGameIcon").src = profileArt[profile.id] || profileArt.scum;
  state.activeProfileName = profile.name;
  applyProfileTitles();
  picker.classList.add("hidden");
  appShell.classList.remove("hidden");
  showPage("dashboard");
  updateStats(null);
  renderAllData();
  setStatus("Starting automatic profile checks...");
  enqueueStartupScans(profile.id);
}

function applyProfileVisibility(profileId) {
  document.querySelectorAll("[data-profiles]").forEach(node => {
    const allowed = node.dataset.profiles.split(",").map(x => x.trim());
    node.style.display = allowed.includes(profileId) ? "" : "none";
  });
  const currentButton = document.querySelector(`.nav-button[data-page="${state.activePage}"]`);
  if (currentButton && currentButton.style.display === "none") {
    showPage("dashboard");
  }
}

function showPage(page) {
  state.activePage = page;
  document.querySelectorAll(".nav-button").forEach(button => {
    button.classList.toggle("active", button.dataset.page === page);
  });
  document.querySelectorAll(".page").forEach(item => {
    item.classList.toggle("active", item.id === `page-${page}`);
  });
  if (page === "astryx") renderAstryxView();
  autoLoadPage(page);
}

function renderFindings() {
  const baseFindings = visibleFindings().filter(item => categoryGroup(item.category) === "findings");
  const filtered = baseFindings.filter(item => findingFilterMatches(item, state.activeFilter));
  const findings = filtered.filter(item => findingMatches(item, state.searches.findings));
  const pageSize = state.findingsPageSize;
  const totalPages = Math.max(1, Math.ceil(findings.length / pageSize));
  state.findingsPageIndex = Math.min(Math.max(0, state.findingsPageIndex), totalPages - 1);
  const start = state.findingsPageIndex * pageSize;
  const pageFindings = findings.slice(start, start + pageSize);

  renderFindingsPagination(findings.length, totalPages);

  if (!findings.length) {
    resultsList.innerHTML = `<div class="empty-state">No findings for this filter/search.</div>`;
    return;
  }

  const buckets = new Map();
  for (const item of pageFindings) {
    const bucket = detectionBucket(item);
    if (!buckets.has(bucket.key)) buckets.set(bucket.key, { ...bucket, items: [] });
    buckets.get(bucket.key).items.push(item);
  }

  resultsList.innerHTML = Array.from(buckets.values()).map(bucket => `
    <section class="detection-section">
      <div class="detection-section-head">
        <img src="${bucket.icon}" alt="">
        <div>
          <h4>${escapeHtml(bucket.title)}</h4>
          <p>${bucket.items.length} item(s)</p>
        </div>
      </div>
      ${bucket.items.map(renderFindingCard).join("")}
    </section>
  `).join("");
  bindEvidenceButtons();
}

function renderFindingsPagination(total, totalPages) {
  if (!findingsPagination) return;
  if (!total) {
    findingsPagination.innerHTML = "";
    return;
  }
  const page = state.findingsPageIndex + 1;
  const start = state.findingsPageIndex * state.findingsPageSize + 1;
  const end = Math.min(total, state.findingsPageIndex * state.findingsPageSize + state.findingsPageSize);
  findingsPagination.innerHTML = `
    <span>${start}-${end} / ${total}</span>
    <div class="pager-buttons">
      <button class="mini-button page-button" data-page-step="-1" type="button" ${page <= 1 ? "disabled" : ""}>Prev</button>
      <strong>${page} / ${totalPages}</strong>
      <button class="mini-button page-button" data-page-step="1" type="button" ${page >= totalPages ? "disabled" : ""}>Next</button>
    </div>
  `;
  findingsPagination.querySelectorAll(".page-button").forEach(button => {
    button.addEventListener("click", () => {
      state.findingsPageIndex += Number(button.dataset.pageStep || 0);
      renderFindings();
    });
  });
}

function renderFindingCard(item) {
  const bucket = detectionBucket(item);
  const evidence = bestEvidencePath(item);
  const canInspectProcess = bucket.key === "processes" || item.category === "NetConn";
  const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(`${item.title || item.details || "windows process"} process what is it`)}`;
  return `
    <article class="finding">
      <div class="finding-title">
        <span><img class="inline-icon" src="${bucket.icon}" alt="">${escapeHtml(item.title || "Untitled finding")}</span>
        <span class="severity-${item.severity}">${escapeHtml(item.severityName)} / ${item.score}</span>
      </div>
      <div class="finding-meta">${escapeHtml(item.category || "General")} · ${escapeHtml(item.reason || "No reason")}</div>
      <div class="finding-meta">${escapeHtml(item.details || "")}</div>
      ${evidence ? `<div class="finding-meta evidence-line">${escapeHtml(evidence)}</div>` : ""}
      <div class="finding-actions">
        ${canInspectProcess ? `<button class="mini-button evidence-button" data-open="taskmgr" type="button">Task Manager</button>` : ""}
        ${canInspectProcess ? `<button class="mini-button evidence-button" data-open="${escapeHtml(searchUrl)}" type="button">Web search</button>` : ""}
        ${evidence ? `<button class="mini-button evidence-button" data-reveal="${escapeHtml(evidence)}" type="button">Reveal evidence</button>` : ""}
      </div>
    </article>
  `;
}

function bindEvidenceButtons() {
  document.querySelectorAll(".evidence-button").forEach(button => {
    button.addEventListener("click", () => {
      if (button.dataset.open) bridge({ type: "open", target: button.dataset.open });
      if (button.dataset.reveal) bridge({ type: "reveal", path: button.dataset.reveal });
    });
  });
}

function parseDetails(details) {
  const parsed = {};
  for (const part of String(details || "").split("|")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    parsed[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }
  return parsed;
}

function itemTime(item) {
  const text = `${item.details || ""} ${item.evidencePath || ""}`;
  const iso = text.match(/\b20\d{2}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?\b/);
  if (iso) {
    const parsed = Date.parse(iso[0].replace(" ", "T"));
    if (!Number.isNaN(parsed)) return parsed;
  }
  const timestamp = text.match(/\b(?:Timestamp|lastRun|Login)=(\d{9,13})\b/i);
  if (timestamp) {
    const value = Number(timestamp[1]);
    if (Number.isFinite(value)) return value < 100000000000 ? value * 1000 : value;
  }
  return 0;
}

function sortRowsForGroup(rows, group) {
  const copy = [...rows];
  if (group === "history") {
    return copy.sort((a, b) => itemTime(a) - itemTime(b));
  }
  return copy.sort((a, b) => (b.severity || 0) - (a.severity || 0));
}

function renderHistoryFlow(container, rows, emptyText) {
  if (!rows.length) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(emptyText)}</div>`;
    return;
  }

  const limited = rows;
  container.innerHTML = `
    <div class="history-flow">
      ${limited.map((item, index) => {
        const details = parseDetails(item.details);
        const when = details.lastRun || details.LastRun || details.LoginTimeLocal || "";
        const label = item.category === "ExecHistory" ? "Запуск ПО" :
          item.category === "UsbHistory" ? "USB/device event" : "Device inventory";
        const next = limited[index + 1];
        const hasLaunchEdge = next && item.category === "ExecHistory" &&
          /parent|child|spawn|created process|launched/i.test(`${item.reason} ${item.details} ${next.reason} ${next.details}`);
        return `
          <article class="history-step severity-${item.severity}">
            <div class="history-step-kicker">${escapeHtml(label)}${when ? ` · ${escapeHtml(when)}` : ""}</div>
            <strong>${escapeHtml(item.title)}</strong>
            <span>${escapeHtml(item.reason || item.details || "")}</span>
            ${item.evidencePath ? `<small>${escapeHtml(item.evidencePath)}</small>` : ""}
          </article>
          ${hasLaunchEdge ? `<div class="history-arrow" aria-hidden="true">↓</div>` : ""}
        `;
      }).join("")}
    </div>
  `;
}

function dmaKind(item) {
  if (item.category === "PCIeDevice") return "pcie";
  if (item.category === "NetConn") return "connection";
  if (item.category === "NetArp") return "neighbour";
  return "note";
}

function renderDmaCards(container, rows) {
  const counts = rows.reduce((acc, item) => {
    acc[dmaKind(item)] = (acc[dmaKind(item)] || 0) + 1;
    if (item.severity >= 3) acc.high++;
    if (item.severity === 2) acc.medium++;
    return acc;
  }, { pcie: 0, connection: 0, neighbour: 0, note: 0, high: 0, medium: 0 });

  container.innerHTML = `
    <section class="dma-summary">
      <article><strong>${counts.pcie}</strong><span>PCIe devices</span></article>
      <article><strong>${counts.connection}</strong><span>Connections</span></article>
      <article><strong>${counts.neighbour}</strong><span>LAN neighbours</span></article>
      <article><strong>${counts.high}</strong><span>High risk</span></article>
    </section>
    <section class="dma-list">
      ${rows.map(item => {
        const kind = dmaKind(item);
        const details = parseDetails(item.details);
        const badge = kind === "pcie" ? "PCIe" : kind === "connection" ? "TCP" : kind === "neighbour" ? "LAN" : "Info";
        const main = kind === "pcie"
          ? `${details.Driver || "driver?"} · ${details.class || details.mfg || "device"}`
          : item.reason;
        return `
          <article class="dma-card kind-${kind}">
            <div class="dma-card-head">
              <span>${badge}</span>
              <strong class="severity-${item.severity}">${escapeHtml(item.severityName)}</strong>
            </div>
            <h4>${escapeHtml(item.title)}</h4>
            <p>${escapeHtml(main || "")}</p>
            <small>${escapeHtml(item.details || item.evidencePath || "")}</small>
          </article>
        `;
      }).join("")}
    </section>
  `;
}

function renderSteam() {
  const allSteamItems = visibleFindings().filter(item => item.category === "Steam" && item.title === "Steam account");
  const steamItems = allSteamItems.filter(item => findingMatches(item, state.searches.steam));
  document.querySelector("#steamCount").textContent = allSteamItems.length;

  if (!steamItems.length) {
    document.querySelector("#steamCards").innerHTML = `<div class="empty-state">Steam accounts are loading automatically. Use Refresh Steam if Steam was opened later.</div>`;
    document.querySelector("#steamSummary").innerHTML = `<div class="compact-item">No Steam account cards yet.</div>`;
    return;
  }

  document.querySelector("#steamCards").innerHTML = steamItems.map(item => {
    const details = parseDetails(item.details);
    const steamId = details.SteamID || "";
    const account = details.AccountName || "unknown";
    if (steamId && !state.steamProfiles[steamId]) {
      state.steamProfiles[steamId] = { loading: true };
      bridge({ type: "steamProfile", steamId });
    }
    const profile = state.steamProfiles[steamId] || {};
    const persona = profile.persona && !profile.unknown ? profile.persona : (details.PersonaName || account);
    const recent = details.MostRecent === "1";
    const timestamp = details.LoginTimeLocal || details.Timestamp || "";
    const avatar = profile.avatar || "./assets/icons/account.png";
    const game = activeGameLine(details);
    const banLabel = profile.loading
      ? "Steam: loading..."
      : `VAC: ${profile.vacBans ?? 0} · Game bans: ${profile.gameBans ?? 0}`;
    const days = profile.daysSinceLastBan === null || profile.daysSinceLastBan === undefined
      ? "-"
      : `${profile.daysSinceLastBan} days`;
    return `
      <article class="steam-card ${recent ? "current" : ""}" data-steamid="${escapeHtml(steamId)}">
        <div class="steam-card-head">
          <img class="steam-avatar" src="${avatar}" alt="" onerror="this.src='./assets/icons/account.png'">
          <div>
            <h4>${escapeHtml(persona)}</h4>
            <p>Account: ${escapeHtml(account)}</p>
          </div>
        </div>
        <div class="steam-info-lines">
          <p>SteamID64: ${escapeHtml(steamId)}</p>
          <p>MostRecent: ${recent ? "yes" : "no"}</p>
        </div>
        <div class="steam-info-lines">
          <p>Login: ${escapeHtml(timestamp || "-")}</p>
          <p>${escapeHtml(game.label)}: ${escapeHtml(game.value)}</p>
        </div>
        <div class="steam-info-lines">
          <p>${escapeHtml(banLabel)}</p>
          <p>Last ban: ${escapeHtml(days)}</p>
        </div>
      </article>
    `;
  }).join("");

  document.querySelector("#steamCards").classList.toggle("grid-mode", state.steamView === "grid");

  document.querySelector("#steamSummary").innerHTML = allSteamItems.slice(0, 4).map(item => {
    const details = parseDetails(item.details);
    return `<div class="compact-item">${escapeHtml(details.PersonaName || details.AccountName || details.SteamID || "Steam account")}</div>`;
  }).join("");

  document.querySelectorAll(".steam-card").forEach(card => {
    card.addEventListener("dblclick", () => {
      const id = card.dataset.steamid;
      if (id) bridge({ type: "open", target: `https://steamcommunity.com/profiles/${id}` });
    });
  });
}

function renderRows(containerId, group, emptyText) {
  const query = state.searches[group] || "";
  const rows = visibleFindings()
    .filter(item => categoryGroup(item.category) === group)
    .filter(item => findingMatches(item, query))
    .filter(item => group !== "history" || state.historyCategory === "all" || item.category === state.historyCategory);
  if (group === "history") {
    const history = visibleFindings().filter(item => categoryGroup(item.category) === "history");
    document.querySelectorAll("[data-history-count]").forEach(badge => {
      const category = badge.dataset.historyCount;
      badge.textContent = category === "all" ? history.length : history.filter(item => item.category === category).length;
    });
    if (history.length) emptyText = "В этом разделе нет записей по вашему запросу.";
  }
  const sortedRows = sortRowsForGroup(rows, group);
  const container = document.querySelector(containerId);
  if (!rows.length) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(emptyText)}</div>`;
    return;
  }

  if (group === "history") {
    renderHistoryFlow(container, sortedRows, emptyText);
    return;
  }

  if (group === "dma") {
    renderDmaCards(container, sortedRows);
    return;
  }

  container.innerHTML = sortedRows.map(item => `
    <article class="table-row">
      <div class="row-title">
        <span>${escapeHtml(item.title)}</span>
        <span class="severity-${item.severity}">${escapeHtml(item.category)} · ${escapeHtml(item.severityName)}</span>
      </div>
      <div class="row-meta">${escapeHtml(item.reason)}</div>
      <div class="row-meta">${escapeHtml(item.details)}</div>
      <div class="row-meta">${escapeHtml(item.evidencePath)}</div>
    </article>
  `).join("");
}

function severityDot(severity) {
  if (severity >= 3) return { color: "#ff1717", label: "High", className: "risk-high" };
  if (severity === 2) return { color: "#ff9600", label: "Medium", className: "risk-medium" };
  if (severity === 1) return { color: "#d8c400", label: "Low", className: "risk-low" };
  return { color: "#18b85c", label: "Info", className: "risk-info" };
}

function maxSeverity(items) {
  return items.reduce((max, item) => Math.max(max, Number(item.severity || 0)), 0);
}

function uniqueItems(items) {
  const seen = new Set();
  return items.filter(item => {
    const key = [item.category, item.title, item.reason, item.details, item.evidencePath].join("|");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function nodeFromItems(id, title, icon, items, positionClass) {
  const severity = maxSeverity(items);
  const dot = severityDot(severity);
  const reasons = items.slice(0, 4).map(item => `${item.title || item.category}: ${item.reason || "signal"}`);
  return { id, title, icon, severity, dot, reasons, count: items.length, positionClass };
}

function textOf(item) {
  return `${item.category || ""} ${item.title || ""} ${item.reason || ""} ${item.details || ""} ${item.evidencePath || ""}`.toLowerCase();
}

function itemsMatching(items, patterns) {
  return items.filter(item => patterns.some(pattern => textOf(item).includes(pattern)));
}

function statusLine(items, pattern, onHit, onMiss = "") {
  return items.some(item => textOf(item).includes(pattern)) ? onHit : onMiss;
}

function bootSecurityTitle(items) {
  const lines = [
    statusLine(items, "secure boot disabled", "Secure Boot: OFF"),
    statusLine(items, "secure boot enabled", "Secure Boot: ON"),
    items.some(item => /driver signature enforcement relaxed|testsigning|nointegritychecks|disable_integrity_checks/.test(textOf(item))) ? "DSE: RELAXED" : "",
    statusLine(items, "kernel debugging enabled", "Kernel debug: ON"),
    statusLine(items, "hvci not enabled", "HVCI: OFF"),
    statusLine(items, "hvci enabled", "HVCI: ON"),
    statusLine(items, "vulnerable driver blocklist disabled", "Driver blocklist: OFF")
  ].filter(Boolean);
  return lines.slice(0, 4).join("\n") || "Boot security\nsignal";
}

function protectionTitle(items) {
  const lines = [
    statusLine(items, "defender real-time protection disabled", "Defender RT: OFF"),
    statusLine(items, "tamper protection off", "Tamper: OFF"),
    statusLine(items, "security-config scan limited", "Admin visibility: LIMITED")
  ].filter(Boolean);
  return lines.slice(0, 3).join("\n") || "Protection\nsignal";
}

function certificateTitle(items) {
  const leaked = items.find(item => textOf(item).includes("leaked") || textOf(item).includes("lapsus"));
  if (leaked) return "Leaked signing\ncertificate";
  return "Suspicious\ncertificate";
}

function runtimeTitle(items) {
  const vulnerable = items.find(item => textOf(item).includes("vulnerable kernel driver"));
  if (vulnerable) return "BYOVD driver\nruntime";
  const mapper = items.find(item => /kdmapper|mapper|manual-map|manual map/.test(textOf(item)));
  if (mapper) return "Mapper\nruntime signal";
  if (items.some(item => /injected|thread\(s\) start|unbacked/.test(textOf(item)))) return "Injected code\nin memory";
  return "Runtime / driver\nsignal";
}

function processTitle(items) {
  if (items.some(item => textOf(item).includes("masquerad"))) return "Masquerading\nprocess";
  if (items.some(item => textOf(item).includes("overlay"))) return "Overlay-like\nprocess";
  if (items.some(item => textOf(item).includes("temp"))) return "Process running\nfrom Temp";
  if (items.some(item => textOf(item).includes("injected"))) return "Injected\nprocess";
  return "Unsigned\nprocess";
}

// Each entry is a specific, named threat plate. `select` returns the matching
// suspicious findings; a plate is rendered ONLY when it returns at least one.
// Pure Info notes (severity 0) are filtered out before detectors run, so nothing
// hangs on the graph "for decoration" — a plate means a real local signal.
function astryxDetectors(suspicious) {
  const inCat = (item, cats) => cats.includes(item.category);
  const hit = (item, subs) => { const t = textOf(item); return subs.some(s => t.includes(s)); };
  const pick = (fn) => () => uniqueItems(suspicious.filter(fn));

  return [
    {
      id: "connection", icon: "./assets/svg/network-user.svg",
      title: () => "Strange connection",
      select: pick(i => inCat(i, ["NetConn", "NetArp", "NetInfo"]) ||
        hit(i, ["suspicious connection", "unexpected connection", "listening port", "external connection"]))
    },
    {
      id: "radar", icon: "./assets/svg/network-analytic.svg",
      title: () => "\"Radar\" connection\ndetect p2p",
      select: pick(i => hit(i, ["radar", "p2p", "relay", "peer-to-peer", "same-machine"]))
    },
    {
      id: "mapper", icon: "./assets/svg/data-encryption.svg",
      title: items => runtimeTitle(items),
      select: pick(i => hit(i, ["manual-map", "manual map", "manually mapped", "injected code",
        "unbacked", "thread(s) start", "ksysteminformer"]))
    },
    {
      id: "byovd", icon: "./assets/svg/layers.svg",
      title: () => "BYOVD / vulnerable\ndriver",
      select: pick(i => hit(i, ["vulnerable kernel driver", "vulnerable driver", "byovd", "kdmapper"]))
    },
    {
      id: "unsigned-driver", icon: "./assets/svg/lock-open-alt.svg",
      title: () => "Unsigned kernel\ndriver",
      select: pick(i => inCat(i, ["Driver", "DriverService", "KernelProvider"]) &&
        hit(i, ["unsigned", "untrusted", "suspicious", "signature=invalid", "invalid signature"]))
    },
    {
      id: "process", icon: "./assets/svg/cursor.svg",
      title: items => processTitle(items),
      select: pick(i => inCat(i, ["Process"]) &&
        hit(i, ["unsigned", "masquerad", "temp", "overlay", "suspicious", "injected", "outside trusted"]))
    },
    {
      id: "command", icon: "./assets/svg/keyboard.svg",
      title: () => "Suspicious command\nexecution",
      select: pick(i => hit(i, ["command-line", "autorun command", "encodedcommand", "downloadstring",
        "mshta", "wscript", "bitsadmin", "certutil", "powershell -"]))
    },
    {
      id: "cheatfile", icon: "./assets/svg/virus.svg",
      title: () => "Cheat-related\nfile",
      select: pick(i => inCat(i, ["File"]) &&
        hit(i, ["cheat", "aimbot", "esp", "overlay", "spoof", "melonity", "cheatengine", "indicator"]))
    },
    {
      id: "binary", icon: "./assets/svg/computer.svg",
      title: () => "Unsigned binary\nin user path",
      select: pick(i => inCat(i, ["File"]) &&
        hit(i, ["unsigned", "download", "desktop", "appdata", "temp"]) &&
        !hit(i, ["cheat", "aimbot", "esp", "spoof"]))
    },
    {
      id: "certificate", icon: "./assets/svg/diploma.svg",
      title: items => certificateTitle(items),
      select: pick(i => hit(i, ["certificate", "lapsus", "leaked", "revoked", "signature=invalid", "invalid signature"]))
    },
    {
      id: "pcie", icon: "./assets/svg/network.svg",
      title: () => "PCIe / DMA\ndevice",
      select: pick(i => inCat(i, ["PCIe"]) || hit(i, ["dma device", "pcie", "leech", "screamer", "fpga"]))
    },
    {
      id: "hypervisor", icon: "./assets/svg/crypto-vault.svg",
      title: () => "Hypervisor\npresence",
      select: pick(i => inCat(i, ["Hypervisor"]) || hit(i, ["hypervisor"]))
    },
    {
      id: "usb", icon: "./assets/svg/target-audience.svg",
      title: () => "USB device\nartifact",
      select: pick(i => inCat(i, ["UsbHistory"]) || hit(i, ["usb device"]))
    },
    {
      id: "history", icon: "./assets/svg/time-past.svg",
      title: () => "Execution\nhistory",
      select: pick(i => inCat(i, ["ExecHistory"]) ||
        hit(i, ["execution history", "lastrun", "prefetch", "shimcache", "amcache"]))
    },
    {
      id: "av", icon: "./assets/svg/virus.svg",
      title: items => protectionTitle(items),
      select: pick(i => inCat(i, ["SecurityConfig"]) &&
        hit(i, ["defender", "tamper", "antivirus", "real-time", "realtime", "protection"]))
    },
    {
      id: "boot", icon: "./assets/svg/lock-open-alt.svg",
      title: items => bootSecurityTitle(items),
      select: pick(i => inCat(i, ["SecurityConfig"]) &&
        hit(i, ["secure boot", "hvci", "vbs", "test-signing", "testsigning", "dse", "driver signature",
          "blocklist", "kernel debug", "integrity"]))
    }
  ];
}

function buildAstryxNodes() {
  const findings = visibleFindings();
  if (!findings.length) return [];

  // Only genuinely flagged signals (Low/Medium/High) build plates. Info-level
  // context notes never create a plate.
  const suspicious = findings.filter(item => Number(item.severity || 0) >= 1);

  const childNodes = [];
  const union = [];
  for (const det of astryxDetectors(suspicious)) {
    const items = det.select();
    if (!items.length) continue;
    childNodes.push(nodeFromItems(det.id, det.title(items), det.icon, items));
    union.push(...items);
  }

  // Steam bans plate — shown only when there are actual VAC/game bans.
  const steamProfileValues = Object.values(state.steamProfiles || {}).filter(profile => profile && !profile.loading);
  const vac = steamProfileValues.reduce((sum, profile) => sum + Number(profile.vacBans || 0), 0);
  const gameBans = steamProfileValues.reduce((sum, profile) => sum + Number(profile.gameBans || 0), 0);
  const bannedSteam = uniqueItems(suspicious.filter(i => i.category === "Steam"));
  if (vac > 0 || gameBans > 0 || bannedSteam.length) {
    const node = nodeFromItems("steam", `Steam bans\nVAC: ${vac} / Game: ${gameBans}`, "./assets/svg/svgviewer-output.svg", bannedSteam);
    if (vac > 0 || gameBans > 0) node.severity = Math.max(node.severity, 3), node.dot = severityDot(node.severity);
    childNodes.push(node);
    union.push(...bannedSteam);
  }

  if (!childNodes.length) return [];

  const graphItems = uniqueItems(union);
  const high = graphItems.filter(item => item.severity >= 3).length;
  const medium = graphItems.filter(item => item.severity === 2).length;
  const low = graphItems.filter(item => item.severity === 1).length;
  const rootReasons = graphItems
    .slice()
    .sort((a, b) => Number(b.severity || 0) - Number(a.severity || 0))
    .slice(0, 4);

  const root = nodeFromItems(
    "root",
    `Astryx graph\nSignals: ${graphItems.length}\nHigh: ${high} / Med: ${medium}\nLow: ${low}`,
    "./assets/svg/computer.svg",
    rootReasons.length ? rootReasons : graphItems
  );

  // Most severe plates first.
  childNodes.sort((a, b) => Number(b.severity || 0) - Number(a.severity || 0));
  return [root, ...childNodes];
}

function renderRiskDots(node) {
  return `<span class="risk-dot ${node.dot.className}" tabindex="0"></span>`;
}

function renderAstryxView() {
  const root = document.querySelector("#astryxRootNode");
  const graph = document.querySelector("#astryxGraph");
  const lines = document.querySelector("#astryxLines");
  if (!root || !graph || !lines) return;

  const nodes = buildAstryxNodes();
  if (!nodes.length) {
    // No scan yet: only the message, no leftover root plate.
    root.innerHTML = "";
    root.removeAttribute("style");
    root.style.display = "none";
    graph.style.width = "100%";
    graph.style.height = "100%";
    graph.innerHTML = `
      <div class="astryx-empty">
        <img src="./assets/svg/layers.svg" alt="">
        <strong>${escapeHtml(t("astryx.empty.title"))}</strong>
        <span>${escapeHtml(t("astryx.empty.desc"))}</span>
      </div>
    `;
    lines.innerHTML = "";
    renderAstryxStatus();
    return;
  }
  root.style.display = "";

  const rootNode = nodes.find(node => node.id === "root");
  const childNodes = nodes.filter(node => node.id !== "root");

  // Severity tier (1=low, 2=medium, 3=high). Left -> right the graph reads
  // yellow -> orange -> red, with direct plate-to-plate connectors.
  const TIER_COLOR = { 1: "#d8c400", 2: "#ff9600", 3: "#ff1717" };
  const tierOf = (sev) => (sev >= 3 ? 3 : sev === 2 ? 2 : 1);

  // One column per present tier, ordered low -> high (the stronger, the righter).
  const columns = [1, 2, 3]
    .map(tier => ({
      tier,
      color: TIER_COLOR[tier],
      cards: childNodes
        .filter(node => tierOf(node.severity) === tier)
        .sort((a, b) => (b.count || 0) - (a.count || 0))
    }))
    .filter(col => col.cards.length);

  // Geometry (px). Cards are laid out by severity column; lines are straight
  // right-center -> left-center connectors between actual plates.
  const PAD = 30;
  const ROOT_W = 330, ROOT_H = 126;
  const CARD_W = 280, CARD_H = 108, ROW_GAP = 28;
  const ROW_H = CARD_H + ROW_GAP;
  const COL_GAP = 96;
  const rootX = PAD;
  const cardsTop = PAD + 34;
  const firstColX = rootX + ROOT_W + 110;
  const colX = (ci) => firstColX + ci * (CARD_W + COL_GAP);
  const cardCenterY = (i) => cardsTop + i * ROW_H + CARD_H / 2;

  const maxRows = columns.reduce((m, col) => Math.max(m, col.cards.length), 0);
  const contentBottom = cardsTop + (maxRows - 1) * ROW_H + CARD_H;
  const firstColumnRows = columns[0]?.cards.length || 1;
  const rootRowIndex = Math.max(0, Math.floor((firstColumnRows - 1) / 2));
  const rootCenterY = cardCenterY(rootRowIndex);
  const rootTop = Math.max(PAD, rootCenterY - ROOT_H / 2);

  const canvasW = colX(columns.length - 1) + CARD_W + PAD;
  const canvasH = Math.max(contentBottom, rootTop + ROOT_H) + PAD;

  // Root (graph info, far left).
  root.style.left = `${rootX}px`;
  root.style.top = `${rootTop}px`;
  root.innerHTML = `
    <img src="${rootNode.icon}" alt="">
    <strong>${escapeHtml(rootNode.title).replaceAll("\n", "<br>")}</strong>
    ${renderRiskDots(rootNode)}
  `;

  const placedColumns = columns.map((col, ci) => ({
    ...col,
    x: colX(ci),
    cards: col.cards.map((node, i) => ({
      node,
      x: colX(ci),
      y: cardsTop + i * ROW_H,
      centerY: cardCenterY(i)
    }))
  }));

  // Plates grouped into severity columns, side by side.
  graph.style.width = `${canvasW}px`;
  graph.style.height = `${canvasH}px`;
  const cardsHtml = [];
  placedColumns.forEach((col, ci) => {
    col.cards.forEach(({ node, x, y }, row) => {
      cardsHtml.push(`
        <article class="astryx-node" data-risk="${node.severity}" data-col="${ci}" data-row="${row}" style="left:${x}px;top:${y}px;">
          <img src="${node.icon}" alt="">
          <strong>${escapeHtml(node.title).replaceAll("\n", "<br>")}</strong>
          ${renderRiskDots(node)}
          <div class="node-tip ${ci === columns.length - 1 ? "tip-left" : "tip-right"}">
            <b>${escapeHtml(node.dot.label)} risk · ${node.count} signal${node.count === 1 ? "" : "s"}</b>
            ${node.reasons.map(reason => `<span>${escapeHtml(reason)}</span>`).join("")}
          </div>
        </article>`);
    });
  });
  graph.innerHTML = cardsHtml.join("");

  lines.style.width = `${canvasW}px`;
  lines.style.height = `${canvasH}px`;
  lines.setAttribute("viewBox", `0 0 ${canvasW} ${canvasH}`);
  lines.setAttribute("width", canvasW);
  lines.setAttribute("height", canvasH);

  const paths = [];
  const line = (from, to, color) =>
    `<path style="stroke:${color}" d="M${from.x} ${from.y} L${to.x} ${to.y}" />`;
  const board = lines.parentElement;
  const boardRect = board.getBoundingClientRect();
  const point = (el, side) => {
    const rect = el.getBoundingClientRect();
    return {
      x: (side === "right" ? rect.right : rect.left) - boardRect.left + board.scrollLeft,
      y: rect.top + rect.height / 2 - boardRect.top + board.scrollTop
    };
  };
  const cardEl = (col, row) => graph.querySelector(`.astryx-node[data-col="${col}"][data-row="${row}"]`);

  const firstColumn = placedColumns[0];
  if (firstColumn?.cards.length) {
    const firstRow = Math.min(rootRowIndex, firstColumn.cards.length - 1);
    const firstCard = cardEl(0, firstRow);
    if (firstCard) paths.push(line(point(root, "right"), point(firstCard, "left"), firstColumn.color));
  }

  placedColumns.slice(1).forEach((col, ci) => {
    const previous = placedColumns[ci];
    const pairCount = Math.min(previous.cards.length, col.cards.length);
    for (let i = 0; i < pairCount; i += 1) {
      const from = cardEl(ci, i);
      const to = cardEl(ci + 1, i);
      if (from && to) paths.push(line(point(from, "right"), point(to, "left"), col.color));
    }
  });

  lines.innerHTML = paths.join("");

  renderAstryxStatus();
}

function renderAstryxStatus() {
  const fill = document.querySelector("#astryxProgressFill");
  const text = document.querySelector("#astryxProgressText");
  const status = document.querySelector("#astryxStatus");
  if (!fill || !text || !status) return;
  const incomplete = Object.values(state.scanReports).some(result => !ScanReport.isComplete(result));
  const percent = state.scanBusy ? Math.max(8, state.progressValue) : (incomplete ? 0 : (visibleFindings().length ? 100 : 0));
  fill.style.width = `${percent}%`;
  text.textContent = `${Math.round(percent)}%`;
  status.textContent = state.scanBusy
    ? t("astryx.status.working")
    : (incomplete ? ScanReport.label({ status: 3 }, state.lang)
      : (visibleFindings().length ? t("astryx.status.ready") : t("astryx.status.waiting")));
}

function renderScanReports() {
  const panel = document.querySelector("#scanReport");
  const entries = Object.entries(state.scanReports);
  panel.classList.toggle("hidden", !entries.length);
  if (!entries.length) return;
  const incomplete = entries.filter(([, result]) => !ScanReport.isComplete(result)).length;
  panel.classList.toggle("incomplete", incomplete > 0);
  document.querySelector("#scanReportSummary").textContent = state.lang === "en"
    ? `Scan stages: ${entries.length}; incomplete: ${incomplete}`
    : `Этапов проверки: ${entries.length}; неполных: ${incomplete}`;
  document.querySelector("#scanReportModules").innerHTML = entries.map(([mode, result]) => {
    const count = result.report?.findingsTotal ?? result.findings?.length ?? 0;
    const title = `${ScanReport.modeLabel(mode, state.lang)}: ${ScanReport.label(result, state.lang)}`;
    const countText = state.lang === "en" ? `Findings: ${count}` : `Находок: ${count}`;
    const issues = ScanReport.issues(result, state.lang);
    const notes = issues.length ? `<ul>${issues.map(note => `<li>${escapeHtml(note)}</li>`).join("")}</ul>` : "";
    return `<div class="scan-report-row"><div><strong>${escapeHtml(title)}</strong><span>${escapeHtml(countText)}</span></div>${notes}</div>`;
  }).join("");
}

function renderDashboard() {
  const high = visibleFindings().filter(item => item.severity >= 3).slice(0, 6);
  document.querySelector("#highCount").textContent = high.length;
  document.querySelector("#highList").innerHTML = high.length
    ? high.map(item => `<div class="compact-item">${escapeHtml(item.title)}<br>${escapeHtml(item.reason)}</div>`).join("")
    : `<div class="compact-item">No high priority findings.</div>`;
}

function updateStats(report) {
  document.querySelector("#statFindings").textContent = visibleFindings().length;
  document.querySelector("#statProcesses").textContent = report?.processesChecked ?? 0;
  document.querySelector("#statDrivers").textContent = report?.driversChecked ?? 0;
  document.querySelector("#statElapsed").textContent = `${report?.elapsedMs ?? 0} ms`;
}

function renderAllData() {
  renderFindings();
  renderSteam();
  renderRows("#historyTable", "history", "History checks load automatically when the profile starts or this tab opens.");
  renderRows("#dmaTable", "dma", "DMA/network checks load automatically when the profile starts or this tab opens.");
  renderRows("#seccfgTable", "seccfg", "Security config loads automatically when the profile starts or this tab opens.");
  renderDashboard();
  renderAstryxView();
}

function mergeFindings(mode, incoming) {
  const groups = modeGroups[mode] || ["findings"];
  if (mode === "full") {
    state.lastFindings = incoming;
    return;
  }

  state.lastFindings = state.lastFindings.filter(item => !groups.includes(categoryGroup(item.category)));
  state.lastFindings = state.lastFindings.concat(incoming);
}

function receive(message) {
  switch (message.type) {
    case "profiles":
      state.profiles = Array.isArray(message.profiles) && message.profiles.length ? message.profiles : fallbackProfiles;
      renderGamePicker();
      break;
    case "adminState":
      state.isAdmin = message.isAdmin;
      applyAdminText();
      break;
    case "scanStarted":
      state.resultChunks[message.mode] = ScanReport.beginChunks(message.profile, message.mode);
      setStatus(`${ScanReport.modeLabel(message.mode, state.lang)}…`);
      break;
    case "scanChunk":
      ScanReport.appendChunk(state.resultChunks[message.mode], message);
      break;
    case "scanBusy":
      setStatus("Native scanner is busy. Try again after current scan.");
      finishScanStep(false);
      break;
    case "scanError":
      delete state.resultChunks[state.currentMode || "full"];
      state.scanReports[state.currentMode || "full"] = message;
      renderScanReports();
      setStatus(message.message || "Scan failed.");
      finishScanStep(false);
      renderAstryxStatus();
      break;
    case "scanResult": {
      const mode = message.mode || state.currentMode || "full";
      if (message.chunked) message = ScanReport.finishChunks(state.resultChunks[mode], message);
      delete state.resultChunks[mode];
      state.scanReports[mode] = message;
      renderScanReports();
      state.completedModes.add(mode);
      mergeFindings(mode, message.findings || []);
      if (groupHasData(mode)) state.autoRetryCount[mode] = 0;
      updateStats(message.report);
      renderAllData();
      const complete = ScanReport.isComplete(message);
      const count = message.findings?.length || 0;
      setStatus(`${ScanReport.modeLabel(mode, state.lang)} · ${ScanReport.label(message, state.lang)} · ${state.lang === "en" ? "Findings" : "Находок"}: ${count}`);
      finishScanStep(complete);
      if (!complete && !state.scanBusy) setProgress(0, ScanReport.label(message, state.lang));
      renderAstryxStatus();
      refreshActivePageIfEmpty();
      break;
    }
    case "steamProfile":
      if (message.steamId) {
        state.steamProfiles[message.steamId] = message;
        renderSteam();
        renderDashboard();
      }
      break;
  }
}

window.ScumChecker = { receive };

document.querySelector("#changeGameButton").addEventListener("click", () => {
  appShell.classList.add("hidden");
  picker.classList.remove("hidden");
});

document.querySelectorAll(".nav-button").forEach(button => {
  button.addEventListener("click", () => showPage(button.dataset.page));
});

document.querySelectorAll(".scan-action").forEach(button => {
  button.addEventListener("click", () => enqueueScan(button.dataset.mode || "full", button.textContent.trim()));
});

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(item => item.classList.remove("active"));
    tab.classList.add("active");
    state.activeFilter = tab.dataset.filter;
    state.findingsPageIndex = 0;
    renderFindings();
  });
});

document.querySelector("#findingsFilterButton")?.addEventListener("click", () => {
  state.findingsFiltersOpen = !state.findingsFiltersOpen;
  document.querySelector("#findingsFilterPanel")?.classList.toggle("open", state.findingsFiltersOpen);
});

document.querySelector("#findingsFilterClose")?.addEventListener("click", () => {
  state.findingsFiltersOpen = false;
  document.querySelector("#findingsFilterPanel")?.classList.remove("open");
});

document.querySelectorAll(".tool-button").forEach(button => {
  button.addEventListener("click", () => bridge({ type: "open", target: button.dataset.open }));
});

document.querySelectorAll(".creator a").forEach(link => {
  link.addEventListener("click", event => {
    event.preventDefault();
    bridge({ type: "open", target: link.dataset.open });
  });
});

document.querySelectorAll(".view-button").forEach(button => {
  button.addEventListener("click", () => {
    state.steamView = button.dataset.steamView || "cards";
    document.querySelectorAll(".view-button").forEach(item => item.classList.toggle("active", item === button));
    renderSteam();
  });
});

document.querySelector("#findingsSearch").addEventListener("input", event => {
  state.searches.findings = event.target.value;
  state.findingsPageIndex = 0;
  renderFindings();
});

document.querySelector("#steamSearch").addEventListener("input", event => {
  state.searches.steam = event.target.value;
  renderSteam();
});

document.querySelectorAll(".history-tab").forEach(button => {
  button.addEventListener("click", () => {
    state.historyCategory = button.dataset.historyCategory;
    document.querySelectorAll(".history-tab").forEach(tab => {
      const active = tab === button;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-pressed", String(active));
    });
    renderRows("#historyTable", "history", "Записи истории пока не загружены.");
  });
});

document.querySelector("#historySearch").addEventListener("input", event => {
  state.searches.history = event.target.value;
  renderRows("#historyTable", "history", "History checks load automatically when the profile starts or this tab opens.");
});

document.querySelector("#dmaSearch").addEventListener("input", event => {
  state.searches.dma = event.target.value;
  renderRows("#dmaTable", "dma", "DMA/network checks load automatically when the profile starts or this tab opens.");
});

document.querySelector("#seccfgSearch").addEventListener("input", event => {
  state.searches.seccfg = event.target.value;
  renderRows("#seccfgTable", "seccfg", "Security config loads automatically when the profile starts or this tab opens.");
});

document.querySelector("#toolsSearch").addEventListener("input", event => {
  state.searches.tools = event.target.value.toLowerCase();
  document.querySelectorAll("#page-tools .tool-button").forEach(button => {
    button.classList.toggle("hidden", !button.textContent.toLowerCase().includes(state.searches.tools));
  });
  document.querySelector("#toolsEmpty").classList.toggle("hidden", !!document.querySelector("#page-tools .tool-button:not(.hidden)"));
});

document.querySelector("#hotkeysSearch").addEventListener("input", event => {
  state.searches.hotkeys = event.target.value.toLowerCase();
  document.querySelectorAll("#page-hotkeys .hotkey-button").forEach(button => {
    button.classList.toggle("hidden", !button.textContent.toLowerCase().includes(state.searches.hotkeys));
  });
  document.querySelectorAll(".shortcut-group").forEach(group => {
    group.classList.toggle("hidden", !group.querySelector(".hotkey-button:not(.hidden)"));
  });
  document.querySelector("#hotkeysEmpty").classList.toggle("hidden", !!document.querySelector("#page-hotkeys .hotkey-button:not(.hidden)"));
});

// ---- i18n (RU / EN) ----------------------------------------------------------
const I18N = {
  ru: {
    "nav.profiles": "Профили",
    "nav.astryx": "AstryxView",
    "nav.dashboard": "Дашборд",
    "nav.findings": "Находки",
    "nav.steam": "Steam аккаунты",
    "nav.history": "История",
    "nav.dma": "DMA и сеть",
    "nav.seccfg": "Конфиг безопасности",
    "nav.tools": "Инструменты",
    "nav.hotkeys": "Горячие клавиши",
    "astryx.subtitle": "Пытается распознать сигнатуры поведения пользователя",
    "astryx.analyze": "Анализ",
    "astryx.empty.title": "Графа ещё нет",
    "astryx.empty.desc": "Запустите «Анализ» или полный скан. AstryxView показывает только реальные локальные сигналы нативного сканера.",
    "astryx.status.working": "идёт работа.... Подождите!",
    "astryx.status.ready": "граф анализа готов",
    "astryx.status.waiting": "ожидание.... Запустите скан!",
    "admin.yes": "Админ: да",
    "admin.no": "Админ: нет, проверки драйверов/истории ограничены",
    "admin.checking": "Админ: проверка...",
    "top.profile": "Профиль {name}",
    "top.title": "Панель проверки {name}"
  },
  en: {
    "nav.profiles": "Profiles",
    "nav.astryx": "AstryxView",
    "nav.dashboard": "Dashboard",
    "nav.findings": "Findings",
    "nav.steam": "Steam accounts",
    "nav.history": "History",
    "nav.dma": "DMA & Network",
    "nav.seccfg": "Security config",
    "nav.tools": "Tools",
    "nav.hotkeys": "Hotkeys",
    "astryx.subtitle": "Tries to understand user behavior signatures",
    "astryx.analyze": "Analyze",
    "astryx.empty.title": "No real scan graph yet",
    "astryx.empty.desc": "Run Analyze or Full scan. AstryxView will only show real local signals from the native scanner.",
    "astryx.status.working": "working.... Please wait!",
    "astryx.status.ready": "analysis graph ready",
    "astryx.status.waiting": "waiting.... Please run scan!",
    "admin.yes": "Admin: yes",
    "admin.no": "Admin: no, driver/history checks may be limited",
    "admin.checking": "Admin: checking...",
    "top.profile": "{name} profile",
    "top.title": "{name} check dashboard"
  }
};

function t(key, vars) {
  const lang = state.lang === "en" ? "en" : "ru";
  let str = (I18N[lang] && I18N[lang][key]) || (I18N.ru[key]) || key;
  if (vars) for (const k in vars) str = str.replaceAll(`{${k}}`, vars[k]);
  return str;
}

function applyAdminText() {
  const el = document.querySelector("#adminState");
  if (!el) return;
  el.textContent = state.isAdmin === undefined
    ? t("admin.checking")
    : (state.isAdmin ? t("admin.yes") : t("admin.no"));
}

function applyProfileTitles() {
  const name = state.activeProfileName;
  if (!name) return;
  profileStatus.textContent = t("top.profile", { name });
  screenTitle.textContent = t("top.title", { name });
}

function applyLanguage(lang) {
  state.lang = lang === "en" ? "en" : "ru";
  try { localStorage.setItem("scum.lang", state.lang); } catch (e) { /* ignore */ }
  document.documentElement.lang = state.lang;

  document.querySelectorAll("[data-i18n]").forEach(el => {
    el.textContent = t(el.getAttribute("data-i18n"));
  });
  document.querySelectorAll("#langSwitch .lang-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.lang === state.lang);
  });

  applyAdminText();
  applyProfileTitles();
  renderScanReports();
  renderAstryxView();
}

document.querySelectorAll("#langSwitch .lang-btn").forEach(btn => {
  btn.addEventListener("click", () => applyLanguage(btn.dataset.lang));
});

state.profiles = fallbackProfiles;
let savedLang = "ru";
try { savedLang = localStorage.getItem("scum.lang") || "ru"; } catch (e) { /* ignore */ }
applyLanguage(savedLang);
initPickerShader();
initPickerShader(appShaderCanvas);
renderGamePicker();
setProgress(0, "Idle");
bridge({ type: "ready" });
