const patrol = {
  files: [],
  events: [],
  demoEvents: [],
  selected: null,
  demo: false,
  paused: false,
  speed: 1,
  filter: "all",
  lastFrame: 0,
  patrolIndex: 0,
  patrolClock: 0,
  source: null,
  demoTimer: null,
  demoCycle: 0,
  layout: [],
};

const canvas = document.querySelector("#patrol-canvas");
const ctx = canvas.getContext("2d", { alpha: false });
const hosts = ["server-a", "server-b"];
const severityRank = { safe: 0, suspicious: 1, compromised: 2 };
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

function worldHeight() {
  const rows = Math.ceil(Math.max(1, ...hosts.map((host) => patrol.files.filter((file) => file.host_id === host).length)) / 4);
  return Math.max(560, 260 + rows * 77);
}

function cleanText(value, max = 180) {
  return String(value ?? "")
    .replace(/[\u0000-\u001f\u007f<>]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

function cleanPath(value) {
  const path = cleanText(value, 2048).replace(/\\/g, "/");
  return path.split("/").filter((part) => part && part !== "." && part !== "..").join("/") || "root";
}

function safeSeverity(value) {
  return Object.prototype.hasOwnProperty.call(severityRank, value) ? value : "safe";
}

function latestEvents() {
  return [...patrol.events, ...patrol.demoEvents]
    .sort((left, right) => Date.parse(right.ts || 0) - Date.parse(left.ts || 0))
    .slice(0, 100);
}

function activeActors() {
  const cutoff = Date.now() - 60000;
  const latest = new Map();
  for (const event of latestEvents()) {
    if (event.actor === "police" || Date.parse(event.ts || 0) < cutoff) continue;
    if (patrol.filter !== "all" && severityRank[safeSeverity(event.severity)] < severityRank[patrol.filter]) continue;
    const key = `${event.host_id}:${event.actor}`;
    if (!latest.has(key)) latest.set(key, event);
  }
  return [...latest.values()];
}

function filteredEvents() {
  return latestEvents().filter((event) => {
    if (patrol.filter === "all") return true;
    return (severityRank[event.severity] || 0) >= severityRank[patrol.filter];
  });
}

function renderCounters() {
  const latest = latestEvents();
  const risky = new Map();
  for (const event of latest) {
    if (event.actor === "police" || event.severity === "safe") continue;
    const key = `${event.host_id}:${cleanPath(event.path)}`;
    const severity = safeSeverity(event.severity);
    if (!risky.has(key) || severityRank[severity] > severityRank[risky.get(key)]) {
      risky.set(key, severity);
    }
  }
  const compromised = [...risky.values()].filter((value) => value === "compromised").length;
  const suspicious = [...risky.values()].filter((value) => value === "suspicious").length;
  const unsafeFiles = patrol.files.filter((file) => risky.has(`${file.host_id}:${cleanPath(file.path)}`)).length;
  const safe = Math.max(0, patrol.files.length - unsafeFiles);
  document.querySelector("#patrol-safe-count").textContent = String(safe);
  document.querySelector("#patrol-suspicious-count").textContent = String(suspicious);
  document.querySelector("#patrol-compromised-count").textContent = String(compromised);
  document.querySelector("#patrol-actor-count").textContent = String(activeActors().length);
  document.querySelector("#patrol-event-count").textContent = String(latest.length);
}

function detailText(event) {
  const time = event.ts ? new Date(event.ts).toLocaleString("id-ID") : "Waktu tidak tersedia";
  const ip = event.actor === "police" ? "Agent polisi" : cleanText(event.actor, 96);
  const oldHash = /^[a-f0-9]{64}$/.test(event.hash_old || "") ? event.hash_old : "belum tersedia";
  const newHash = /^[a-f0-9]{64}$/.test(event.hash_new || "") ? event.hash_new : "belum tersedia";
  return `${time} · ${cleanText(event.action)} · ${cleanPath(event.path)} · ${ip} · hash lama ${oldHash} · hash baru ${newHash}`;
}

function showDetail(value) {
  patrol.selected = value;
  document.querySelector("#patrol-detail").textContent = detailText(value);
}

function fileCategory(path) {
  const name = cleanPath(path).split("/").at(-1).toLowerCase();
  if (name === ".env" || name.includes("secret") || name.startsWith("id_rsa")) return "safe";
  if (name.endsWith(".key") || name.endsWith(".pem") || name.endsWith(".p12") || name.endsWith(".pfx")) return "key";
  if (name.endsWith(".db") || name.endsWith(".sqlite") || name.endsWith(".sqlite3")) return "gold";
  if (name === "config" || name.startsWith("config.") || [".json", ".yml", ".yaml", ".ini", ".conf", ".toml", ".config"].some((suffix) => name.endsWith(suffix))) return "document";
  return "box";
}

function severityForFile(file) {
  const event = latestEvents().find((item) => item.host_id === file.host_id && cleanPath(item.path) === cleanPath(file.path) && item.actor !== "police");
  return event?.severity || "safe";
}

function renderFiles() {
  const node = document.querySelector("#patrol-files");
  node.replaceChildren();
  if (!patrol.files.length) {
    const empty = document.createElement("p");
    empty.className = "patrol-empty";
    empty.textContent = "Agent belum mengirim snapshot file.";
    node.append(empty);
    return;
  }
  for (const file of patrol.files.slice(0, 80)) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `patrol-file-row severity-${safeSeverity(severityForFile(file))}`;
    const name = document.createElement("span");
    name.textContent = `${file.host_id} · ${cleanPath(file.path)}`;
    const hash = document.createElement("small");
    hash.textContent = /^[a-f0-9]{64}$/.test(file.sha256 || "") ? file.sha256 : "Hash belum tersedia";
    button.append(name, hash);
    button.addEventListener("click", () => showDetail({
      ts: file.checked_at, actor: "police", host_id: file.host_id, action: "read",
      path: file.path, hash_new: file.sha256, severity: severityForFile(file),
    }));
    node.append(button);
  }
}

function originBadge(event) {
  if (event.scenario_run) return `SIM · ${cleanText(String(event.scenario_run).slice(0, 8), 8)}`;
  if (event.source === "lab-fim-agent" || event.source === "snapshot") return "FIM";
  if (event.source === "demo") return "VISUAL";
  return "LIVE";
}

function renderActors() {
  const node = document.querySelector("#patrol-actors");
  node.replaceChildren();
  const actors = activeActors();
  if (!actors.length) {
    const empty = document.createElement("p");
    empty.className = "patrol-empty";
    empty.textContent = "Belum ada akses tercatat.";
    node.append(empty);
    return;
  }
  for (const event of actors.slice(0, 8)) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `actor-row severity-${safeSeverity(event.severity)}`;
    const head = document.createElement("strong");
    head.textContent = cleanText(event.actor, 96);
    const description = document.createElement("span");
    description.textContent = `${safeSeverity(event.severity)} · ${cleanPath(event.path)}`;
    const action = document.createElement("small");
    action.textContent = `${originBadge(event)} · ${cleanText(event.host_id, 32)} · ${cleanText(event.action, 20)} · ${cleanText(event.status || "observed", 32)}`;
    button.append(head, description, action);
    button.addEventListener("click", () => showDetail(event));
    node.append(button);
  }
}

function renderEvents() {
  const node = document.querySelector("#patrol-events");
  node.replaceChildren();
  const events = filteredEvents();
  if (!events.length) {
    const empty = document.createElement("li");
    empty.className = "patrol-empty";
    empty.textContent = patrol.filter === "all" ? "Menunggu event backend." : "Tidak ada event pada severity ini.";
    node.append(empty);
    return;
  }
  for (const event of events.slice(0, 24)) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = `patrol-event-row severity-${safeSeverity(event.severity)}`;
    const title = document.createElement("strong");
    title.textContent = `${cleanText(event.type, 24)} · ${cleanText(event.action, 20)}`;
    const path = document.createElement("span");
    path.textContent = cleanPath(event.path);
    const actor = document.createElement("small");
    actor.textContent = `${originBadge(event)} · ${cleanText(event.host_id, 32)} · ${cleanText(event.actor, 96)} · ${safeSeverity(event.severity)}`;
    button.append(title, path, actor);
    button.addEventListener("click", () => showDetail(event));
    item.append(button);
    node.append(item);
  }
}

function refreshPatrol() {
  renderCounters();
  renderFiles();
  renderActors();
  renderEvents();
  document.querySelector("#patrol-source-status").textContent = patrol.demo
    ? `Kanvas demo VISUAL · ${patrol.files.length} file dari snapshot agent`
    : `${patrol.files.length} file dari snapshot agent · event live`;
  layoutFiles();
}

// ---------------------------------------------------------------------------
// Skenario lab: kontrol backend state machine (bukan dekorasi kanvas)
// ---------------------------------------------------------------------------

const scenarioUI = {
  runId: null,
  state: null,
  pauseRequested: false,
  pollTimer: null,
  scenarios: {},
  activeRunIds: [],
};

function terminalScenarioState(state) {
  return state === "COMPLETE" || state === "FAILED" || state === "CANCELLED";
}

function describeRun(run) {
  let message = `${run.scenario || "skenario"} · ${run.state}`;
  if (Array.isArray(run.rejection_reason) && run.rejection_reason.length) {
    message += ` · ditolak: ${run.rejection_reason.join(", ")}`;
  }
  return message;
}

function scenarioControlsFor(state) {
  const activeRun = Boolean(scenarioUI.runId) && !terminalScenarioState(state || "");
  return {
    start: !activeRun,
    pause: activeRun && !scenarioUI.pauseRequested,
    resume: activeRun && scenarioUI.pauseRequested,
    cancel: activeRun,
  };
}

function paintScenario(run) {
  const stateNode = document.querySelector("#scenario-state");
  const messageNode = document.querySelector("#scenario-message");
  const start = document.querySelector("#scenario-start");
  const pauseButton = document.querySelector("#scenario-pause");
  const resumeButton = document.querySelector("#scenario-resume");
  const cancelButton = document.querySelector("#scenario-cancel");
  if (run) {
    scenarioUI.runId = run.run_id;
    scenarioUI.state = run.state;
    scenarioUI.pauseRequested = Number(run.pause_requested) > 0;
    const stateClass = terminalScenarioState(run.state)
      ? (run.state === "COMPLETE" ? "terminal-pass" : "terminal-fail")
      : "active";
    stateNode.textContent = `${run.scenario} · ${run.state}`;
    stateNode.className = `scenario-state ${stateClass}`;
    messageNode.textContent = describeRun(run);
  }
  const controls = scenarioControlsFor(scenarioUI.state || "");
  start.hidden = !controls.start;
  pauseButton.hidden = !controls.pause;
  resumeButton.hidden = !controls.resume;
  cancelButton.hidden = !controls.cancel;
}

async function adoptActiveRun() {
  const response = await fetch("/api/demo/scenarios", { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = await response.json();
  scenarioUI.scenarios = data.scenarios || {};
  const activeIds = Array.isArray(data.active_run_ids) ? data.active_run_ids : [];
  const activeRuns = (data.runs || []).filter((run) => activeIds.includes(run.run_id));
  if (activeRuns.length) {
    paintScenario(activeRuns[0]);
    pollScenarioRun(activeRuns[0].run_id);
    return;
  }
  paintScenario({ run_id: null, scenario: "", state: "TIDAK_AKTIF", pause_requested: 0, rejection_reason: [] });
}

function pollScenarioRun(runId) {
  window.clearInterval(scenarioUI.pollTimer);
  scenarioUI.pollTimer = window.setInterval(async () => {
    try {
      const response = await fetch(`/api/demo/scenarios/${encodeURIComponent(runId)}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const run = await response.json();
      paintScenario(run);
      if (terminalScenarioState(run.state)) window.clearInterval(scenarioUI.pollTimer);
    } catch (error) {
      document.querySelector("#scenario-message").textContent = `Polling run gagal: ${error.message}`;
    }
  }, 800);
}

async function startScenario(event) {
  const messageNode = document.querySelector("#scenario-message");
  const scenarioName = document.querySelector("#scenario-select").value;
  const target = document.querySelector("#scenario-target").value;
  messageNode.textContent = "Memulai skenario…";
  try {
    const response = await fetch("/api/demo/scenarios/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenarioName, target }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      messageNode.textContent =
        `Start ditolak (${response.status}): ${cleanText(String(data.error || "unknown"), 96)}` +
        (data.detail ? ` · ${cleanText(String(data.detail), 180)}` : "");
      await adoptActiveRun();
      return;
    }
    messageNode.textContent = "Skenario dibuat; mengikuti state backend…";
    paintScenario(data.run);
    pollScenarioRun(data.run.run_id);
  } catch (error) {
    messageNode.textContent = `Gagal memulai: ${error.message}`;
  }
}

async function scenarioControl(action) {
  const messageNode = document.querySelector("#scenario-message");
  if (!scenarioUI.runId) return;
  try {
    const response = await fetch(
      `/api/demo/scenarios/${encodeURIComponent(scenarioUI.runId)}/${action}`,
      { method: "POST" },
    );
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      messageNode.textContent = `${action} ditolak (${response.status}): ${cleanText(String(data.error || "unknown"), 96)}`;
      return;
    }
    const data = await response.json();
    paintScenario(data.run);
    if (!terminalScenarioState(data.run.state)) pollScenarioRun(data.run.run_id);
  } catch (error) {
    messageNode.textContent = `${action} gagal: ${error.message}`;
  }
}

async function refreshBackendChips() {
  const mapping = { "server-a": "#backend-chip-server-a", "server-b": "#backend-chip-server-b" };
  try {
    const response = await fetch("/v1/dashboard", { cache: "no-store" });
    if (!response.ok) return;
    const data = await response.json();
    const backends = data.backends || data.load_balancer || {};
    for (const [host, selector] of Object.entries(mapping)) {
      const chip = document.querySelector(selector);
      const state = cleanText(String((backends[host] || {}).state || backends[host] || "UNKNOWN"), 12).toUpperCase();
      chip.textContent = `${host} · ${state}`;
      chip.classList.toggle("up", state.startsWith("UP"));
      chip.classList.toggle("down", /DOWN|MAINT|DRAIN/.test(state));
    }
  } catch (error) {
    for (const selector of Object.values(mapping)) {
      document.querySelector(selector).textContent = "backend terputus";
    }
  }
}

async function loadState() {
  try {
    const response = await fetch("/api/patrol/state", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const state = await response.json();
    patrol.files = Array.isArray(state.files) ? state.files : [];
    patrol.events = Array.isArray(state.events) ? state.events : [];
    refreshPatrol();
    const lastId = patrol.events.at(-1)?.id || 0;
    connectEvents(lastId);
    await refreshBackendChips();
    await adoptActiveRun();
  } catch (error) {
    document.querySelector("#patrol-source-status").textContent = "Collector terputus · snapshot belum tersedia";
  }
}

function connectEvents(after) {
  if (patrol.source) return;
  patrol.source = new EventSource(`/api/patrol/stream?after=${encodeURIComponent(after)}`);
  patrol.source.addEventListener("patrol", (message) => {
    try {
      const event = JSON.parse(message.data);
      patrol.events.unshift(event);
      patrol.events = patrol.events.slice(0, 100);
      refreshPatrol();
    } catch (error) {
      document.querySelector("#patrol-source-status").textContent = "Event stream menerima payload rusak";
    }
  });
  patrol.source.onerror = () => {
    document.querySelector("#patrol-source-status").textContent = "Menyambungkan ulang event stream…";
  };
}

function makeDemoEvent(actor, host, action, severity, path, offset) {
  const ts = new Date(Date.now() + offset).toISOString();
  return {
    id: `demo-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    ts,
    type: severity === "safe" ? "access" : "alert",
    actor,
    action,
    host_id: host,
    path,
    severity,
    hash_old: severity === "compromised" ? "a".repeat(64) : null,
    hash_new: severity === "compromised" ? "b".repeat(64) : null,
    status: action === "denied" ? "blocked" : "demo",
    source: "demo",
  };
}

function addDemoPair() {
  const fileA = patrol.files.find((file) => file.host_id === "server-a")?.path || "index.txt";
  const fileB = patrol.files.find((file) => file.host_id === "server-b")?.path || "index.txt";
  const cycle = patrol.demoCycle++;
  const actions = [["read", "modify"], ["download", "read"], ["denied", "delete"], ["read", "download"]][cycle % 4];
  patrol.demoEvents.unshift(
    makeDemoEvent("198.51.100.23", "server-a", actions[0], "suspicious", fileA, 0),
    makeDemoEvent("203.0.113.42", "server-b", actions[1], actions[1] === "denied" ? "suspicious" : "compromised", fileB, 1),
  );
  patrol.demoEvents = patrol.demoEvents.slice(0, 30);
  refreshPatrol();
}

function toggleDemo() {
  patrol.demo = !patrol.demo;
  const button = document.querySelector("#patrol-demo-toggle");
  button.setAttribute("aria-pressed", String(patrol.demo));
  button.textContent = patrol.demo ? "Hentikan kanvas demo" : "Kanvas demo (VISUAL)";
  if (patrol.demo) {
    addDemoPair();
    patrol.demoTimer = window.setInterval(addDemoPair, 4200);
  } else {
    window.clearInterval(patrol.demoTimer);
    patrol.demoEvents = [];
    refreshPatrol();
  }
}

function layoutFiles() {
  patrol.layout = [];
  const height = Math.max(390, Math.min(960, (canvas.parentElement.clientWidth || 900) * worldHeight() / 900));
  canvas.style.height = `${height}px`;
  const canvasRect = canvas.getBoundingClientRect();
  const scale = Math.min(canvasRect.width / 900 || 1, canvasRect.height / worldHeight() || 1);
  const offsets = [(canvasRect.width - 900 * scale) / 2, (canvasRect.height - worldHeight() * scale) / 2];
  const rooms = {
    "server-a": { x: 28, y: 62, w: 410, h: worldHeight() - 118 },
    "server-b": { x: 462, y: 62, w: 410, h: worldHeight() - 118 },
  };
  for (const host of hosts) {
    const files = patrol.files.filter((file) => file.host_id === host);
    const room = rooms[host];
    files.forEach((file, index) => {
      const col = index % 4;
      const row = Math.floor(index / 4);
      const x = room.x + 70 + col * 88;
      const y = room.y + 130 + row * 77;
      patrol.layout.push({ ...file, x, y, screenX: offsets[0] + x * scale, screenY: offsets[1] + y * scale, screenScale: scale });
    });
  }
}

function roundRect(x, y, width, height, radius, fill, stroke) {
  ctx.beginPath();
  ctx.roundRect(x, y, width, height, radius);
  ctx.fillStyle = fill;
  ctx.fill();
  if (stroke) {
    ctx.strokeStyle = stroke;
    ctx.lineWidth = 2;
    ctx.stroke();
  }
}

function drawRoom(host, title, room, phase) {
  roundRect(room.x, room.y, room.w, room.h, 5, "#d4c49e", "#243947");
  for (let y = room.y + 12; y < room.y + room.h - 10; y += 27) {
    for (let x = room.x + 10; x < room.x + room.w - 10; x += 27) {
      ctx.fillStyle = ((x + y) / 27) % 2 ? "#ddcea8" : "#e7d9b6";
      ctx.fillRect(x, y, 25, 25);
    }
  }
  ctx.fillStyle = "#263d4b";
  ctx.fillRect(room.x + 6, room.y + 6, room.w - 12, 34);
  ctx.font = "bold 14px ui-monospace, monospace";
  ctx.fillStyle = "#f6f0df";
  ctx.fillText(title, room.x + 18, room.y + 28);
  ctx.font = "10px ui-monospace, monospace";
  ctx.fillStyle = "#4a5553";
  ctx.fillText("/data · folder rooms", room.x + 18, room.y + 59);
  ctx.fillStyle = phase % 2 ? "#8b5c31" : "#9b6536";
  ctx.fillRect(room.x + room.w / 2 - 25, room.y + room.h - 5, 50, 9);
  ctx.fillStyle = "#47372a";
  ctx.fillRect(room.x + room.w / 2 - 20, room.y + room.h - 1, 40, 4);
  ctx.fillStyle = "#50635b";
  ctx.fillRect(room.x + 20, room.y + 80, room.w - 40, 7);
}

function drawFile(file, phase) {
  const severity = severityForFile(file);
  const category = fileCategory(file.path);
  const lastEvent = latestEvents().find((event) => event.host_id === file.host_id && cleanPath(event.path) === cleanPath(file.path) && event.actor !== "police");
  if (lastEvent?.action === "delete" && lastEvent.status !== "blocked") {
    ctx.strokeStyle = "#a84238"; ctx.lineWidth = 2; ctx.strokeRect(file.x - 18, file.y - 16, 36, 31);
    ctx.fillStyle = "#a84238"; ctx.font = "9px ui-monospace, monospace"; ctx.textAlign = "center";
    ctx.fillText("REMOVED", file.x, file.y + 4); ctx.textAlign = "left";
    return;
  }
  if (["safe", "key", "gold", "document"].includes(category)) {
    ctx.save();
    ctx.shadowColor = severity === "safe" ? "#dfb84d" : "#f5c34d";
    ctx.shadowBlur = 12;
    roundRect(file.x - 17, file.y - 16, 34, 31, 4, category === "safe" ? "#788597" : "#936a28", "#493b2b");
    ctx.restore();
  }
  if (category === "safe") {
    ctx.fillStyle = "#b7c0c6"; ctx.fillRect(file.x - 11, file.y - 10, 22, 19);
    ctx.fillStyle = "#263d4b"; ctx.fillRect(file.x - 5, file.y - 4, 10, 7);
    ctx.fillStyle = "#f2cb56"; ctx.fillRect(file.x + 2, file.y - 2, 3, 3);
  } else if (category === "key") {
    ctx.fillStyle = "#efc34e"; ctx.fillRect(file.x - 4, file.y - 11, 8, 20);
    ctx.fillRect(file.x - 10, file.y - 12, 20, 5); ctx.fillRect(file.x + 3, file.y + 1, 9, 4);
  } else if (category === "gold") {
    ctx.fillStyle = "#e9b93e"; ctx.fillRect(file.x - 13, file.y + 3, 26, 8);
    ctx.fillRect(file.x - 9, file.y - 4, 21, 8); ctx.fillRect(file.x - 5, file.y - 10, 14, 7);
  } else if (category === "document") {
    ctx.fillStyle = "#f7f2df"; ctx.fillRect(file.x - 11, file.y - 13, 22, 27);
    ctx.fillStyle = "#60756e"; ctx.fillRect(file.x - 7, file.y - 7, 14, 2);
    ctx.fillRect(file.x - 7, file.y - 1, 12, 2); ctx.fillRect(file.x - 7, file.y + 5, 9, 2);
  } else {
    ctx.fillStyle = "#a87442"; ctx.fillRect(file.x - 12, file.y - 11, 24, 21);
    ctx.fillStyle = "#d7ac6a"; ctx.fillRect(file.x - 8, file.y - 7, 16, 13);
    ctx.fillStyle = "#855a35"; ctx.fillRect(file.x - 3, file.y - 3, 6, 6);
  }
  if (lastEvent?.action === "modify" && lastEvent.status !== "blocked") {
    ctx.fillStyle = "rgba(190, 67, 54, .28)"; ctx.fillRect(file.x - 11, file.y - 12, 22, 23);
  }
  if (severity === "compromised" || (severity === "suspicious" && phase % 2 < 1)) {
    ctx.fillStyle = severity === "compromised" ? "#b34236" : "#cb7a23";
    ctx.font = "bold 17px ui-monospace, monospace";
    ctx.fillText("!", file.x + 15, file.y - 14);
  }
  const label = cleanPath(file.path).split("/").at(-1).slice(0, 13);
  ctx.font = "9px ui-monospace, monospace";
  ctx.fillStyle = "#283f4b";
  ctx.textAlign = "center";
  ctx.fillText(label, file.x, file.y + 25);
  ctx.textAlign = "left";
}

function policeTarget(actors) {
  const active = latestEvents().filter((event) => event.severity !== "safe" && Date.now() - Date.parse(event.ts || 0) < 12000);
  const alert = active.find((event) => event.actor !== "police") || active[0];
  if (alert) return patrol.layout.find((file) => file.host_id === alert.host_id && cleanPath(file.path) === cleanPath(alert.path));
  return patrol.layout[patrol.patrolIndex % Math.max(1, patrol.layout.length)];
}

function drawPolice(x, y, time, checkingPath, siren) {
  const pulse = reduceMotion.matches ? 0.5 : (Math.sin(time / 120) + 1) / 2;
  if (siren) {
    ctx.fillStyle = pulse > 0.5 ? "#d9584e" : "#f1c04d";
    ctx.fillRect(x - 7, y - 31, 14, 4);
    ctx.fillStyle = "rgba(202, 65, 52, .16)";
    ctx.beginPath(); ctx.arc(x, y, 30 + pulse * 8, 0, Math.PI * 2); ctx.fill();
  }
  ctx.fillStyle = "#1f3443"; ctx.fillRect(x - 10, y - 7, 20, 22);
  ctx.fillStyle = "#314d5d"; ctx.fillRect(x - 12, y - 19, 24, 14);
  ctx.fillStyle = "#e5cda8"; ctx.fillRect(x - 7, y - 27, 14, 9);
  ctx.fillStyle = "#23485b"; ctx.fillRect(x - 10, y - 31, 20, 5);
  ctx.fillStyle = "#d7ad45"; ctx.fillRect(x - 3, y - 28, 6, 4);
  ctx.fillStyle = "#172b39"; ctx.fillRect(x - 8, y + 14, 6, 6); ctx.fillRect(x + 2, y + 14, 6, 6);
  const bubble = `Checking ${cleanPath(checkingPath).split("/").at(-1).slice(0, 12)}... ${siren ? "ALERT !" : "OK ✓"}`;
  ctx.font = "10px ui-monospace, monospace";
  const bubbleWidth = Math.min(180, ctx.measureText(bubble).width + 16);
  roundRect(x - bubbleWidth / 2, y - 55, bubbleWidth, 18, 3, "#fffdf5", "#3c514f");
  ctx.fillStyle = "#253d4a"; ctx.fillText(bubble, x - bubbleWidth / 2 + 8, y - 43);
}

function drawThief(event, time) {
  const file = patrol.layout.find((item) => item.host_id === event.host_id && cleanPath(item.path) === cleanPath(event.path));
  if (!file) return;
  const room = event.host_id === "server-b" ? { x: 462, y: 62, w: 410, h: worldHeight() - 118 } : { x: 28, y: 62, w: 410, h: worldHeight() - 118 };
  const denied = event.status === "blocked";
  const age = Math.max(0, time - Date.parse(event.ts || time));
  const approach = event.action === "download" ? 1400 : 2200;
  const progress = Math.min(denied ? 0.38 : 1, age / approach);
  const startX = room.x + room.w / 2;
  const startY = room.y + room.h - 12;
  const exit = event.action === "download" && age > approach
    ? Math.min(1, (age - approach) / 1500)
    : 0;
  const arrivedX = startX + (file.x - startX) * progress;
  const arrivedY = startY + (file.y + 24 - startY) * progress;
  const x = arrivedX + (startX - arrivedX) * exit;
  const y = arrivedY + (startY - arrivedY) * exit;
  const severity = safeSeverity(event.severity);
  const color = severity === "compromised" ? "#c84637" : severity === "suspicious" ? "#dc872c" : "#e4bd42";
  ctx.fillStyle = color; ctx.fillRect(x - 8, y - 5, 16, 14);
  ctx.fillStyle = "#283541"; ctx.fillRect(x - 9, y - 12, 18, 8);
  ctx.fillStyle = "#e9d0ad"; ctx.fillRect(x - 5, y - 18, 10, 7);
  ctx.fillStyle = "#273544"; ctx.fillRect(x - 4, y - 13, 2, 2); ctx.fillRect(x + 2, y - 13, 2, 2);
  if (event.action === "read") {
    ctx.fillStyle = "rgba(255, 226, 131, .22)";
    ctx.beginPath(); ctx.moveTo(x, y - 14); ctx.lineTo(file.x, file.y); ctx.lineTo(x + 10, y - 8); ctx.fill();
    ctx.fillStyle = "#f7df94"; ctx.fillRect(x + 6, y - 8, 4, 4);
  } else if (event.action === "modify") {
    ctx.strokeStyle = "#b63f35"; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.moveTo(file.x, file.y - 8); ctx.lineTo(file.x - 4, file.y); ctx.lineTo(file.x + 3, file.y + 4); ctx.stroke();
  } else if (event.action === "download") {
    ctx.fillStyle = "#e8c456"; ctx.fillRect(x + 8, y - 7, 8, 8);
  } else if (event.action === "delete") {
    ctx.strokeStyle = "#c7483b"; ctx.lineWidth = 3;
    ctx.beginPath(); ctx.moveTo(x - 8, y - 7); ctx.lineTo(x + 8, y + 7); ctx.moveTo(x + 8, y - 7); ctx.lineTo(x - 8, y + 7); ctx.stroke();
  }
  if (denied && age > 300) {
    ctx.strokeStyle = "#a84238"; ctx.lineWidth = 3;
    ctx.beginPath(); ctx.moveTo(x - 13, y - 17); ctx.lineTo(x + 13, y + 14); ctx.moveTo(x + 13, y - 17); ctx.lineTo(x - 13, y + 14); ctx.stroke();
  }
}

function drawScene(time) {
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  if (canvas.width !== Math.round(rect.width * dpr) || canvas.height !== Math.round(rect.height * dpr)) {
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    layoutFiles();
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.imageSmoothingEnabled = false;
  ctx.fillStyle = "#9caf9d"; ctx.fillRect(0, 0, rect.width, rect.height);
  const scale = Math.min(rect.width / 900, rect.height / worldHeight());
  const offsetX = (rect.width - 900 * scale) / 2;
  const offsetY = (rect.height - worldHeight() * scale) / 2;
  ctx.save(); ctx.translate(offsetX, offsetY); ctx.scale(scale, scale);
  const rooms = [
    { x: 28, y: 62, w: 410, h: worldHeight() - 118 },
    { x: 462, y: 62, w: 410, h: worldHeight() - 118 },
  ];
  drawRoom("server-a", "SERVER A · /data", rooms[0], Math.floor(time / 900));
  drawRoom("server-b", "SERVER B · /data", rooms[1], Math.floor(time / 900));
  ctx.fillStyle = "#435852"; ctx.fillRect(438, 280, 24, 10);
  ctx.fillStyle = "#e9e3c8"; ctx.font = "10px ui-monospace, monospace"; ctx.fillText("LB", 442, 273);
  for (const file of patrol.layout) drawFile(file, time / 1200);
  for (const event of activeActors()) drawThief(event, time);
  if (patrol.layout.length) {
    const target = policeTarget();
    const targetIndex = patrol.layout.indexOf(target);
    if (patrol.paused === false && !reduceMotion.matches) {
      patrol.patrolClock += Math.min(34, Math.max(0, time - patrol.lastFrame)) * patrol.speed;
      if (patrol.patrolClock > 2200 && !target) {
        patrol.patrolClock = 0;
        patrol.patrolIndex = (patrol.patrolIndex + 1) % patrol.layout.length;
      }
    }
    const siren = latestEvents().some((event) => event.severity !== "safe" && Date.now() - Date.parse(event.ts || 0) < 12000);
    const start = patrol.layout[patrol.patrolIndex % patrol.layout.length];
    const destination = target || patrol.layout[(patrol.patrolIndex + 1) % patrol.layout.length];
    const walk = Math.min(1, patrol.patrolClock / 1800);
    const x = start.x + (destination.x - start.x) * walk;
    const y = start.y + (destination.y - start.y) * walk;
    drawPolice(x, y + 48, time, destination.path, siren);
    canvas.dataset.currentFile = String(targetIndex);
  }
  patrol.lastFrame = time;
  ctx.restore();
}

function animationFrame(time) {
  drawScene(time);
  window.requestAnimationFrame(animationFrame);
}

function selectTab(name) {
  const patrolSelected = name === "patrol";
  document.querySelector("#patrol-view").hidden = !patrolSelected;
  document.querySelector("#overview-view").hidden = patrolSelected;
  document.querySelector("#tab-patrol").setAttribute("aria-selected", String(patrolSelected));
  document.querySelector("#tab-overview").setAttribute("aria-selected", String(!patrolSelected));
  if (patrolSelected) layoutFiles();
}

document.querySelector("#tab-patrol").addEventListener("click", () => selectTab("patrol"));
document.querySelector("#tab-overview").addEventListener("click", () => selectTab("overview"));
document.querySelector("#patrol-demo-toggle").addEventListener("click", toggleDemo);
document.querySelector("#scenario-start").addEventListener("click", startScenario);
document.querySelector("#scenario-pause").addEventListener("click", () => scenarioControl("pause"));
document.querySelector("#scenario-resume").addEventListener("click", () => scenarioControl("resume"));
document.querySelector("#scenario-cancel").addEventListener("click", () => scenarioControl("cancel"));
document.querySelector("#patrol-pause").addEventListener("click", (event) => {
  patrol.paused = !patrol.paused;
  event.currentTarget.setAttribute("aria-pressed", String(patrol.paused));
  event.currentTarget.textContent = patrol.paused ? "Lanjutkan" : "Jeda";
  if (patrol.demo) {
    window.clearInterval(patrol.demoTimer);
    if (!patrol.paused) patrol.demoTimer = window.setInterval(addDemoPair, 4200);
  }
});
document.querySelector("#patrol-speed").addEventListener("change", (event) => { patrol.speed = Number(event.target.value) || 1; });
document.querySelector("#patrol-filter").addEventListener("change", (event) => {
  patrol.filter = event.target.value;
  renderEvents();
});
canvas.addEventListener("click", (event) => {
  const rect = canvas.getBoundingClientRect();
  const point = { x: event.clientX - rect.left, y: event.clientY - rect.top };
  const actor = activeActors().find((item) => {
    const candidate = patrol.layout.find((fileItem) => fileItem.host_id === item.host_id && cleanPath(fileItem.path) === cleanPath(item.path));
    return candidate && Math.hypot(candidate.screenX - point.x, candidate.screenY + 24 * candidate.screenScale - point.y) < 24;
  });
  if (actor) return showDetail(actor);
  const file = patrol.layout.find((item) => Math.hypot(item.screenX - point.x, item.screenY - point.y) < 32);
  if (file) showDetail({ ts: file.checked_at, actor: "police", action: "read", host_id: file.host_id, path: file.path, hash_new: file.sha256, severity: severityForFile(file) });
});

document.querySelector(".dashboard-tabs").addEventListener("keydown", (event) => {
  const tabs = [document.querySelector("#tab-overview"), document.querySelector("#tab-patrol")];
  const current = tabs.indexOf(document.activeElement);
  if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
    event.preventDefault();
    tabs[(current + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length].click();
    tabs[(current + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length].focus();
  }
});

window.addEventListener("resize", layoutFiles);
loadState();
// Polling state 800 ms terfokus; event live tetap lewat SSE — bukan polling per frame.
window.setInterval(loadState, 800);
window.requestAnimationFrame(animationFrame);
