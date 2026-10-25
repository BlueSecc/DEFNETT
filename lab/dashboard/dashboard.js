const $ = (selector) => document.querySelector(selector);
const eventList = $("#event-list");
const hostFilter = $("#host-filter");
const displayedEvents = [];

const labels = {
  file_created: "File baru",
  file_modified: "File berubah",
  file_deleted: "File dihapus",
};

const remediationLabels = {
  DETECTED: "Canary terdeteksi",
  ISOLATING: "Mengisolasi host target",
  ISOLATED: "Host target keluar dari rotasi",
  REPAIRING: "Mengarantina artefak target",
  VERIFYING: "Memverifikasi hasil perbaikan",
  REJOINING: "Health check dan rejoin target",
  REPAIRED: "Host target aktif kembali",
  FAILED: "Pemulihan host target gagal",
};

function setNodeState(id, state, detail) {
  const node = document.getElementById(id);
  if (node) {
    node.setAttribute("class", `map-node ${state}`);
    const text = node.querySelector(".node-detail");
    if (text) text.textContent = detail;
  }
  const mobileId = id.replace("node-agent-", "mobile-agent-").replace("node-server-", "mobile-server-");
  const mobileNode = document.getElementById(mobileId);
  if (mobileNode) {
    mobileNode.setAttribute("class", `mobile-node ${state}`);
    const mobileText = mobileNode.querySelector("strong");
    if (mobileText) mobileText.textContent = detail;
  }
}

function formatTime(value) {
  if (!value) return "Waktu tidak tersedia";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Waktu tidak valid" : new Intl.DateTimeFormat("id-ID", {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).format(date);
}

function backendState(value) {
  const upper = String(value || "UNKNOWN").toUpperCase();
  if (upper.startsWith("UP")) return ["up", "UP · menerima trafik"];
  if (upper.includes("MAINT") || upper.includes("DRAIN")) return ["maint", upper];
  if (upper.includes("DOWN") || upper.includes("STOP")) return ["down", upper];
  return ["stale", upper];
}

function renderRemediation(data) {
  const enabled = Boolean(data.analysis?.auto_repair_enabled);
  const mode = $("#repair-mode");
  mode.textContent = enabled ? "Otomatis · canary lab" : "DRY RUN";
  mode.classList.toggle("active", enabled);

  const worker = $("#remediator-health");
  const workerStates = data.remediator?.by_host || {};
  const hosts = ["server-a", "server-b"];
  const workerReady = hosts.every((host) => workerStates[host]?.status === "ready");
  worker.className = `worker-health ${workerReady ? "ready" : "unavailable"}`;
  worker.textContent = hosts.map((host) => {
    const name = host === "server-a" ? "A" : "B";
    return `Worker ${name} ${workerStates[host]?.status === "ready" ? "siap" : "offline"}`;
  }).join(" · ");

  const run = data.remediation;
  const items = [...document.querySelectorAll("#repair-steps [data-stage]")];
  if (!run) {
    $("#repair-status").className = "repair-status waiting";
    $("#repair-status").textContent = enabled ? "Siap menunggu canary" : "Mode observasi";
    $("#repair-headline").textContent = "Belum ada pemulihan yang dijalankan";
    $("#repair-detail").textContent = enabled
      ? "Playbook otomatis aktif untuk penanda lab. Saat terdeteksi, Server A diisolasi, file dipindahkan ke karantina, lalu health check menentukan apakah backend boleh aktif lagi."
      : "Playbook berada di DRY RUN. Aktifkan overlay canary lab untuk menjalankan isolasi dan pemulihan otomatis.";
    $("#repair-file").textContent = "Menunggu event";
    $("#repair-survivor").textContent = "Belum ada target";
    $("#repair-quarantine").textContent = "Belum ada";
    $("#repair-started").textContent = "Belum ada";
    for (const item of items) {
      item.hidden = true;
      item.className = "";
      item.querySelector("small").textContent = "";
    }
    return;
  }

  const history = Array.isArray(run.steps) ? run.steps : [];
  const latest = history.at(-1)?.stage || run.status;
  const failed = run.status === "FAILED";
  const successful = run.status === "REPAIRED";
  const failedBeforeIsolation = run.detail?.includes("tidak sehat; ")
    || run.detail?.includes("belum mengonfirmasi isolasi");
  const badge = $("#repair-status");
  badge.className = `repair-status ${failed ? "failed" : successful ? "complete" : "running"}`;
  badge.textContent = remediationLabels[run.status] || run.status;
  $("#repair-headline").textContent = successful
    ? `Artefak dikarantina dan ${run.host_id} kembali aktif`
    : failed ? failedBeforeIsolation
      ? "Respons dihentikan, periksa kesehatan backend"
      : "Pemulihan gagal, lihat status backend dan langkah terakhir"
      : `Sedang berjalan: ${remediationLabels[run.status] || run.status}`;
  let detail = run.detail || "Status pemulihan belum memiliki rincian.";
  const demoHost = data.analysis?.demo_repair_host;
  const demoDelay = Number(data.analysis?.demo_repair_delay_seconds || 0);
  const repairStarted = history.find((step) => step.stage === "REPAIRING")?.timestamp;
  if (run.status === "REPAIRING" && run.host_id === demoHost && demoDelay > 0 && repairStarted) {
    const elapsed = Math.floor((Date.now() - new Date(repairStarted).getTime()) / 1000);
    const remaining = Math.max(0, demoDelay - elapsed);
    const minutes = String(Math.floor(remaining / 60)).padStart(2, "0");
    const seconds = String(remaining % 60).padStart(2, "0");
    detail = `${detail} Sisa waktu demo: ${minutes}:${seconds}.`;
  }
  $("#repair-detail").textContent = detail;
  $("#repair-file").textContent = `${run.host_id || "server-a"} · ${run.path || "file tidak diketahui"}`;
  const survivor = run.host_id === "server-a" ? "server-b" : "server-a";
  const survivorStatus = String(data.backends?.[survivor] || "UNKNOWN");
  const survivorIsUp = survivorStatus.toUpperCase().startsWith("UP");
  $("#repair-survivor").textContent = survivorIsUp
    ? `${survivor} tetap UP, tidak diperbaiki`
    : `${survivor} ${survivorStatus}, cek ketersediaan`;
  $("#repair-quarantine").textContent = run.quarantine_path || (successful ? "Tidak tersedia" : "Belum dibuat");
  $("#repair-started").textContent = formatTime(run.started_at);

  const recorded = new Map(history.map((step) => [step.stage, step]));
  for (const item of items) {
    const stage = item.dataset.stage;
    const step = recorded.get(stage);
    item.hidden = !step;
    item.className = !step ? "" : stage === "FAILED" ? "failed"
      : stage === latest && !successful ? "current" : "done";
    item.querySelector("small").textContent = step?.detail || "";
  }
}

function formatDelay(seconds) {
  return seconds >= 60 && seconds % 60 === 0 ? `${seconds / 60} menit` : `${seconds} detik`;
}

function renderTraffic(data) {
  const traffic = data.traffic || {};
  const delay = Number(data.analysis?.demo_repair_delay_seconds || 0);
  $("#demo-delay-label").textContent = delay > 0 ? formatDelay(delay) : "beberapa detik";
  const phaseLabels = { before: "SEBELUM", during: "SELAMA", after: "SETELAH" };
  const label = $("#traffic-phase");
  label.textContent = traffic.enabled === false ? "Probe nonaktif"
    : traffic.phase ? `Fase: ${phaseLabels[traffic.phase] || traffic.phase}` : "Menunggu probe";
  label.classList.toggle("active", traffic.enabled !== false && traffic.phase === "during");
  for (const card of document.querySelectorAll(".traffic-card")) {
    const phase = card.dataset.phase;
    const window = traffic.windows?.[phase] || { ok: 0, fail: 0, total: 0, by_host: {} };
    card.classList.toggle("current", traffic.enabled !== false && traffic.phase === phase);
    card.classList.toggle("has-fail", window.fail > 0);
    card.querySelector(".traffic-ok").textContent = String(window.ok);
    card.querySelector(".traffic-rate").textContent = window.total
      ? `request sukses · ${Math.round((window.ok / window.total) * 100)}% dari ${window.total}`
      : "request sukses";
    card.querySelector(".traffic-fail").textContent = String(window.fail);
    card.querySelector(".traffic-a").textContent = String(window.by_host?.["server-a"] || 0);
    card.querySelector(".traffic-b").textContent = String(window.by_host?.["server-b"] || 0);
  }
}

function renderState(data) {
  $("#updated-at").textContent = formatTime(data.generated_at);
  const mode = data.mode || "UNKNOWN";
  $("#lab-mode").textContent = `MODE ${mode}`;
  $("#lab-mode").classList.toggle("active", mode === "ACTIVE_LAB");
  const responseEnabled = Boolean(data.analysis?.canary_response_enabled);
  $("#response-mode").textContent = responseEnabled ? "Aktif untuk canary lab" : "DRY RUN";
  $("#response-detail").textContent = responseEnabled
    ? "Isolasi, karantina penanda, health check, lalu rejoin otomatis."
    : "Playbook nonaktif; keputusan hanya dicatat.";
  const proxyKnown = Object.values(data.backends || {}).some((state) => state !== "UNKNOWN");
  $("#proxy-state").textContent = proxyKnown ? "Runtime API tersambung" : "Status belum diketahui";

  for (const suffix of ["a", "b"]) {
    const host = `server-${suffix}`;
    const agent = data.agents?.[host] || {};
    const age = agent.age_seconds;
    const fresh = Boolean(agent.online);
    const agentText = age == null ? "Belum ada heartbeat" : fresh ? `Heartbeat ${age} dtk lalu` : `Heartbeat usang · ${age} dtk`;
    setNodeState(`node-agent-${suffix}`, fresh ? "online" : age == null ? "stale" : "error", agentText);
    const [state, text] = backendState(data.backends?.[host]);
    setNodeState(`node-server-${suffix}`, state, text);
    $(`#backend-${suffix}-state`).textContent = text;
  }
  displayedEvents.splice(0, displayedEvents.length, ...(Array.isArray(data.events) ? data.events : []));
  $("#event-count").textContent = String(displayedEvents.length);
  const highRisk = displayedEvents.filter((event) => event.level >= 2).length;
  $("#risk-summary").textContent = highRisk
    ? `${highRisk} dari ${displayedEvents.length} event ini perlu ditinjau`
    : `Dari ${displayedEvents.length} event yang ditampilkan, tidak ada level tinggi`;
  renderRemediation(data);
  renderTraffic(data);
  renderEvents();
}

function createEventRow(event) {
  const row = document.createElement("article");
  row.className = "event-row";
  const identity = document.createElement("div");
  const title = document.createElement("span");
  title.className = "event-type";
  title.textContent = labels[event.event_type] || event.event_type || "Event file";
  const host = document.createElement("span");
  host.className = "event-host";
  host.textContent = event.host_id || "host tidak diketahui";
  identity.append(title, host);

  const file = document.createElement("div");
  file.className = "event-file";
  file.textContent = event.path || "path tidak tersedia";

  const decision = document.createElement("div");
  decision.className = "decision";
  const risk = document.createElement("span");
  const level = Number(event.level || 0);
  risk.className = `risk-mark${level >= 3 ? " alert" : level >= 2 ? " warn" : ""}`;
  const attackScore = Number(event.p_attack);
  const scoreText = Number.isFinite(attackScore) ? ` · skor heuristik ${Math.round(attackScore * 100)}%` : "";
  risk.textContent = `Risiko ${Number(event.risk || 0).toFixed(2)}${scoreText} · L${level}`;
  const verdict = document.createElement("strong");
  verdict.textContent = event.advisor_verdict || "dicatat";
  const response = document.createElement("span");
  response.className = "decision-detail";
  response.textContent = `${event.recommendation || "record"} · ${event.mode || "DRY_RUN"} · ${event.response_action || "none"}`;
  decision.append(risk, verdict, response);

  const time = document.createElement("div");
  time.className = "event-time";
  time.textContent = formatTime(event.timestamp);
  row.append(identity, file, decision, time);

  if (event.old_hash || event.new_hash) {
    const hashes = document.createElement("div");
    hashes.className = "event-hashes";
    const oldValue = document.createElement("span");
    oldValue.textContent = "SHA-256 lama: ";
    const oldHash = document.createTextNode(event.old_hash || "n/a");
    const newValue = document.createElement("span");
    newValue.textContent = " · baru: ";
    hashes.append(oldValue, oldHash, newValue, document.createTextNode(event.new_hash || "n/a"));
    row.append(hashes);
  }
  return row;
}

function renderEvents() {
  const selectedHost = hostFilter.value;
  const rows = displayedEvents.filter((event) => selectedHost === "all" || event.host_id === selectedHost);
  eventList.replaceChildren();
  eventList.setAttribute("aria-busy", "false");
  if (!displayedEvents.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "Belum ada perubahan file. Event akan muncul setelah agent mendeteksi file baru, berubah, atau terhapus.";
    eventList.append(empty);
    return;
  }
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = `Belum ada event untuk ${selectedHost}. Pilih host lain untuk melihat bukti.`;
    eventList.append(empty);
    return;
  }
  for (const event of rows) eventList.append(createEventRow(event));
}

async function refresh() {
  const connection = $("#connection");
  try {
    const response = await fetch("/v1/dashboard", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderState(await response.json());
    $("#load-error").hidden = true;
    connection.className = "connection connected";
    connection.lastChild.textContent = "Collector tersambung";
  } catch (error) {
    $("#load-error").hidden = false;
    connection.className = "connection disconnected";
    connection.lastChild.textContent = "Collector terputus";
    eventList.setAttribute("aria-busy", "false");
    if (!displayedEvents.length) {
      eventList.replaceChildren();
      const message = document.createElement("p");
      message.className = "empty-state";
      message.textContent = "Data belum dimuat karena collector tidak merespons. Tekan Segarkan setelah lab aktif.";
      eventList.append(message);
    }
    console.error("Dashboard refresh failed", error);
  }
}

$("#refresh").addEventListener("click", refresh);
hostFilter.addEventListener("change", renderEvents);
refresh();
window.setInterval(refresh, 3000);
