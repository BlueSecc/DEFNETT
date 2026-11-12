const $ = (selector) => document.querySelector(selector);
const eventList = $("#event-list");
const hostFilter = $("#host-filter");
const displayedEvents = [];
const openEvents = new Set();
let latestDashboard = null;
const operator = { username: null, role: null, csrf: null };
window.__operator = operator;

const labels = {
  file_created: "File baru",
  file_modified: "File berubah",
  file_deleted: "File dihapus",
  OT_MODBUS_TRANSACTION: "Transaksi Modbus lab",
  OT_FRAME_REJECTED: "Frame Modbus ditolak",
};

const remediationLabels = {
  DETECTED: "Menunggu persetujuan operator",
  EXECUTING: "Executor berjalan",
  ISOLATION_CONFIRMED: "Host target keluar dari rotasi",
  ISOLATION_UNCONFIRMED: "Isolasi belum terkonfirmasi",
  MASTER_UNTRUSTED: "Master tidak dipercaya manifes",
  REPAIRING: "Mengarantina artefak target",
  VERIFYING: "Memverifikasi hasil perbaikan",
  REJOINING: "Health check dan rejoin target",
  REPAIRED: "Host target aktif kembali",
  HEALTH_CHECK_FAILED: "Health check gagal",
  EXECUTION_FAILED: "Pemulihan host target gagal",
  REJECTED: "Ditolak operator; tidak ada tindakan",
};

const approvalLabels = {
  CONTAIN_CANARY: "Karantina canary",
  RESTORE_KEYS: "Pulihkan kunci dari master",
  SIMULATE_LAB_ATTACK: "Simulasi serangan lab",
  REJOIN_BACKEND: "Rejoin backend",
};

function setNodeState(id, state, detail) {
  const node = document.getElementById(id);
  if (node) {
    node.setAttribute("class", `map-node ${node.dataset.base || ""} ${state}`.replace(/\s+/g, " "));
    const text = node.querySelector(".node-detail");
    if (text) {
      if (text.textContent !== detail) {
        text.style.opacity = "0";
        setTimeout(() => {
          text.textContent = detail;
          text.style.opacity = "1";
        }, 150);
      }
    }
  }
  const mobileId = id.replace("node-agent-", "mobile-agent-").replace("node-server-", "mobile-server-");
  // collector dan proxy tidak punya versi mobile; jangan timpa node desktop dengan kelas mobile.
  const mobileNode = mobileId !== id ? document.getElementById(mobileId) : null;
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

function formatClock(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "-" : new Intl.DateTimeFormat("id-ID", {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).format(date);
}

function backendState(value) {
  const upper = String(value || "UNKNOWN").toUpperCase();
  if (upper.startsWith("UP")) return ["up", "UP"];
  if (upper.includes("MAINT") || upper.includes("DRAIN") || upper.includes("DOWN") || upper.includes("STOP")) return ["down", "DOWN"];
  if (upper.startsWith("NOLB") || upper.startsWith("CHECK")) return ["maint", "CEK"];
  return ["stale", "?"];
}

function renderBackends(data) {
  const states = ["a", "b"].map((suffix) => {
    const host = `server-${suffix}`;
    const [state, text] = backendState(data.backends?.[host]);
    setNodeState(`node-server-${suffix}`, state, text);
    $(`#chip-backend-${suffix}`).textContent = text;
    $(`#chip-backend-${suffix}`).className = `mode-label status-${state}`;
    $(`#route-server-${suffix}`).classList.toggle("route-down", state !== "up");
    return state;
  });
  const up = states.filter((state) => state === "up").length;
  const known = Object.values(data.backends || {}).some((state) => state !== "UNKNOWN");
  // LB hijau selama masih melayani (minimal satu backend UP), merah kalau tidak ada yang UP atau statusnya tidak diketahui.
  const proxyState = known && up > 0 ? "up" : "down";
  setNodeState("node-proxy", proxyState === "up" ? "online" : "down", known ? `${up}/${states.length} UP` : "Offline");
  setRoute("proxy", proxyState === "up");
  $("#chip-proxy").textContent = known ? `${up}/${states.length}` : "OFF";
  $("#chip-proxy").className = `mode-label status-${proxyState}`;
}

function renderRemediation(data) {
  const approvalsRequired = Boolean(data.analysis?.approvals_required);
  const executorReady = Boolean(data.analysis?.executor_ready);
  const mode = $("#repair-mode");
  mode.textContent = !approvalsRequired ? "Approval" : executorReady ? "Approval · executor siap" : "Approval · executor belum terjangkau";
  mode.classList.toggle("active", executorReady);

  const worker = $("#remediator-health");
  const workerStates = data.remediator?.by_host || {};
  const hosts = ["server-a", "server-b"];
  const workerReady = hosts.every((host) => workerStates[host]?.status === "ready");
  worker.className = `badge ${workerReady ? "ready" : "unavailable"}`;
  worker.textContent = `Worker ${hosts.filter((host) => workerStates[host]?.status === "ready").length}/${hosts.length}`;

  const run = data.remediation;
  const items = [...document.querySelectorAll("#repair-steps [data-stage]")];
  $("#repair-facts").hidden = !run;
  $("#repair-metrics").hidden = !run;
  if (!run) {
    $("#repair-status").className = "status-indicator waiting";
    $("#repair-status").textContent = "Siap";
    $("#repair-headline").textContent = "Belum ada insiden";
    $("#repair-detail").textContent = "";
    for (const item of items) {
      item.hidden = true;
      item.className = "";
    }
    return;
  }

  const history = Array.isArray(run.steps) ? run.steps : [];
  const latest = history.at(-1)?.stage || run.status;
  const failed = run.status === "EXECUTION_FAILED";
  const successful = run.status === "REPAIRED";
  const stoppedWithoutChanges = run.detail?.includes("tidak sehat; ")
    || run.detail?.includes("tidak diubah lebih jauh");
  const badge = $("#repair-status");
  badge.className = `status-indicator ${failed ? "failed" : successful ? "complete" : "running"}`;
  badge.textContent = remediationLabels[run.status] || run.status;
  $("#repair-headline").textContent = successful
    ? `${run.host_id} pulih`
    : failed ? stoppedWithoutChanges
      ? "Respons dihentikan"
      : "Pemulihan gagal"
      : remediationLabels[run.status] || run.status;
  $("#repair-detail").textContent = failed ? run.detail || "" : "";
  const metrics = run.metrics || {};
  $("#metric-detect").textContent = formatSeconds(metrics.detect);
  $("#metric-isolate").textContent = formatSeconds(metrics.isolate);
  $("#metric-recover").textContent = formatSeconds(metrics.demo_hold ? metrics.recover_without_hold : metrics.recover);
  $("#metric-recover-label").textContent = metrics.demo_hold ? `Pulih, tanpa jeda demo ${metrics.demo_hold} dtk` : "Pulih";
  $("#repair-entry").textContent = run.entry ? `${run.entry.actor} lewat port ${run.entry.port}` : "Tidak diketahui";
  $("#repair-file").textContent = `${run.host_id || "server-a"} · ${run.path || "-"}`;
  const survivor = run.host_id === "server-a" ? "server-b" : "server-a";
  $("#repair-survivor").textContent = `${survivor} ${backendState(data.backends?.[survivor])[1]}`;
  $("#repair-quarantine").textContent = run.quarantine_path || "-";
  $("#repair-started").textContent = formatTime(run.started_at);

  const recorded = new Map(history.map((step) => [step.stage, step]));
  for (const item of items) {
    const stage = item.dataset.stage;
    const step = recorded.get(stage);
    item.hidden = !step;
    item.className = !step ? "" : stage === "FAILED" ? "failed"
      : stage === latest && !successful ? "current" : "done";
  }
}

function formatSeconds(value) {
  return Number.isFinite(value) ? `${value.toLocaleString("id-ID")} dtk` : "-";
}

async function apiPost(path, body) {
  const headers = { "Content-Type": "application/json" };
  if (operator.csrf) headers["X-DEFNETT-CSRF"] = operator.csrf;
  return fetch(path, { method: "POST", headers, cache: "no-store", body: body === undefined ? "" : JSON.stringify(body) });
}

function isOperator() {
  return operator.role === "operator";
}

const EXECUTION_HINTS = [
  ["key_not_pristine", "Kunci server masih rusak dari serangan lama; pulihkan dulu (lab/vm/fix-server-a-keys.sh atau restore-kunci.sh)"],
  ["target_not_up", "Server target tidak UP di HAProxy"],
  ["survivor_not_healthy", "Server lain tidak sehat; serangan ditahan agar layanan tetap jalan"],
  ["attack_simulation_disabled", "Simulasi serangan nonaktif di remediator"],
];
function shortApprovalDetail(approval) {
  const raw = approval.execution_detail || approval.reason || "";
  const hint = approval.execution_status === "FAILED" && EXECUTION_HINTS.find(([key]) => raw.includes(key));
  if (hint) return `Gagal: ${hint[1]}`;
  const run = raw;
  return run.length > 74 ? `${run.slice(0, 74)}…` : run;
}

function attackNoticeMsg(text) {
  try {
    const payload = JSON.parse(text);
    console.warn(payload.error || text);
  } catch (error) {
    console.warn(text);
  }
}

function renderApprovals(approvals) {
  const list = $("#approval-list");
  if (!list) return;
  list.replaceChildren();
  if (!Array.isArray(approvals) || !approvals.length) {
    const empty = document.createElement("li");
    empty.className = "approval-row empty";
    empty.textContent = "Tidak ada persetujuan berjalan.";
    list.append(empty);
    return;
  }
  for (const approval of approvals) {
    const row = document.createElement("li");
    row.className = "approval-row";
    const head = document.createElement("div");
    head.className = "approval-head-row";
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    detail.className = "small-text";
    detail.textContent = `${approvalLabels[approval.action] || approval.action} · ${approval.host_id} · ${approval.path}`;
    const status = document.createElement("span");
    status.className = `approval-status st-${String(approval.approval_status || "").toLowerCase()}`;
    const state = approval.execution_status && approval.execution_status !== "NONE"
      ? `${approval.approval_status}/${approval.execution_status}` : approval.approval_status;
    status.textContent = state;
    head.append(title, status);
    title.textContent = formatTime(approval.created_at);
    const actionRow = document.createElement("div");
    actionRow.className = "approval-actions";
    const actions = document.createElement("span");
    actions.className = "small-text";
    actions.textContent = shortApprovalDetail(approval);
    actionRow.append(actions);
    if (isOperator()) {
      if (approval.approval_status === "PENDING") {
        const approveButton = document.createElement("button");
        approveButton.className = "approval-btn";
        approveButton.type = "button";
        approveButton.textContent = "Setujui";
        approveButton.addEventListener("click", async () => {
          const response = await apiPost(`/v1/approvals/${approval.id}/approve`);
          if (!response.ok) attackNoticeMsg(await response.text());
          refreshApprovals();
        });
        const rejectButton = document.createElement("button");
        rejectButton.className = "approval-btn danger";
        rejectButton.type = "button";
        rejectButton.textContent = "Tolak";
        rejectButton.addEventListener("click", async () => {
          await apiPost(`/v1/approvals/${approval.id}/reject`, { reason: "operator_rejected" });
          refreshApprovals();
        });
        actionRow.append(approveButton, rejectButton);
      } else if (approval.approval_status === "APPROVED" && approval.execution_status === "NONE") {
        const runButton = document.createElement("button");
        runButton.className = "approval-btn";
        runButton.type = "button";
        runButton.textContent = "Jalankan";
        runButton.addEventListener("click", async () => {
          const response = await apiPost(`/v1/approvals/${approval.id}/execute`);
          if (!response.ok) attackNoticeMsg(await response.text());
          refreshApprovals();
        });
        actionRow.append(runButton);
      }
    }
    row.append(head, detail, actionRow);
    list.append(row);
  }
}

async function refreshApprovals() {
  try {
    const response = await fetch("/v1/approvals", { cache: "no-store" });
    if (!response.ok) return;
    renderApprovals((await response.json()).approvals);
  } catch (error) { /* offline: overview menampilkan pesan itu */ }
}

async function refreshEvidence() {
  const badge = $("#evidence-status");
  try {
    const response = await fetch("/v1/evidence/verify", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const result = await response.json();
    badge.textContent = result.status === "ok" ? `Bukti utuh · ${result.events} event` : "Bukti rusak";
    badge.className = `badge ${result.status === "ok" ? "ready" : "unavailable"}`;
  } catch (error) {
    badge.textContent = "Bukti tidak terbaca";
    badge.className = "badge unavailable";
  }
}

function renderTraffic(data) {
  const traffic = data.traffic || {};
  for (const card of document.querySelectorAll(".traffic-card")) {
    const phase = card.dataset.phase;
    const window = traffic.windows?.[phase] || { ok: 0, fail: 0, total: 0, by_host: {} };
    card.classList.toggle("current", traffic.enabled !== false && traffic.phase === phase);
    card.classList.toggle("has-fail", window.fail > 0);
    card.querySelector(".traffic-ok").textContent = String(window.ok);
    card.querySelector(".traffic-rate").textContent = window.total
      ? `${Math.round((window.ok / window.total) * 100)}%`
      : "-";
    card.querySelector(".traffic-fail").textContent = String(window.fail);
    card.querySelector(".traffic-a").textContent = String(window.by_host?.["server-a"] || 0);
    card.querySelector(".traffic-b").textContent = String(window.by_host?.["server-b"] || 0);
  }
}

function renderState(data) {
  latestDashboard = data;
  const mode = data.mode || "UNKNOWN";
  $("#lab-mode").textContent = mode === "OPERATIONAL" ? "MODE APPROVAL" : mode === "DEGRADED" ? "DEGRADED" : mode;
  $("#lab-mode").classList.toggle("active", mode === "OPERATIONAL");
  const otStatus = data.ot?.status || "SENSOR_UNAVAILABLE";
  const otBadge = $("#ot-sensor-status");
  otBadge.textContent = otStatus;
  otBadge.title = data.ot?.mode || "OT telemetry status not reported";
  otBadge.className = `mode-label ${otStatus === "SENSOR_UNAVAILABLE" ? "status-down" : otStatus === "LIVE_LAB_TELEMETRY" ? "status-up" : "status-maint"}`;

  for (const suffix of ["a", "b"]) {
    const host = `server-${suffix}`;
    const agent = data.agents?.[host] || {};
    const age = agent.age_seconds;
    const fresh = Boolean(agent.online);
    const agentText = age == null ? "-" : fresh ? "Online" : "Offline";
    setNodeState(`node-agent-${suffix}`, fresh ? "online" : age == null ? "stale" : "error", agentText);
    setRoute(`agent-${suffix}`, fresh);
  }
  renderBackends(data);
  displayedEvents.splice(0, displayedEvents.length, ...(Array.isArray(data.events) ? data.events : []));
  renderRemediation(data);
  renderTraffic(data);
  renderEvents();
}

function createEventRow(event) {
  const row = document.createElement("details");
  row.className = "event-row";
  row.open = openEvents.has(event.id);
  row.addEventListener("toggle", () => {
    if (row.open) openEvents.add(event.id); else openEvents.delete(event.id);
  });

  const level = Number(event.level || 0);
  const summary = document.createElement("summary");
  const identity = document.createElement("div");
  identity.className = "event-head";
  const title = document.createElement("span");
  title.className = "event-type";
  title.textContent = labels[event.event_type] || event.event_type || "Event";
  const host = document.createElement("span");
  host.className = "event-host";
  host.textContent = String(event.host_id || "-").replace("server-", "").toUpperCase();
  const time = document.createElement("span");
  time.className = "event-time";
  time.textContent = formatClock(event.timestamp);
  identity.append(title, host, time);

  const file = document.createElement("div");
  file.className = "event-file";
  file.textContent = event.path || "-";
  summary.append(identity, file);

  const decision = document.createElement("div");
  decision.className = "decision";
  const risk = document.createElement("span");
  risk.className = `risk-mark${level >= 3 ? " alert" : level >= 2 ? " warn" : ""}`;
  risk.textContent = `Risiko ${Number(event.risk || 0).toFixed(2)} · L${level}`;
  const verdict = document.createElement("strong");
  verdict.textContent = event.advisor_verdict || "dicatat";
  decision.append(risk, verdict);
  row.classList.toggle("level-alert", level >= 3);
  row.classList.toggle("level-warn", level === 2);
  row.append(summary, decision);

  if (event.risk_assessment) {
    const assessment = event.risk_assessment;
    const breakdown = document.createElement("p");
    breakdown.className = "trajectory-relation";
    const score = assessment.risk_score == null ? "tidak dihitung" : `${assessment.risk_score}/100 ordinal`;
    const missing = Array.isArray(assessment.missing_evidence) && assessment.missing_evidence.length
      ? ` · input belum tersedia: ${assessment.missing_evidence.join(", ")}` : "";
    breakdown.textContent = `Risk ${assessment.risk_level || "UNKNOWN"} · ${score} (bukan probabilitas)${missing}`;
    row.append(breakdown);
    if (assessment.dimensions && typeof assessment.dimensions === "object") {
      for (const [name, dimension] of Object.entries(assessment.dimensions)) {
        const item = document.createElement("div");
        item.className = "event-file";
        const value = dimension?.score == null ? "tidak tersedia" : `${dimension.score}/100`;
        item.textContent = `${name}: ${value} — ${dimension?.reason || "tanpa alasan"}`;
        row.append(item);
      }
    }
  }

  if (event.old_hash || event.new_hash) {
    const hashes = document.createElement("div");
    hashes.className = "event-hashes";
    const oldValue = document.createElement("span");
    oldValue.textContent = "Lama ";
    const oldHash = document.createTextNode(event.old_hash || "-");
    const newValue = document.createElement("span");
    newValue.textContent = " Baru ";
    hashes.append(oldValue, oldHash, newValue, document.createTextNode(event.new_hash || "-"));
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
    empty.textContent = "Belum ada event.";
    eventList.append(empty);
    return;
  }
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = `Belum ada event di ${selectedHost}.`;
    eventList.append(empty);
    return;
  }
  for (const event of rows) eventList.append(createEventRow(event));
}

function renderTrajectories(items) {
  const container = $("#trajectory-list");
  if (!container) return;
  container.replaceChildren();
  if (!Array.isArray(items) || !items.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "Belum ada rangkaian event yang memenuhi aturan korelasi.";
    container.append(empty);
    return;
  }
  for (const trajectory of items) {
    const card = document.createElement("section");
    card.className = "trajectory-card";
    const heading = document.createElement("strong");
    heading.textContent = `${trajectory.trajectory_id} · ${trajectory.host_id}`;
    const count = document.createElement("span");
    count.className = "small-text";
    count.textContent = `${Number(trajectory.event_count) || 0} event · ${formatTime(trajectory.started_at)}`;
    const timeline = document.createElement("ol");
    timeline.className = "trajectory-timeline";
    for (const event of (Array.isArray(trajectory.events) ? trajectory.events : [])) {
      const item = document.createElement("li");
      item.textContent = `${formatTime(event.timestamp)} · ${labels[event.event_type] || event.event_type} · ${event.path || "target tidak tersedia"}`;
      timeline.append(item);
    }
    card.append(heading, count, timeline);
    for (const edge of (Array.isArray(trajectory.relationships) ? trajectory.relationships : [])) {
      const relation = document.createElement("p");
      relation.className = "trajectory-relation";
      const confidence = Number(edge.confidence);
      relation.textContent = `${edge.relation || "RELATION"} · confidence ${Number.isFinite(confidence) ? confidence.toFixed(2) : "unknown"} · ${edge.reason || "alasan tidak tersedia"}`;
      card.append(relation);
    }
    container.append(card);
  }
}

async function refreshTrajectories() {
  try {
    const response = await fetch("/v1/trajectories", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderTrajectories((await response.json()).trajectories);
  } catch (error) {
    renderTrajectories([]);
    const container = $("#trajectory-list");
    const status = document.createElement("p");
    status.className = "empty-state";
    status.textContent = "Data trajectory tidak tersedia saat ini.";
    container.replaceChildren(status);
  }
}

// Kabel (dan titik sambungnya) hijau kalau hidup, merah putus-putus kalau mati.
function setRoute(name, up) {
  document.getElementById(`route-${name}`)?.classList.toggle("route-down", !up);
  document.getElementById(`dot-${name}`)?.classList.toggle("route-down", !up);
}

// Collector hijau kalau menjawab (termasuk 401: hidup tapi belum login), merah kalau tidak terjangkau.
function setCollectorState(alive) {
  const node = document.getElementById("node-collector");
  if (node && !node.dataset.base) node.dataset.base = "collector-node";
  setNodeState("node-collector", alive ? "online" : "down", alive ? "Online" : "Offline");
  if (!alive) {
    ["agent-a", "agent-b", "proxy", "server-a", "server-b"].forEach((name) => setRoute(name, false));
    setNodeState("node-proxy", "down", "Tidak diketahui");
    const chip = $("#chip-proxy");
    chip.textContent = "OFF";
    chip.className = "mode-label status-down";
  }
}

async function refresh() {
  const connection = $("#connection");
  try {
    const response = await fetch("/v1/dashboard", { cache: "no-store" });
    setCollectorState(true);
    if (response.status === 401) {
      // Collector hidup tetapi belum ada sesi: minta login, bukan tampilkan "terputus".
      showOperatorModal(operator.username ? "" : "Masuk operatormu untuk melihat dashboard.");
      $("#load-error").hidden = true;
      connection.className = "connection disconnected";
      connection.lastChild.textContent = "Belum masuk";
      return;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    renderState(data);
    renderApprovals(data.approvals);
    await refreshTrajectories();
    $("#load-error").hidden = true;
    connection.className = "connection connected";
    connection.lastChild.textContent = "Online";
  } catch (error) {
    setCollectorState(false);
    $("#load-error").hidden = false;
    connection.className = "connection disconnected";
    connection.lastChild.textContent = "Terputus";
    eventList.setAttribute("aria-busy", "false");
    if (!displayedEvents.length) {
      eventList.replaceChildren();
      const message = document.createElement("p");
      message.className = "empty-state";
      message.textContent = "Collector tidak merespons.";
      eventList.append(message);
    }
    console.error("Dashboard refresh failed", error);
  }
}

hostFilter.addEventListener("change", renderEvents);

// Kelopak sakura mengikuti cursor, dibatasi agar tetap ringan.
let lastPetalAt = 0;
document.addEventListener("pointermove", (event) => {
  const now = performance.now();
  if (now - lastPetalAt < 90) return;
  lastPetalAt = now;

  const petal = document.createElement("i");
  const size = 7 + Math.random() * 7;
  petal.className = "sakura-petal";
  petal.style.width = `${size}px`;
  petal.style.height = `${size}px`;
  petal.style.left = `${event.clientX - size / 2}px`;
  petal.style.top = `${event.clientY - size / 2}px`;
  petal.style.animation = `fall ${1.8 + Math.random() * 0.8}s cubic-bezier(.2,.7,.4,1) forwards`;
  document.body.append(petal);
  petal.addEventListener("animationend", () => petal.remove());
});

// Sidebar tabs
const sidebarTabs = document.querySelectorAll('.s-tab');
sidebarTabs.forEach((tab) => {
  tab.addEventListener('click', () => {
    sidebarTabs.forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');
    document.querySelectorAll('.s-panel').forEach((p) => p.classList.remove('active'));
    const target = document.getElementById(tab.dataset.target);
    if (target) target.classList.add('active');
  });
});

// Sidebar close (drawer mode on small screens)
const sidebarClose = $("#sidebar-close");
const sidebarOpen = $("#sidebar-open");
const detailsSidebar = $("#details-sidebar");
if (sidebarClose && detailsSidebar) {
  sidebarClose.addEventListener('click', () => {
    detailsSidebar.classList.remove('drawer-open');
  });
}
if (sidebarOpen && detailsSidebar) {
  sidebarOpen.addEventListener('click', () => {
    detailsSidebar.classList.add('drawer-open');
  });
}

function scheduleRefresh() {
  const busy = !$("#patrol-incident").hidden || Date.now() < (window.__patrol?.patrol.fastUntil || 0);
  window.setTimeout(async () => { await refresh(); scheduleRefresh(); }, busy ? 1000 : 2500);
}

/* Operator & approval */
function showOperatorModal(message = "") {
  // Refresh berkala memanggil ini tiap 2,5 dtk saat belum login; jangan rebut fokus
  // atau timpa pesan galat selagi operator mengetik.
  const modal = $("#operator-modal");
  if (!modal.hidden) return;
  $("#op-error").textContent = message;
  modal.hidden = false;
  $("#op-user").focus();
}

function hideOperatorModal() {
  $("#operator-modal").hidden = true;
  $("#op-pass").value = "";
  $("#op-error").textContent = "";
}

function setOperatorButton() {
  const button = $("#operator-button");
  button.textContent = operator.username ? `${operator.username} · ${operator.role}` : "Masuk operator";
  button.classList.toggle("active", Boolean(operator.username));
  $("#logout-button").hidden = !operator.username;
}

async function operatorLogin() {
  const username = $("#op-user").value.trim();
  const password = $("#op-pass").value;
  if (!username || !password) {
    $("#op-error").textContent = "Nama pengguna dan sandi wajib diisi.";
    return;
  }
  $("#op-login").disabled = true;
  try {
    const response = await apiPost("/v1/operator/login", { username, password });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      $("#op-error").textContent = data.error === "too_many_failures"
        ? `Terkunci sementara (${data.retry_seconds || 60} dtk).`
        : data.error === "kredensial_tidak_sah" ? "Kredensial salah." : data.error || `HTTP ${response.status}`;
      return;
    }
    operator.username = data.username;
    operator.role = data.role;
    operator.csrf = data.csrf;
    hideOperatorModal();
    setOperatorButton();
    refresh();
  } finally {
    $("#op-login").disabled = false;
  }
}

async function whoamiRefresh() {
  try {
    const response = await fetch("/v1/operator/whoami", { cache: "no-store" });
    const data = await response.json();
    if (data?.authenticated) {
      operator.username = data.username;
      operator.role = data.role;
      operator.csrf = data.csrf;
    }
  } catch (error) { /* collector offline */ }
  setOperatorButton();
}

$("#operator-button").addEventListener("click", () => {
  // Saat sudah masuk, tombol ini hanya label nama; keluar lewat tombol Keluar.
  if (!operator.username) showOperatorModal();
});
$("#logout-button").addEventListener("click", async () => {
  await apiPost("/v1/operator/logout");
  operator.username = null;
  operator.role = null;
  operator.csrf = null;
  setOperatorButton();
  refresh();
});
$("#op-login").addEventListener("click", () => { operatorLogin(); });
$("#op-cancel").addEventListener("click", hideOperatorModal);
$("#op-pass").addEventListener("keydown", (event) => { if (event.key === "Enter") operatorLogin(); });
$("#op-user").addEventListener("keydown", (event) => { if (event.key === "Enter") operatorLogin(); });

refresh();
scheduleRefresh();
refreshEvidence();
whoamiRefresh();
window.setInterval(refreshEvidence, 15000);
