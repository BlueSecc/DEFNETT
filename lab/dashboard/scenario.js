// Panel Skenario lab (digerakkan backend) — JS terpisah supaya mesin
// animasi insiden tetap utuh dan panel skenario dapat di-adopsi/di-drop.
(() => {
  "use strict";

  const scenarioUI = {
    runId: null,
    state: null,
    pauseRequested: false,
    pollTimer: null,
    scenarios: {},
    activeRunIds: [],
  };

  function safeTrim(value, max = 180) {
    const text = String(value == null ? "" : value);
    const normalized = text.replace(/\s+/g, " ").trim();
    return normalized.length > max ? `${normalized.slice(0, max - 1)}…` : normalized;
  }

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
    if (!stateNode || !messageNode || !start || !pauseButton || !resumeButton || !cancelButton) {
      return;
    }
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

  async function startScenario() {
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
          `Start ditolak (${response.status}): ${safeTrim(String(data.error || "unknown"), 96)}` +
          (data.detail ? ` · ${safeTrim(String(data.detail), 180)}` : "");
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
        messageNode.textContent = `${action} ditolak (${response.status}): ${safeTrim(String(data.error || "unknown"), 96)}`;
        return;
      }
      const data = await response.json();
      paintScenario(data.run);
      if (!terminalScenarioState(data.run.state)) pollScenarioRun(data.run.run_id);
    } catch (error) {
      messageNode.textContent = `${action} gagal: ${error.message}`;
    }
  }

  const start = document.querySelector("#scenario-start");
  const pauseButton = document.querySelector("#scenario-pause");
  const resumeButton = document.querySelector("#scenario-resume");
  const cancelButton = document.querySelector("#scenario-cancel");
  if (!start) return;
  start.addEventListener("click", startScenario);
  pauseButton.addEventListener("click", () => scenarioControl("pause"));
  resumeButton.addEventListener("click", () => scenarioControl("resume"));
  cancelButton.addEventListener("click", () => scenarioControl("cancel"));
  adoptActiveRun().catch((error) => {
    const messageNode = document.querySelector("#scenario-message");
    if (messageNode) messageNode.textContent = `Panel skenario menunggu backend: ${error.message}`;
  });
})();
