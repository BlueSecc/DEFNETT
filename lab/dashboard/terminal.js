/* DEFNETT terminal — shell SSH ke Server A / Server B lewat collector.
 * Login tetap memakai akun server: username di form, password diketik di prompt ssh.
 * Hanya operator yang sudah masuk yang bisa membuka sesi. */
(() => {
"use strict";
const $ = (selector) => document.querySelector(selector);
const XTERM_CSS = "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css";
const XTERM_JS = "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js";
const FIT_JS = "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.js";
const ERRORS = {
  unauthorized: "Masuk sebagai operator dulu.",
  csrf_required: "Sesi operator kedaluwarsa, masuk lagi.",
  unknown_host: "Server tidak dikenal.",
  invalid_username: "Username tidak valid (huruf kecil, angka, _ . -).",
  too_many_terminals: "Terlalu banyak terminal terbuka di collector.",
  too_many_terminals_for_operator: "Maksimal 2 terminal per operator. Putuskan yang lain dulu.",
  terminal_disabled: "Terminal web dinonaktifkan di collector.",
  terminal_not_found: "Sesi terminal sudah tidak ada.",
};

const state = { host: "server-a", id: null, offset: 0, term: null, fit: null, loading: null, pending: "", flushTimer: null };

function status(text, tone = "") {
  const node = $("#term-status");
  node.textContent = text;
  node.dataset.tone = tone;
}
function operator() { return window.__operator || {}; }
async function post(path, body) {
  const headers = { "Content-Type": "application/json" };
  if (operator().csrf) headers["X-DEFNETT-CSRF"] = operator().csrf;
  const response = await fetch(path, { method: "POST", headers, cache: "no-store", body: JSON.stringify(body || {}) });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(ERRORS[payload.error] || payload.error || `HTTP ${response.status}`);
  return payload;
}
function toBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
function fromBase64(data) {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function loadScript(src) {
  return new Promise((resolve, reject) => {
    const tag = document.createElement("script");
    tag.src = src; tag.onload = resolve; tag.onerror = () => reject(new Error(`gagal memuat ${src}`));
    document.head.append(tag);
  });
}
function ensureXterm() {
  if (state.term) return Promise.resolve(state.term);
  if (!state.loading) {
    const css = document.createElement("link");
    css.rel = "stylesheet"; css.href = XTERM_CSS; document.head.append(css);
    state.loading = loadScript(XTERM_JS).then(() => loadScript(FIT_JS)).then(() => {
      const term = new window.Terminal({
        cursorBlink: true, fontSize: 13, scrollback: 3000, convertEol: false,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        theme: { background: "#0b0f12", foreground: "#d8e2e8", cursor: "#1abc9c", selectionBackground: "#1abc9c55" },
      });
      const fit = new window.FitAddon.FitAddon();
      term.loadAddon(fit);
      term.open($("#term-screen"));
      term.onData((data) => queueInput(data));
      state.term = term; state.fit = fit;
      fitTerminal();
      term.writeln("\x1b[2mPilih server, isi username, lalu tekan Hubungkan. Password diminta di sini.\x1b[0m");
      return term;
    }).catch((error) => {
      state.loading = null;
      status(`xterm.js tidak bisa dimuat (browser perlu akses internet ke cdn.jsdelivr.net): ${error.message}`, "bad");
      throw error;
    });
  }
  return state.loading;
}
function fitTerminal() {
  if (!state.fit || $("#terminal-view").hidden) return;
  try { state.fit.fit(); } catch (error) { return; }
  if (state.id) post(`/v1/term/${state.id}/resize`, { rows: state.term.rows, cols: state.term.cols }).catch(() => {});
}
function queueInput(data) {
  if (!state.id) return;
  state.pending += data;
  if (!state.flushTimer) state.flushTimer = setTimeout(flushInput, 12);
}
async function flushInput() {
  state.flushTimer = null;
  const data = state.pending; state.pending = "";
  if (!data || !state.id) return;
  try { await post(`/v1/term/${state.id}/input`, { data: toBase64(data) }); }
  catch (error) { status(error.message, "bad"); }
}
async function pollLoop(id) {
  while (state.id === id) {
    try {
      const response = await fetch(`/v1/term/${id}?offset=${state.offset}&wait=10`, { cache: "no-store" });
      const payload = await response.json().catch(() => ({}));
      if (state.id !== id) return;
      if (!response.ok) throw new Error(ERRORS[payload.error] || payload.error || `HTTP ${response.status}`);
      if (payload.data) state.term.write(fromBase64(payload.data));
      state.offset = payload.offset;
      if (payload.closed) {
        state.term.writeln(`\r\n\x1b[33m[sesi ${state.host} selesai${payload.exit_code != null ? `, kode ${payload.exit_code}` : ""}]\x1b[0m`);
        finish("Sesi selesai. Hubungkan lagi bila perlu.");
        return;
      }
    } catch (error) {
      if (state.id !== id) return;
      finish(error.message, "bad");
      return;
    }
  }
}
function setConnected(connected) {
  $("#term-connect").hidden = connected;
  $("#term-disconnect").hidden = !connected;
  $("#term-user").disabled = connected;
  document.querySelectorAll(".term-hosts button").forEach((button) => { button.disabled = connected; });
}
function finish(text, tone = "") {
  state.id = null;
  setConnected(false);
  status(text, tone);
}
async function connect(event) {
  event.preventDefault();
  const username = $("#term-user").value.trim();
  if (!operator().csrf) { status(ERRORS.unauthorized, "bad"); return; }
  if (!username) { status("Isi username server dulu.", "bad"); return; }
  try {
    const term = await ensureXterm();
    fitTerminal();
    status(`Menghubungkan ke ${state.host} sebagai ${username}…`);
    const opened = await post("/v1/term", { host: state.host, username, rows: term.rows, cols: term.cols });
    term.reset();
    state.id = opened.id; state.offset = 0;
    setConnected(true);
    status(`Terhubung ke ${opened.host} sebagai ${opened.username}. Ketik password server di terminal.`, "good");
    term.focus();
    pollLoop(opened.id);
  } catch (error) {
    if (!state.term) return;
    status(error.message, "bad");
  }
}
async function disconnect() {
  const id = state.id;
  if (!id) return;
  try { await post(`/v1/term/${id}/close`); } catch (error) { /* sesi mungkin sudah tutup */ }
}

document.querySelectorAll(".term-hosts button").forEach((button) => {
  button.addEventListener("click", () => {
    state.host = button.dataset.host;
    document.querySelectorAll(".term-hosts button").forEach((item) => item.setAttribute("aria-pressed", String(item === button)));
  });
});
$("#term-form").addEventListener("submit", connect);
$("#term-disconnect").addEventListener("click", disconnect);
window.addEventListener("resize", () => { clearTimeout(fitTerminal.timer); fitTerminal.timer = setTimeout(fitTerminal, 120); });
window.addEventListener("defnett:tab", (event) => {
  if (event.detail !== "terminal") return;
  ensureXterm().then(() => { setTimeout(fitTerminal, 60); if (state.id) state.term.focus(); }).catch(() => {});
});
window.addEventListener("beforeunload", () => {
  if (!state.id) return;
  // Tutup sesi saat halaman ditutup supaya ssh tidak tertinggal di collector.
  fetch(`/v1/term/${state.id}/close`, { method: "POST", keepalive: true, headers: { "Content-Type": "application/json", "X-DEFNETT-CSRF": operator().csrf || "" }, body: "{}" }).catch(() => {});
});
})();
