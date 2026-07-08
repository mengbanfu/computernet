const frame = document.querySelector("#viewFrame");
const transitionMask = document.querySelector("#transitionMask");
const statusMini = document.querySelector("#statusMini");

const state = {
  view: "home",
  services: [],
  servicesLoaded: false,
  lastSummary: null,
  lastResults: [],
  lastError: "",
  lastPayload: null,
};

const quickPorts = [
  ["WEB", "80,443,8080,8443"],
  ["REMOTE", "22,3389,5900"],
  ["DATABASE", "3306,5432,6379,27017"],
  ["COMMON", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080"],
];

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function withPageTransition(loadPage) {
  transitionMask.classList.remove("active");
  void transitionMask.offsetWidth;
  transitionMask.classList.add("active");

  const startedAt = performance.now();
  await loadPage();

  const elapsed = performance.now() - startedAt;
  if (elapsed < 300) {
    await delay(300 - elapsed);
  }
}

function navigate(view, options = {}) {
  return withPageTransition(async () => {
    if (view === "services" && !state.servicesLoaded) {
      await loadServices();
    }
    state.view = view;
    render(options);
  });
}

function render(options = {}) {
  if (state.view === "home") {
    renderHome();
  } else if (state.view === "scan") {
    renderScan(options.message || "");
  } else if (state.view === "scanning") {
    renderScanning();
  } else if (state.view === "results") {
    renderResults();
  } else if (state.view === "services") {
    renderServices();
  } else if (state.view === "help") {
    renderHelp();
  } else if (state.view === "status") {
    renderStatus();
  }

  bindViewActions();
}

function shell(kicker, title, content) {
  frame.innerHTML = `
    <section class="view">
      <p class="kicker">${kicker}</p>
      <h2 class="page-title">${title}</h2>
      ${content}
    </section>
  `;
}

function renderHome() {
  shell("Local scanner mode", "Select<br>Action", `
    <nav class="menu-stack" aria-label="Main menu">
      <button class="menu-button" data-view="scan">SCAN</button>
      <button class="menu-button" data-view="services">PORTS</button>
      <button class="menu-button" data-view="help">HELP</button>
      <button class="menu-button" data-view="status">STATUS</button>
    </nav>
    <p class="home-copy">
      A local TCP connect scanner UI. Results stay in this browser page.
      Scan only hosts you own or are allowed to test.
    </p>
  `);
}

function renderScan(message = "") {
  const payload = state.lastPayload || {
    ipExpression: "127.0.0.1",
    portExpression: "80,443,8080",
    timeoutMs: 500,
    threadCount: 10,
  };

  shell("Configure target", "Scan<br>Target", `
    <div class="form-panel">
      <form class="scan-form" id="scanForm">
        <label class="field">
          <span>Target IP or range</span>
          <input id="ipExpression" name="ipExpression" value="${escapeAttr(payload.ipExpression)}"
                 placeholder="192.168.1.10 or 192.168.1.1-192.168.1.20">
        </label>

        <label class="field">
          <span>Port expression</span>
          <input id="portExpression" name="portExpression" value="${escapeAttr(payload.portExpression)}"
                 placeholder="80 / 1-1024 / 21,22,80,443">
        </label>

        <div class="quick-ports">
          ${quickPorts.map(([label, ports]) => `
            <button class="chip-button" type="button" data-ports="${ports}"><span>${label}</span></button>
          `).join("")}
        </div>

        <div class="form-grid">
          <label class="field">
            <span>Timeout ms</span>
            <input id="timeoutMs" name="timeoutMs" type="number" min="1" value="${payload.timeoutMs}">
          </label>
          <label class="field">
            <span>Threads</span>
            <input id="threadCount" name="threadCount" type="number" min="1" value="${payload.threadCount}">
          </label>
        </div>

        <div class="action-row">
          <button class="action-button" type="submit"><span>START SCAN</span></button>
          <button class="ghost-button" type="button" data-view="home"><span>BACK</span></button>
        </div>
      </form>
      ${message ? `<div class="message error">${escapeHtml(message)}</div>` : ""}
    </div>
  `);
}

function renderScanning() {
  shell("Request in progress", "Scanning", `
    <div class="content-panel scan-pulse">
      <div class="pulse-word">SCANNING</div>
      <p class="home-copy">
        Waiting for the local scanner to finish. No fake percent is shown because V2 does not receive live progress yet.
      </p>
    </div>
  `);
}

function renderResults() {
  const summary = state.lastSummary;
  const results = state.lastResults || [];

  const summaryHtml = summary ? `
    <div class="summary-grid">
      ${summaryItem("TASKS", summary.totalTasks)}
      ${summaryItem("OPEN", summary.openPorts)}
      ${summaryItem("CLOSED", summary.closedPorts)}
      ${summaryItem("TIMEOUT", summary.timeoutPorts)}
      ${summaryItem("HOSTS", summary.hostCount)}
      ${summaryItem("PORTS", summary.portCount)}
      ${summaryItem("TIME", `${Number(summary.elapsedSeconds).toFixed(2)}s`)}
    </div>
  ` : "";

  const resultsHtml = results.length > 0
    ? `<div class="result-list">${results.map(renderResultCard).join("")}</div>`
    : `<div class="empty-state">No open ports found. Closed and timeout ports are counted in the summary.</div>`;

  shell("Scan report", "Results", `
    <div class="content-panel">
      ${summaryHtml}
      ${resultsHtml}
      <div class="action-row">
        <button class="action-button" type="button" data-view="scan"><span>SCAN AGAIN</span></button>
        <button class="ghost-button" type="button" data-view="home"><span>MENU</span></button>
      </div>
    </div>
  `);
}

function renderServices() {
  shell("Known service map", "Ports", `
    <div class="content-panel">
      <div class="service-list">
        ${state.services.map((service) => `
          <div class="service-card">
            <strong>${service.port}</strong>
            <span>${escapeHtml(service.name)}</span>
          </div>
        `).join("")}
      </div>
      <div class="action-row">
        <button class="ghost-button" type="button" data-view="home"><span>BACK</span></button>
      </div>
    </div>
  `);
}

function renderHelp() {
  shell("Rules and input", "Help", `
    <div class="content-panel">
      <ul class="help-list">
        <li>Use one IPv4 address or a same-C-class range.</li>
        <li>Ports accept a single value, a range, or comma-separated mixed input.</li>
        <li>Only open ports are shown as cards. Closed and timeout values stay in summary stats.</li>
        <li>Scan only local, lab, virtual machine, or explicitly authorized targets.</li>
        <li>The web service listens on 127.0.0.1:8080 for local browser use.</li>
      </ul>
      <div class="action-row">
        <button class="ghost-button" type="button" data-view="home"><span>BACK</span></button>
      </div>
    </div>
  `);
}

function renderStatus() {
  const summary = state.lastSummary;
  const body = summary
    ? `
      <div class="summary-grid">
        ${summaryItem("LAST TASKS", summary.totalTasks)}
        ${summaryItem("LAST OPEN", summary.openPorts)}
        ${summaryItem("LAST TIME", `${Number(summary.elapsedSeconds).toFixed(2)}s`)}
      </div>
    `
    : `<div class="empty-state">No scan has completed in this page session.</div>`;

  shell("Local web service", "Status", `
    <div class="content-panel">
      ${body}
      <p class="home-copy">Server: http://127.0.0.1:8080</p>
      <div class="action-row">
        <button class="ghost-button" type="button" data-view="home"><span>BACK</span></button>
      </div>
    </div>
  `);
}

function summaryItem(label, value) {
  return `
    <div class="summary-card">
      <strong>${value}</strong>
      <span>${label}</span>
    </div>
  `;
}

function renderResultCard(result) {
  const endpoint = `${result.ip}:${result.port}`;
  const service = result.detectedService || result.service || "Unknown";
  const version = result.version ? ` (${escapeHtml(result.version)})` : "";
  const method = result.method ? ` [${escapeHtml(result.method)}]` : "";
  const portGuess = result.portGuess && result.portGuess !== service
    ? `<div class="meta">端口猜测：${escapeHtml(result.portGuess)}</div>`
    : "";
  const banner = result.banner
    ? `<div class="banner">Banner: ${escapeHtml(result.banner)}</div>`
    : "";

  return `
    <article class="result-card">
      <h3 class="endpoint">${escapeHtml(endpoint)}</h3>
      <div class="meta">${escapeHtml(service)}${version}${method} / ${result.timeMs} ms</div>
      ${portGuess}
      ${banner}
    </article>
  `;
}

function bindViewActions() {
  frame.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => navigate(button.dataset.view));
  });

  frame.querySelectorAll("[data-ports]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = frame.querySelector("#portExpression");
      input.value = button.dataset.ports;
      input.focus();
    });
  });

  const form = frame.querySelector("#scanForm");
  if (form) {
    form.addEventListener("submit", runScan);
  }
}

async function runScan(event) {
  event.preventDefault();

  let payload;
  try {
    payload = readScanForm();
  } catch (error) {
    renderScan(error.message);
    return;
  }

  state.lastPayload = payload;
  state.view = "scanning";
  render();

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();

    if (!response.ok || !data.ok) {
      throw new Error(data.error || "Scan failed.");
    }

    state.lastError = "";
    state.lastSummary = data.summary;
    state.lastResults = data.openResults || [];
    statusMini.textContent = `${data.summary.openPorts} open`;
    await navigate("results");
  } catch (error) {
    state.lastError = error.message;
    state.lastSummary = null;
    state.lastResults = [];
    await navigate("scan", { message: `Scan failed: ${error.message}` });
  }
}

function readScanForm() {
  const ipExpression = frame.querySelector("#ipExpression").value.trim();
  const portExpression = frame.querySelector("#portExpression").value.trim();
  const timeoutMs = readPositiveInteger("#timeoutMs", "Timeout");
  const threadCount = readPositiveInteger("#threadCount", "Threads");

  if (!ipExpression) {
    throw new Error("Target IP or range is required.");
  }
  if (!portExpression) {
    throw new Error("Port expression is required.");
  }

  return { ipExpression, portExpression, timeoutMs, threadCount };
}

function readPositiveInteger(selector, label) {
  const value = Number(frame.querySelector(selector).value);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

async function loadServices() {
  const response = await fetch("/api/services");
  const data = await response.json();
  state.services = data.services || [];
  state.servicesLoaded = true;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll("`", "&#096;");
}

render();
