const frame = document.querySelector("#viewFrame");
const transitionMask = document.querySelector("#transitionMask");
const statusMini = document.querySelector("#statusMini");

const state = {
  view: "home",
  services: [],
  servicesLoaded: false,
  lastSummary: null,
  lastResults: [],
  lastPayload: null,
};

const menuItems = [
  ["scan", "SCAN"],
  ["services", "PORTS"],
  ["help", "HELP"],
  ["status", "STATUS"],
];

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

function activeMenuFor(view) {
  if (view === "results" || view === "scanning") {
    return "scan";
  }
  return view;
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
  const views = {
    home: renderHome,
    scan: () => renderScan(options.message || ""),
    scanning: renderScanning,
    results: renderResults,
    services: renderServices,
    help: renderHelp,
    status: renderStatus,
  };

  (views[state.view] || renderHome)();
  bindViewActions();
}

function renderMenu() {
  const active = activeMenuFor(state.view);
  return `
    <nav class="poster-menu" aria-label="主菜单">
      ${menuItems.map(([view, label]) => `
        <button class="menu-button ${active === view ? "active" : ""}" data-view="${view}">
          ${label}
        </button>
      `).join("")}
    </nav>
  `;
}

function shell(kicker, title, content) {
  frame.innerHTML = `
    <section class="view">
      <p class="kicker">${kicker}</p>
      <h2 class="page-title">${title}</h2>
      <div class="poster-grid">
        ${renderMenu()}
        <div class="poster-content">
          ${content}
        </div>
      </div>
    </section>
  `;
}

function renderHome() {
  shell("本地端口扫描器", "选择功能", `
    <p class="home-copy">
      在本机浏览器中配置扫描目标，结果只显示在当前页面。请仅扫描本机、实验环境、虚拟机或已授权的目标。
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

  shell("配置扫描目标", "扫描参数", `
    <div class="panel-shard">
      <form class="scan-form" id="scanForm">
        <label class="field">
          <span>目标 IP 或 IP 范围</span>
          <input id="ipExpression" name="ipExpression" value="${escapeAttr(payload.ipExpression)}"
                 placeholder="192.168.1.10 或 192.168.1.1-192.168.1.20">
        </label>

        <label class="field">
          <span>端口表达式</span>
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
            <span>超时时间 ms</span>
            <input id="timeoutMs" name="timeoutMs" type="number" min="1" value="${payload.timeoutMs}">
          </label>
          <label class="field">
            <span>线程数</span>
            <input id="threadCount" name="threadCount" type="number" min="1" value="${payload.threadCount}">
          </label>
        </div>

        <div class="action-row">
          <button class="action-button" type="submit"><span>开始扫描</span></button>
          <button class="ghost-button" type="button" data-view="home"><span>返回主界面</span></button>
        </div>
      </form>
      ${message ? `<div class="message">${escapeHtml(message)}</div>` : ""}
    </div>
  `);
}

function renderScanning() {
  shell("扫描请求执行中", "正在扫描", `
    <div class="panel-shard scan-pulse">
      <div class="pulse-word">SCANNING</div>
      <p class="home-copy">
        正在等待本地扫描器返回结果。当前后端没有实时进度流，因此这里不显示假的百分比。
      </p>
    </div>
  `);
}

function renderResults() {
  const summary = state.lastSummary;
  const results = state.lastResults || [];

  const summaryHtml = summary ? `
    <div class="summary-grid">
      ${summaryItem("任务", summary.totalTasks)}
      ${summaryItem("开放", summary.openPorts)}
      ${summaryItem("关闭", summary.closedPorts)}
      ${summaryItem("超时", summary.timeoutPorts)}
      ${summaryItem("主机", summary.hostCount)}
      ${summaryItem("端口", summary.portCount)}
      ${summaryItem("耗时", `${Number(summary.elapsedSeconds).toFixed(2)}s`)}
    </div>
  ` : "";

  const resultsHtml = results.length > 0
    ? `<div class="result-list">${results.map(renderResultSticker).join("")}</div>`
    : `<div class="empty-state">未发现开放端口。关闭和超时端口已计入扫描摘要。</div>`;

  shell("扫描反馈结果", "结果反馈", `
    <div class="panel-shard">
      ${summaryHtml}
      ${resultsHtml}
      <div class="action-row">
        <button class="action-button" type="button" data-view="scan"><span>再次扫描</span></button>
        <button class="ghost-button" type="button" data-view="home"><span>返回主界面</span></button>
      </div>
    </div>
  `);
}

function renderServices() {
  shell("内置常见端口", "端口列表", `
    <div class="panel-shard">
      <div class="service-list">
        ${state.services.map((service) => `
          <div class="service-card">
            <strong>${service.port}</strong>
            <span>${escapeHtml(service.name)}</span>
          </div>
        `).join("")}
      </div>
    </div>
  `);
}

function renderHelp() {
  shell("输入与安全说明", "使用说明", `
    <div class="panel-shard">
      <ul class="help-list">
        <li>IP 支持单个 IPv4 地址，或同 C 段范围。</li>
        <li>端口支持单个端口、范围、逗号组合。</li>
        <li>页面只展示开放端口，关闭和超时端口进入摘要统计。</li>
        <li>请仅扫描本机、实验环境、虚拟机或已授权的目标。</li>
        <li>本地 Web 服务默认监听 127.0.0.1:8080。</li>
      </ul>
    </div>
  `);
}

function renderStatus() {
  const summary = state.lastSummary;
  const body = summary
    ? `
      <div class="summary-grid">
        ${summaryItem("上次任务", summary.totalTasks)}
        ${summaryItem("上次开放", summary.openPorts)}
        ${summaryItem("上次耗时", `${Number(summary.elapsedSeconds).toFixed(2)}s`)}
      </div>
    `
    : `<div class="empty-state">当前页面会话中还没有完成扫描。</div>`;

  shell("本地服务状态", "运行状态", `
    <div class="panel-shard">
      ${body}
      <p class="home-copy">服务地址：http://127.0.0.1:8080</p>
    </div>
  `);
}

function summaryItem(label, value) {
  return `
    <div class="summary-strip">
      <strong>${value}</strong>
      <span>${label}</span>
    </div>
  `;
}

function renderResultSticker(result) {
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
    <article class="result-sticker">
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
      throw new Error(data.error || "扫描失败。");
    }

    state.lastSummary = data.summary;
    state.lastResults = data.openResults || [];
    statusMini.textContent = `${data.summary.openPorts} open`;
    await navigate("results");
  } catch (error) {
    state.lastSummary = null;
    state.lastResults = [];
    await navigate("scan", { message: `扫描失败：${error.message}` });
  }
}

function readScanForm() {
  const ipExpression = frame.querySelector("#ipExpression").value.trim();
  const portExpression = frame.querySelector("#portExpression").value.trim();
  const timeoutMs = readPositiveInteger("#timeoutMs", "超时时间");
  const threadCount = readPositiveInteger("#threadCount", "线程数");

  if (!ipExpression) {
    throw new Error("目标 IP 或 IP 范围不能为空。");
  }
  if (!portExpression) {
    throw new Error("端口表达式不能为空。");
  }

  return { ipExpression, portExpression, timeoutMs, threadCount };
}

function readPositiveInteger(selector, label) {
  const value = Number(frame.querySelector(selector).value);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${label}必须是正整数。`);
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
