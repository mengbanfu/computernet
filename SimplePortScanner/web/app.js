const form = document.querySelector("#scanForm");
const scanButton = document.querySelector("#scanButton");
const clearButton = document.querySelector("#clearButton");
const statusBadge = document.querySelector("#statusBadge");
const messageBox = document.querySelector("#messageBox");
const summaryCards = document.querySelector("#summaryCards");
const resultList = document.querySelector("#resultList");
const portInput = document.querySelector("#portExpression");
const serviceList = document.querySelector("#serviceList");

function setBusy(isBusy) {
  scanButton.disabled = isBusy;
  for (const element of form.elements) {
    element.disabled = isBusy;
  }
  scanButton.textContent = isBusy ? "扫描中..." : "开始扫描";
}

function setStatus(text, state) {
  statusBadge.textContent = text;
  statusBadge.className = `status-badge ${state}`;
}

function showMessage(text, type = "info") {
  messageBox.textContent = text;
  messageBox.className = `message-box ${type}`;
}

function hideMessage() {
  messageBox.textContent = "";
  messageBox.className = "message-box hidden";
}

function clearResults() {
  hideMessage();
  setStatus("待扫描", "idle");
  summaryCards.className = "summary-grid hidden";
  summaryCards.innerHTML = "";
  resultList.innerHTML = `
    <div class="empty-state">
      输入目标和端口后开始扫描，开放端口会显示在这里。
    </div>
  `;
}

function readPositiveInt(id, label) {
  const value = Number(document.querySelector(`#${id}`).value);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${label}必须是正整数。`);
  }
  return value;
}

function readFormData() {
  const ipExpression = document.querySelector("#ipExpression").value.trim();
  const portExpression = portInput.value.trim();

  if (!ipExpression) {
    throw new Error("目标 IP 或 IP 范围不能为空。");
  }
  if (!portExpression) {
    throw new Error("端口表达式不能为空。");
  }

  return {
    ipExpression,
    portExpression,
    timeoutMs: readPositiveInt("timeoutMs", "超时时间"),
    threadCount: readPositiveInt("threadCount", "线程数"),
  };
}

function renderSummary(summary) {
  const items = [
    ["总任务", summary.totalTasks],
    ["开放", summary.openPorts],
    ["关闭", summary.closedPorts],
    ["超时", summary.timeoutPorts],
    ["主机数", summary.hostCount],
    ["端口数", summary.portCount],
    ["耗时", `${Number(summary.elapsedSeconds).toFixed(2)} 秒`],
  ];

  summaryCards.innerHTML = items.map(([label, value]) => `
    <div class="summary-item">
      <strong>${value}</strong>
      <span>${label}</span>
    </div>
  `).join("");
  summaryCards.className = "summary-grid";
}

function renderResults(results) {
  if (!results || results.length === 0) {
    resultList.innerHTML = `
      <div class="empty-state">
        未发现开放端口。关闭和超时端口已计入扫描摘要。
      </div>
    `;
    return;
  }

  resultList.innerHTML = results.map((result) => {
    const endpoint = `${result.ip}:${result.port}`;
    const service = result.detectedService || result.service || "Unknown";
    const version = result.version ? ` (${escapeHtml(result.version)})` : "";
    const method = result.method ? ` [${escapeHtml(result.method)}]` : "";
    const portGuess = result.portGuess && result.portGuess !== service
      ? `<div class="result-meta">端口猜测：${escapeHtml(result.portGuess)}</div>`
      : "";
    const banner = result.banner
      ? `<div class="banner">Banner: ${escapeHtml(result.banner)}</div>`
      : "";

    return `
      <article class="result-card">
        <div class="result-main">
          <span class="open-pill">OPEN</span>
          <span class="endpoint">${escapeHtml(endpoint)}</span>
          <span class="service-name">${escapeHtml(service)}${version}${method}</span>
        </div>
        <div class="result-meta">耗时 ${result.timeMs} ms</div>
        ${portGuess}
        ${banner}
      </article>
    `;
  }).join("");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function runScan(event) {
  event.preventDefault();

  let payload;
  try {
    payload = readFormData();
  } catch (error) {
    setStatus("输入错误", "error");
    showMessage(error.message, "error");
    return;
  }

  setBusy(true);
  setStatus("扫描中", "scanning");
  showMessage("扫描进行中，请稍候...");
  summaryCards.className = "summary-grid hidden";
  resultList.innerHTML = `<div class="empty-state">正在等待扫描结果...</div>`;

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

    setStatus("扫描完成", "done");
    hideMessage();
    renderSummary(data.summary);
    renderResults(data.openResults);
  } catch (error) {
    setStatus("扫描失败", "error");
    showMessage(`扫描失败：${error.message}`, "error");
    resultList.innerHTML = `
      <div class="empty-state">
        请检查输入参数或确认本地服务仍在运行。
      </div>
    `;
  } finally {
    setBusy(false);
  }
}

async function loadServices() {
  try {
    const response = await fetch("/api/services");
    const data = await response.json();
    serviceList.innerHTML = data.services.map((service) => `
      <span class="service-chip">${service.port} ${escapeHtml(service.name)}</span>
    `).join("");
  } catch {
    serviceList.textContent = "常见端口加载失败。";
  }
}

document.querySelectorAll("[data-ports]").forEach((button) => {
  button.addEventListener("click", () => {
    portInput.value = button.dataset.ports;
    portInput.focus();
  });
});

form.addEventListener("submit", runScan);
clearButton.addEventListener("click", clearResults);

clearResults();
loadServices();
