// Dashboard logic: start a scan, poll its status, render results from the JSON reports.
const $ = (id) => document.getElementById(id);
const STAGES = ["validating", "scanning", "analysing", "completed"];
const LEVELS = ["Critical", "High", "Medium", "Low", "Informational"];
let pollTimer = null;

// Small helper that builds elements with textContent (safe: never inserts raw HTML).
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(url, options) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed (" + response.status + ")");
  return data;
}

function showError(message) {
  const box = $("form-error");
  box.textContent = message || "";
  box.hidden = !message;
}

function paintStages(stage, status) {
  const current = STAGES.indexOf(stage);
  document.querySelectorAll("#stages li").forEach((li) => {
    const index = STAGES.indexOf(li.dataset.stage);
    li.className = "";
    if (status === "completed") li.className = "done";
    else if (status === "failed") li.className = index < current || current === -1 ? "" : (index === current ? "failed" : "");
    else if (index < current) li.className = "done";
    else if (index === current) li.className = "active";
  });
  if (status === "failed" && stage === "failed") {
    document.querySelectorAll("#stages li").forEach((li) => (li.className = ""));
  }
}

async function poll() {
  try {
    const s = await api("/api/status");
    $("status-message").textContent = s.message;
    $("t-status").textContent = s.status.charAt(0).toUpperCase() + s.status.slice(1);
    if (s.target) $("t-target").textContent = s.target;
    paintStages(s.stage, s.status);
    if (s.status === "running") return;
    clearInterval(pollTimer);
    pollTimer = null;
    $("scan-btn").disabled = false;
    await loadResults();
  } catch (err) {
    clearInterval(pollTimer);
    pollTimer = null;
    $("scan-btn").disabled = false;
    $("status-message").textContent = "Lost contact with the server: " + err.message;
  }
}

function renderSeverity(summary) {
  const box = $("severity");
  box.replaceChildren();
  LEVELS.forEach((level) => {
    const chip = el("span", "chip sev-" + level.toLowerCase(), level);
    chip.appendChild(el("b", "", String((summary && summary[level]) || 0)));
    box.appendChild(chip);
  });
}

function renderPorts(ports) {
  const body = $("ports-body");
  body.replaceChildren();
  if (!ports.length) {
    const row = el("tr");
    const cell = el("td", "empty", "No open ports found.");
    cell.colSpan = 6;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  ports.forEach((p) => {
    const row = el("tr");
    row.appendChild(el("td", "num", String(p.port)));
    [p.protocol, p.state, p.service || "unknown", p.product || "-", p.version || "-"]
      .forEach((value) => row.appendChild(el("td", "", value)));
    body.appendChild(row);
  });
}

function addField(list, label, value) {
  list.appendChild(el("dt", "", label));
  list.appendChild(el("dd", "", value));
}

function renderFindings(findings) {
  const box = $("findings");
  box.replaceChildren();
  if (!findings.length) {
    box.appendChild(el("p", "empty", "No findings. Nothing in the scan data suggested a security concern."));
    return;
  }
  findings.forEach((f) => {
    const card = el("article", "finding sev-" + f.severity.toLowerCase());
    const title = el("h3");
    title.appendChild(el("span", "badge", f.severity));
    title.appendChild(document.createTextNode(f.title));
    card.appendChild(title);
    card.appendChild(el("p", "meta", f.id + " | " + f.protocol + "/" + f.affected_port + " " + f.service +
      " | Confidence: " + f.confidence));
    const list = el("dl");
    addField(list, "Evidence", f.evidence);
    addField(list, "Why it matters", f.description);
    addField(list, "Recommended action", f.recommendation);
    card.appendChild(list);
    box.appendChild(card);
  });
}

async function loadResults() {
  const data = await api("/api/results");
  const ports = data.port_scan, vulns = data.vulnerabilities;
  if (!ports || !vulns) return;
  const meta = ports.scan_metadata;
  $("t-target").textContent = meta.target;
  $("t-time").textContent = meta.scan_time.replace("T", " ");
  $("t-status").textContent = meta.status.charAt(0).toUpperCase() + meta.status.slice(1);
  $("t-ports").textContent = ports.ports.length;
  $("t-services").textContent = ports.ports.filter((p) => p.service && p.service !== "unknown").length;
  $("t-findings").textContent = vulns.findings.length;
  renderSeverity(vulns.scan_metadata.severity_summary);
  renderPorts(ports.ports);
  renderFindings(vulns.findings);
}

$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("");
  const target = $("target").value.trim();
  if (!target) return showError("Enter a target IP address or hostname.");
  if (!$("authorized").checked) return showError("Tick the box to confirm you are authorized to scan this target.");
  $("scan-btn").disabled = true;
  try {
    await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target, authorized: true }),
    });
    pollTimer = setInterval(poll, 1000);
    poll();
  } catch (err) {
    showError(err.message);
    $("scan-btn").disabled = false;
  }
});

document.querySelectorAll("button[data-view]").forEach((button) => {
  button.addEventListener("click", async () => {
    const view = $("json-view");
    try {
      const response = await fetch("/files/" + button.dataset.view);
      if (!response.ok) throw new Error("File not created yet. Run a scan first.");
      view.textContent = JSON.stringify(await response.json(), null, 2);
    } catch (err) {
      view.textContent = err.message;
    }
    view.hidden = false;
  });
});

renderSeverity({});
loadResults().catch(() => {});
