// Email content is attacker-controlled, so everything below is rendered with
// textContent (never innerHTML) to make script injection through an email impossible.
(() => {
  const $ = (id) => document.getElementById(id);
  const MAX_BYTES = 2 * 1024 * 1024;
  const LEVEL_LABEL = { LOW: "Low risk", MEDIUM: "Medium risk", HIGH: "High risk" };

  const textarea = $("emailText");
  const analyzeBtn = $("analyzeBtn");
  const errorBox = $("error");

  // Small DOM helper: h("li", {class: "x", text: "hello"}, [children])
  function h(tag, opts = {}, children = []) {
    const node = document.createElement(tag);
    if (opts.class) node.className = opts.class;
    if (opts.text !== undefined) node.textContent = opts.text;
    children.forEach((c) => node.appendChild(c));
    return node;
  }

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = !msg;
  }

  async function loadSample(name) {
    showError("");
    try {
      const res = await fetch(`/sample/${encodeURIComponent(name)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not load sample.");
      textarea.value = data.email;
      analyze();
    } catch (err) {
      showError(err.message);
    }
  }

  async function readFile(file) {
    showError("");
    const ext = file.name.toLowerCase().split(".").pop();
    if (!["eml", "txt"].includes(ext)) return showError("Only .eml or .txt files are supported.");
    if (file.size > MAX_BYTES) return showError("File is larger than 2 MB.");
    textarea.value = await file.text();
  }

  async function analyze() {
    showError("");
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing…";
    try {
      const res = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: textarea.value }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Analysis failed.");
      render(data);
    } catch (err) {
      showError(err.message);
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = "Analyze email";
    }
  }

  function render(r) {
    const level = r.risk_level.toLowerCase();
    const report = $("report");
    report.dataset.level = level;
    $("empty").hidden = true;
    report.hidden = false;

    const notice = $("notice");
    notice.textContent = r.notice || "";
    notice.hidden = !r.notice;

    $("scoreNum").textContent = r.risk_score;
    $("levelText").textContent = LEVEL_LABEL[r.risk_level];
    $("verdictText").textContent = r.verdict;
    $("recText").textContent = r.recommendation;

    // Ruler marker: start at 0, then slide to the score (one-time reveal).
    const marker = $("marker");
    marker.style.left = "0%";
    requestAnimationFrame(() => requestAnimationFrame(() => {
      marker.style.left = `${Math.min(Math.max(r.risk_score, 1), 99)}%`;
    }));

    const cap = $("capNote");
    cap.hidden = r.raw_score <= r.risk_score;
    cap.textContent = `Findings added up to ${r.raw_score} points; the score is capped at 100.`;

    // Email details
    const meta = $("meta");
    meta.replaceChildren();
    [["From", r.email.from], ["Reply-To", r.email.reply_to], ["Return-Path", r.email.return_path],
     ["Subject", r.email.subject], ["Date", r.email.date],
     ["Attachments", r.email.attachments.join(", ")]]
      .filter(([, v]) => v)
      .forEach(([k, v]) => meta.append(h("dt", { text: k }), h("dd", { text: v })));

    // Findings
    $("findCount").textContent = r.findings.length ? `(${r.findings.length})` : "";
    const list = $("findings");
    list.replaceChildren();
    if (!r.findings.length) list.append(h("li", { class: "none", text: "No suspicious findings." }));
    r.findings.forEach((f) => {
      const body = h("div", {}, [h("h4", { text: f.title }), h("p", { text: f.detail })]);
      if (f.evidence.length) {
        body.append(h("div", { class: "evidence" }, f.evidence.slice(0, 4).map((e) => h("code", { text: e }))));
      }
      list.append(h("li", {}, [h("div", { class: "wt", text: `+${f.weight}` }), body]));
    });

    // URLs and indicators
    const urls = $("urls");
    urls.replaceChildren(...(r.urls.length ? r.urls.map((u) => h("li", { text: u.url })) : [h("li", { class: "none", text: "No links found." })]));
    const chips = $("indicators");
    chips.replaceChildren(...(r.indicators.length ? r.indicators.map((i) => h("li", { text: i })) : [h("li", { class: "none", text: "None" })]));

    report.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ----- wiring -----
  analyzeBtn.addEventListener("click", analyze);
  $("fileBtn").addEventListener("click", () => $("fileInput").click());
  $("fileInput").addEventListener("change", (e) => e.target.files[0] && readFile(e.target.files[0]));
  $("clearBtn").addEventListener("click", () => {
    textarea.value = "";
    $("fileInput").value = "";
    showError("");
    $("report").hidden = true;
    $("empty").hidden = false;
    $("notice").hidden = true;
  });
  document.querySelectorAll("[data-sample]").forEach((b) =>
    b.addEventListener("click", () => loadSample(b.dataset.sample)));
})();
