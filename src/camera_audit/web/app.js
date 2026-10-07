(() => {
  "use strict";
  const token = document.querySelector('meta[name="camera-audit-token"]').content;
  const $ = (id) => document.getElementById(id);
  let selectedMode = null;
  let renderedResultsKey = null;
  let resultsLoading = false;
  let resultsPage = 1;
  let totalPages = 1;
  let shownPromptId = null;
  let modalOpen = false;
  let closed = false;
  let latestState = null;

  async function request(path, body) {
    const options = {headers: {"X-Camera-Audit-Token": token}, cache: "no-store"};
    if (body !== undefined) {
      options.method = "POST";
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    if (!response.ok) {
      let data = {};
      try { data = await response.json(); } catch (_) { /* Use a generic error. */ }
      throw new Error(data.error || `Request failed (${response.status}).`);
    }
    return response;
  }

  function showError(message) {
    $("activity").classList.remove("hidden");
    $("activity").classList.add("error");
    $("activity").classList.remove("working");
    $("activity-title").textContent = "Could not continue";
    $("activity-detail").textContent = message;
  }

  function chooseMode(mode) {
    if (latestState && ["scanning", "working", "waiting_for_input"].includes(latestState.phase)) return;
    selectedMode = mode;
    $("mode-scan").setAttribute("aria-pressed", String(mode === "scan"));
    $("mode-watch").setAttribute("aria-pressed", String(mode === "scan_watch"));
    $("target-panel").classList.remove("hidden");
    $("target-heading").textContent = mode === "scan" ? "Scan a network" : "Scan, then choose a camera";
    $("start-scan").textContent = mode === "scan" ? "Start scan →" : "Start scan + watch →";
    $("target-panel").scrollIntoView({behavior: "smooth", block: "nearest"});
  }

  function field(label, type, value = "") {
    const wrap = document.createElement("div");
    const id = `modal-field-${Math.random().toString(36).slice(2)}`;
    const caption = document.createElement("label");
    caption.htmlFor = id;
    caption.textContent = label;
    const input = document.createElement("input");
    input.id = id;
    input.type = type;
    input.autocomplete = "off";
    input.value = value;
    wrap.append(caption, input);
    return {wrap, input};
  }

  function modal(config) {
    modalOpen = true;
    const body = $("modal-body");
    body.replaceChildren();
    $("modal-kicker").textContent = config.kicker || "YOUR APPROVAL";
    $("modal-title").textContent = config.title || "Confirm action";
    $("modal-message").textContent = config.message || "";
    $("modal-error").classList.add("hidden");
    $("modal-confirm").textContent = config.confirmText || "Continue";
    let read = () => true;

    if (config.kind === "exact") {
      const item = field(`Type ${config.cidr} to authorize this lab target`, "text");
      body.append(item.wrap);
      read = () => item.input.value.trim();
      setTimeout(() => item.input.focus(), 30);
    } else if (config.kind === "credentials") {
      const username = field("Username", "text", config.username || "");
      const password = field("Password", "password");
      body.append(username.wrap, password.wrap);
      read = () => ({username: username.input.value.trim(), password: password.input.value});
      setTimeout(() => username.input.focus(), 30);
    } else if (config.kind === "manual_url") {
      const item = field("RTSP URL", "text");
      item.input.placeholder = "rtsp://192.168.1.20:554/live";
      body.append(item.wrap);
      read = () => item.input.value.trim();
      setTimeout(() => item.input.focus(), 30);
    } else if (config.kind === "choose") {
      let selected = null;
      for (const [index, option] of config.options.entries()) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "modal-option";
        button.textContent = option;
        button.addEventListener("click", () => {
          selected = index;
          body.querySelectorAll(".modal-option").forEach((entry) => entry.classList.remove("selected"));
          button.classList.add("selected");
        });
        body.append(button);
      }
      read = () => selected;
    }

    $("modal-backdrop").classList.remove("hidden");
    const finish = async (cancelled) => {
      let answer = cancelled ? null : read();
      if (!cancelled && config.kind === "exact" && answer !== config.cidr) {
        $("modal-error").textContent = "The CIDR must match the target exactly.";
        $("modal-error").classList.remove("hidden");
        return;
      }
      if (!cancelled && config.kind === "choose" && answer === null) {
        $("modal-error").textContent = "Select one option or cancel.";
        $("modal-error").classList.remove("hidden");
        return;
      }
      if (!cancelled && config.kind === "credentials" && (!answer.username || !answer.password)) {
        $("modal-error").textContent = "Enter both a username and password.";
        $("modal-error").classList.remove("hidden");
        return;
      }
      if (config.kind === "confirm") answer = !cancelled;
      $("modal-confirm").disabled = true;
      $("modal-cancel").disabled = true;
      try {
        await config.submit(answer, cancelled);
        body.replaceChildren();
        $("modal-backdrop").classList.add("hidden");
        modalOpen = false;
      } catch (error) {
        $("modal-error").textContent = error.message;
        $("modal-error").classList.remove("hidden");
      } finally {
        $("modal-confirm").disabled = false;
        $("modal-cancel").disabled = false;
      }
    };
    $("modal-confirm").onclick = () => finish(false);
    $("modal-cancel").onclick = () => finish(true);
  }

  async function startScan() {
    if (!selectedMode) return;
    try {
      const response = await request("/api/target", {cidr: $("cidr").value});
      const target = await response.json();
      modal({
        kind: target.non_private ? "exact" : "confirm",
        cidr: target.cidr,
        kicker: "SCAN AUTHORIZATION",
        title: "Confirm your scan",
        message: `Target: ${target.cidr}. The scan checks live hosts and the top 1,000 TCP ports with light service detection. Continue only if you are authorized to test this range.`,
        confirmText: "Authorize & start",
        submit: async (answer, cancelled) => {
          if (cancelled) return;
          await request("/api/scan", {mode: selectedMode, cidr: target.cidr,
                                       confirmation: target.non_private ? answer : "yes"});
          renderedResultsKey = null;
          resultsPage = 1;
          $("candidates-only").checked = false;
          $("results").classList.add("hidden");
          await refresh();
        }
      });
    } catch (error) { showError(error.message); }
  }

  function tag(text) {
    const item = document.createElement("span");
    item.className = "chip";
    item.textContent = text;
    return item;
  }

  function renderHost(host, mode) {
    const card = document.createElement("article");
    card.className = "host-card";
    const content = document.createElement("div");
    const title = document.createElement("div");
    title.className = "host-title";
    const ip = document.createElement("strong");
    ip.textContent = host.ip;
    title.append(ip);
    if (host.hostname) {
      const name = document.createElement("span");
      name.textContent = host.hostname;
      title.append(name);
    }
    if (host.camera_candidate) {
      const badge = document.createElement("span");
      badge.className = "candidate-badge";
      badge.textContent = "CAMERA CANDIDATE";
      title.append(badge);
    }
    content.append(title);
    const meta = document.createElement("div");
    meta.className = "host-meta";
    if (host.mac_vendor) meta.append(tag(host.mac_vendor));
    for (const port of host.ports || []) meta.append(tag(`${port.port}/${port.protocol || "tcp"} ${port.service || "unknown"}`));
    if (!(host.ports || []).length) meta.append(tag("No open TCP ports found"));
    content.append(meta);
    if ((host.camera_evidence || []).length) {
      const evidence = document.createElement("p");
      evidence.className = "host-evidence";
      evidence.textContent = `Camera evidence: ${host.camera_evidence.join(" · ")}`;
      content.append(evidence);
    }
    const findings = document.createElement("div");
    findings.className = "finding-list";
    for (const finding of host.vulnerabilities || []) {
      const line = document.createElement("div");
      line.className = "finding";
      const link = document.createElement("a");
      link.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(finding.id)}`;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = finding.id;
      line.append(link, document.createTextNode(` · possible impact · CVSS ${finding.score ?? "?"}`));
      findings.append(line);
    }
    content.append(findings);
    const nvdStatus = {
      no_versioned_cpe: "NVD: no versioned CPE was identified",
      offline_unavailable: "NVD: no cached lookup is available",
      lookup_unavailable: "NVD: lookup unavailable",
      stale_cache: "NVD: showing cached results"
    }[host.nvd_status];
    if (nvdStatus) {
      const note = document.createElement("p");
      note.className = "host-evidence";
      note.textContent = nvdStatus;
      content.append(note);
    }
    card.append(content);
    if (mode === "scan_watch" && host.camera_candidate) {
      const button = document.createElement("button");
      button.className = "secondary-button watch-button";
      button.type = "button";
      button.textContent = "Watch camera →";
      button.addEventListener("click", async () => {
        try { await request("/api/watch", {ip: host.ip}); await refresh(); }
        catch (error) { showError(error.message); }
      });
      card.append(button);
    }
    return card;
  }

  async function renderResults(state) {
    if (!state.scan_id || resultsLoading) return;
    const key = `${state.scan_id}:${resultsPage}:${$("candidates-only").checked}`;
    if (key === renderedResultsKey) return;
    resultsLoading = true;
    let data;
    try {
      const params = new URLSearchParams({page: String(resultsPage),
        candidates: $("candidates-only").checked ? "1" : "0"});
      data = await (await request(`/api/results?${params}`)).json();
    } finally { resultsLoading = false; }
    if (data.scan_id !== latestState.scan_id || key !== `${data.scan_id}:${resultsPage}:${$("candidates-only").checked}`) return;
    renderedResultsKey = key;
    totalPages = data.total_pages;
    $("results").classList.remove("hidden");
    $("results-subtitle").textContent = `${data.cidr} · ${new Date(data.created_at).toLocaleString()} · Findings are evidence for testing.`;
    $("stat-hosts").textContent = data.total_hosts;
    $("stat-cameras").textContent = data.total_candidates;
    $("stat-findings").textContent = data.total_findings;
    $("results-range").textContent = `${data.first}–${data.last} of ${data.candidates_only ? data.total_candidates : data.total_hosts} devices`;
    $("results-pages").classList.toggle("hidden", totalPages <= 1);
    $("page-label").textContent = `Page ${data.page} of ${totalPages}`;
    $("previous-page").disabled = data.page <= 1;
    $("next-page").disabled = data.page >= totalPages;
    const list = $("host-list");
    list.replaceChildren();
    if (!data.hosts.length) {
      const empty = document.createElement("p");
      empty.className = "hint";
      empty.textContent = data.candidates_only ? "No camera candidates were found in this scan." : "No live hosts were found in this scan.";
      list.append(empty);
    } else {
      for (const host of data.hosts) list.append(renderHost(host, state.mode));
      if (state.mode === "scan_watch" && data.total_candidates === 0) {
        const note = document.createElement("p");
        note.className = "hint";
        note.textContent = "No camera candidates were found. Review the inventory above or scan another authorized network.";
        list.prepend(note);
      }
    }
  }

  function renderPrompt(prompt) {
    if (!prompt || prompt.id === shownPromptId || modalOpen) return;
    shownPromptId = prompt.id;
    modal({
      kind: prompt.kind,
      kicker: prompt.kind === "credentials" ? "CAMERA AUTHENTICATION" : "CAMERA INSPECTION",
      title: {confirm: "Confirm camera action", choose: "Choose an endpoint", credentials: "Camera credentials", manual_url: "Manual stream URL"}[prompt.kind],
      message: prompt.message,
      options: prompt.options || [],
      username: prompt.username || "",
      confirmText: prompt.kind === "confirm" ? "Yes, continue" : "Continue",
      submit: async (answer) => { await request("/api/respond", {id: prompt.id, answer}); await refresh(); }
    });
  }

  async function refresh() {
    if (closed) return;
    const state = await (await request("/api/state")).json();
    latestState = state;
    if (state.network && !$("cidr").dataset.initialized) {
      $("cidr").value = state.network.cidr;
      $("cidr").dataset.initialized = "true";
      $("network-hint").textContent = `Detected ${state.network.address} on ${state.network.interface}. Edit the range if needed.`;
    } else if (state.network_error && !$("cidr").dataset.initialized) {
      $("cidr").dataset.initialized = "true";
      $("network-hint").textContent = `${state.network_error} Enter an authorized CIDR manually.`;
    }
    const busy = ["scanning", "cancelling", "working", "waiting_for_input"].includes(state.phase);
    $("mode-scan").disabled = busy;
    $("mode-watch").disabled = busy;
    $("start-scan").disabled = busy;
    $("quit").disabled = busy;
    $("cancel-scan").classList.toggle("hidden", !["scanning", "cancelling"].includes(state.phase));
    $("cancel-scan").disabled = state.phase === "cancelling";
    document.querySelectorAll(".watch-button").forEach((button) => { button.disabled = busy; });
    $("activity").classList.toggle("hidden", state.phase === "ready" && !state.error);
    $("activity").classList.toggle("working", busy);
    $("activity").classList.toggle("error", Boolean(state.error));
    $("activity-title").textContent = state.error ? "Could not continue" :
      state.phase === "scan_complete" ? "Scan complete" :
      state.phase === "waiting_for_input" ? "Your input is needed" :
      state.phase === "watch_complete" ? "Camera session complete" :
      state.phase === "watch_failed" ? "Camera session ended" :
      state.phase === "cancelled" ? "Scan cancelled" :
      state.phase === "cancelling" ? "Stopping scan" :
      state.phase === "scanning" ? "Scanning network" : "Working";
    $("activity-detail").textContent = state.error || state.message;
    await renderResults(state);
    if (state.prompt) renderPrompt(state.prompt);
  }

  async function poll() {
    if (closed) return;
    try { await refresh(); } catch (error) { showError(error.message); }
    if (!closed) setTimeout(poll, 850);
  }

  $("mode-scan").addEventListener("click", () => chooseMode("scan"));
  $("mode-watch").addEventListener("click", () => chooseMode("scan_watch"));
  $("start-scan").addEventListener("click", startScan);
  $("candidates-only").addEventListener("change", () => {
    resultsPage = 1;
    if (latestState) renderResults(latestState).catch((error) => showError(error.message));
  });
  $("previous-page").addEventListener("click", () => {
    if (resultsPage > 1) resultsPage--;
    if (latestState) renderResults(latestState).catch((error) => showError(error.message));
  });
  $("next-page").addEventListener("click", () => {
    if (resultsPage < totalPages) resultsPage++;
    if (latestState) renderResults(latestState).catch((error) => showError(error.message));
  });
  $("cancel-scan").addEventListener("click", async () => {
    try { await request("/api/cancel", {}); await refresh(); }
    catch (error) { showError(error.message); }
  });
  $("download").addEventListener("click", async () => {
    try {
      const response = await request("/api/report");
      const objectUrl = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = `scan-${latestState.scan_id}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    } catch (error) { showError(error.message); }
  });
  $("quit").addEventListener("click", async () => {
    try {
      await request("/api/quit", {});
      closed = true;
      document.body.replaceChildren();
      const message = document.createElement("main");
      message.className = "closed-message";
      message.textContent = "Camera Audit has closed. You can close this tab.";
      document.body.append(message);
    } catch (error) { showError(error.message); }
  });
  poll();
})();
