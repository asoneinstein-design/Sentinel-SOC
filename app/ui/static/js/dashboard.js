let currentIncidentId = null;
let refreshHandle = null;
let loadingIncident = false;

/* =========================================================
   CORE API
========================================================= */

async function api(url, options = {}) {
    const response = await fetch(url, options);
    let payload = null;
    try { payload = await response.json(); } catch (_) {}

    if (!response.ok) {
        const message = payload?.detail || payload?.message || `HTTP ${response.status}: ${response.statusText}`;
        throw new Error(message);
    }
    return payload;
}

function escapeHTML(value) {
    const div = document.createElement("div");
    div.textContent = String(value ?? "");
    return div.innerHTML;
}

function time(value) {
    if (!value) return "--";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return "--";
    return parsed.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function humanSource(source) {
    const map = {
        nids: "NIDS",
        server_logs: "SERVER LOGS",
        cve: "CVE INTELLIGENCE",
        network: "NETWORK"
    };
    return map[source] || String(source || "UNKNOWN").toUpperCase();
}

function normalizeResult(value) {
    return String(value ?? "").toUpperCase();
}

function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = String(value ?? "");
}

function statusTone(value) {
    const normalized = normalizeResult(value);
    if (["SUCCESS", "RESOLVED", "ISOLATED", "BLOCKED", "CONTAINED"].includes(normalized)) return "good";
    if (["FAILURE", "FAILED", "ACTIVE", "EXPOSED", "OPEN"].includes(normalized)) return "bad";
    if (["PENDING", "ADAPTING", "REPLANNING", "UNKNOWN"].includes(normalized)) return "warn";
    return "neutral";
}

function evidenceTitle(item) {
    switch (item?.source) {
        case "nids": return ["Suspicious SMB activity", "High-severity network detection"];
        case "server_logs": return ["Privileged authentication", "Admin authentication with suspicious process context"];
        case "cve": return ["Critical vulnerability match", "Vulnerability intelligence correlated with the asset"];
        case "network": return ["Active network session", "Live source → target communication observed"];
        default: return [item?.tool || "Evidence record", "Collected by the investigation toolchain"];
    }
}

function showToast(message, tone = "info") {
    const stack = document.getElementById("toast-stack");
    if (!stack) return;
    const toast = document.createElement("div");
    toast.className = `toast ${tone}`;
    toast.textContent = message;
    stack.appendChild(toast);
    setTimeout(() => toast.remove(), 3600);
}

/* =========================================================
   CLOCK / HEADER
========================================================= */

function updateClock() {
    setText("clock", new Date().toLocaleTimeString([], {
        hour: "2-digit", minute: "2-digit", second: "2-digit"
    }));
}
setInterval(updateClock, 1000);
updateClock();

function renderProvider(detail) {
    const provider = detail?.incident?.provider || detail?.incident?.llm_provider || detail?.provider || "local";
    const node = document.getElementById("agent-provider");
    if (!node) return;
    node.innerHTML = `<span class="provider-dot"></span>AGENT <strong>${escapeHTML(String(provider).toUpperCase())}</strong>`;
}

/* =========================================================
   INCIDENT QUEUE
========================================================= */

async function loadIncidentQueue() {
    const incidents = await api("/api/incidents");
    setText("incident-count", incidents.length);

    const container = document.getElementById("incident-list");
    if (!container) return;
    container.innerHTML = "";

    if (!incidents.length) {
        container.innerHTML = `<div class="side-loading">No incidents available.</div>`;
        return;
    }

    for (const incident of incidents.slice(0, 12)) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = `incident-card-small${incident.incident_id === currentIncidentId ? " selected" : ""}`;

        const dotClass = incident.status === "RESOLVED" ? "resolved" : "active";
        button.innerHTML = `
            <div class="small-incident-status">
                <span class="queue-dot ${dotClass}"></span>
                ${escapeHTML(incident.status || "UNKNOWN")}
            </div>
            <div class="small-incident-id">${escapeHTML(incident.incident_id)}</div>
            <div class="small-incident-goal">${escapeHTML(incident.goal || "No goal recorded")}</div>
        `;
        button.addEventListener("click", () => selectIncident(incident.incident_id));
        container.appendChild(button);
    }
}

function selectIncident(incidentId) {
    currentIncidentId = incidentId;
    const url = new URL(window.location.href);
    url.searchParams.set("incident", incidentId);
    window.history.replaceState({}, "", url);
    loadIncident(incidentId, { quiet: false });
}

/* =========================================================
   HEADER / METRICS
========================================================= */

function renderHeader(incident) {
    const title = incident?.title || incident?.name || "Suspicious SMB compromise";
    setText("incident-title", title);
    setText("incident-goal", incident?.goal || "Evidence-grounded investigation and containment.");
    setText("incident-id", incident?.incident_id || "—");
    setText("alert-id", incident?.trigger_alert_id || "—");

    const host = incident?.host_id || incident?.host || "FILE-01";
    const ip = incident?.target_ip || incident?.ip || "10.0.0.15";
    setText("incident-host", host);
    setText("incident-ip", ip);

    const statusNode = document.getElementById("incident-status");
    if (statusNode) {
        statusNode.textContent = incident?.status || "UNKNOWN";
        statusNode.className = `resolution-status ${incident?.status === "RESOLVED" ? "resolved" : "active"}`;
    }
    setText("resolution-sub", incident?.status === "RESOLVED" ? "Containment independently verified" : "Awaiting verified containment");
    renderProvider({ incident });
}

function renderMetrics(dashboard, detail) {
    const metrics = dashboard?.metrics || {};
    const evidence = detail?.evidence || [];
    const actions = detail?.actions || [];
    const verifications = detail?.verifications || [];

    const evidenceCount = metrics.evidence_count ?? evidence.length;
    const actionCount = metrics.action_count ?? actions.length;
    const verificationCount = metrics.verification_count ?? verifications.length;

    const successChecks = verifications.filter(v => normalizeResult(v.result) === "SUCCESS").length;
    const successRate = metrics.success_rate ?? (verificationCount ? Math.round((successChecks / verificationCount) * 100) : 0);

    setText("evidence-count", evidenceCount);
    setText("action-count", actionCount);
    setText("verification-count", verificationCount);

    const confidence = metrics.confidence ?? (evidence.length >= 4 ? "HIGH" : evidence.length >= 2 ? "MEDIUM" : "FORMING");
    const confidenceNode = document.getElementById("confidence");
    if (confidenceNode) {
        let displayConfidence = confidence;

        if (typeof confidence === "number" && Number.isFinite(confidence)) {
            // Support both normalized values (0.94) and percentage values (94).
            displayConfidence = confidence <= 1
                ? Math.round(confidence * 100)
                : Math.round(confidence);
        }

        confidenceNode.textContent =
            typeof displayConfidence === "number"
                ? `${displayConfidence}%`
                : String(displayConfidence).toUpperCase();

        confidenceNode.className = `metric-main ${statusTone(displayConfidence)}`;
    }
    setText(
        "confidence-detail",
        typeof confidence === "number"
            ? "stored reasoning confidence"
            : "evidence strength"
    );

    const outcome = detail?.incident?.status || "PENDING";
    const outcomeNode = document.getElementById("metric-outcome");
    if (outcomeNode) {
        outcomeNode.textContent = outcome;
        outcomeNode.className = `metric-main ${outcome === "RESOLVED" ? "good" : "warn"}`;
    }
    setText("metric-outcome-detail", `${successRate}% verification success`);
}

/* =========================================================
   ATTACK PATH
========================================================= */

function renderThreatPath(detail) {
    const container = document.getElementById("threat-path");
    if (!container) return;

    const evidence = detail?.evidence || [];
    const sources = new Set(evidence.map(item => item.source));
    const verifications = detail?.verifications || [];
    const failed = verifications.some(v => normalizeResult(v.result) === "FAILURE");
    const verified = verifications.some(v => v.method === "verify_host_isolation" && normalizeResult(v.result) === "SUCCESS");

    const node = (icon, title, subtitle, tone) => `
        <div class="graph-node ${tone || ""}">
            <div class="graph-icon">${icon}</div>
            <div class="graph-copy"><strong>${title}</strong><span>${subtitle}</span></div>
        </div>`;
    const link = `<div class="graph-link">→</div>`;

    const html = [
        node("N", "NIDS", sources.has("nids") ? "alert correlated" : "awaiting alert", sources.has("nids") ? "active" : ""),
        link,
        node("L", "SERVER LOGS", sources.has("server_logs") ? "host evidence" : "awaiting logs", sources.has("server_logs") ? "active" : ""),
        link,
        node("C", "CVE", sources.has("cve") ? "vulnerability match" : "awaiting match", sources.has("cve") ? "active" : ""),
        link,
        node("↔", "NETWORK", sources.has("network") ? "live activity" : "awaiting activity", failed ? "failure" : (sources.has("network") ? "active" : "")),
        link,
        node("✓", "CONTAINMENT", verified ? "verified response" : (failed ? "adaptation required" : "response pending"), verified ? "success" : (failed ? "failure" : ""))
    ].join("");

    container.innerHTML = html;
    setText("threat-state", verified ? "VERIFIED" : (failed ? "ADAPTING" : "TRACKING"));
}

/* =========================================================
   EVIDENCE
========================================================= */

function renderEvidence(evidence) {
    const container = document.getElementById("evidence-list");
    if (!container) return;
    container.innerHTML = "";
    setText("evidence-state", `${evidence.length} SOURCES`);

    if (!evidence.length) {
        container.innerHTML = `<div class="empty-state" style="padding:18px">No evidence collected.</div>`;
        return;
    }

    evidence.forEach(item => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "evidence-item";
        const [title, detail] = evidenceTitle(item);
        button.innerHTML = `
            <div class="evidence-source">${escapeHTML(humanSource(item.source))}</div>
            <div class="evidence-copy">
                <strong>${escapeHTML(title)}</strong>
                <span>${escapeHTML(detail)}</span>
            </div>`;
        button.addEventListener("click", () => openEvidence(item));
        container.appendChild(button);
    });
}

function openEvidence(item) {
    const modal = document.getElementById("evidence-modal");
    const content = document.getElementById("evidence-modal-content");
    if (!modal || !content) return;
    setText("modal-source", humanSource(item?.source));
    setText("modal-title", item?.tool || "Evidence details");
    content.textContent = JSON.stringify(item?.result ?? item?.raw_result ?? item ?? {}, null, 2);
    modal.classList.add("active");
    modal.setAttribute("aria-hidden", "false");
}

function closeEvidenceModal() {
    const modal = document.getElementById("evidence-modal");
    if (!modal) return;
    modal.classList.remove("active");
    modal.setAttribute("aria-hidden", "true");
}

document.addEventListener("keydown", event => {
    if (event.key === "Escape") closeEvidenceModal();
});

/* =========================================================
   HYPOTHESIS
========================================================= */

function renderHypothesis(detail) {
    const container = document.getElementById("hypothesis");
    if (!container) return;

    const evidence = detail?.evidence || [];
    const storedHypotheses = detail?.hypotheses || detail?.hypothesis || [];
    const hypothesisArray = Array.isArray(storedHypotheses) ? storedHypotheses : [storedHypotheses];
    const stored = hypothesisArray.filter(Boolean).slice(-1)[0];

    const hasAllSources = ["nids", "server_logs", "cve", "network"].every(source => evidence.some(item => item.source === source));
    const derivedStatement = hasAllSources
        ? "Likely active SMB compromise against FILE-01"
        : "Threat hypothesis forming from available evidence";
    const derivedText = hasAllSources
        ? "Network, authentication, vulnerability and live-traffic evidence correlate around the same host and support an active compromise hypothesis."
        : "The investigation has not yet accumulated every expected evidence source."

    const statement = stored?.statement || stored?.text || derivedStatement;
    const confidenceRaw = stored?.confidence ?? (hasAllSources ? 94 : 55);
    const numericConfidence = typeof confidenceRaw === "number" ? Math.max(0, Math.min(100, confidenceRaw)) : null;
    const confidenceLabel = numericConfidence !== null
        ? `${numericConfidence}%`
        : String(confidenceRaw).toUpperCase();
    const confidenceWidth = numericConfidence !== null ? numericConfidence : (String(confidenceRaw).toUpperCase() === "HIGH" ? 94 : 55);

    setText("hypothesis-state", String(stored?.status || (hasAllSources ? "HIGH CONFIDENCE" : "FORMING")).toUpperCase());

    let supportingRaw =
        stored?.supporting_evidence_ids ??
        stored?.supportingEvidenceIds ??
        stored?.supporting_evidence_ids_json ??
        [];

    let supportingIds = [];

    if (Array.isArray(supportingRaw)) {
        supportingIds = supportingRaw;
    } else if (typeof supportingRaw === "string") {
        try {
            const parsed = JSON.parse(supportingRaw);
            supportingIds = Array.isArray(parsed) ? parsed : [];
        } catch (_) {
            supportingIds = [];
        }
    }

    let supportingSources = supportingIds.map(id => {
        const matchedEvidence = evidence.find(
            item => String(item?.id) === String(id)
        );
        return matchedEvidence ? humanSource(matchedEvidence.source) : String(id);
    });

    // If the API does not expose evidence IDs, fall back to the actual
    // evidence records already returned for this incident.
    if (!supportingSources.length) {
        supportingSources = ["nids", "server_logs", "cve", "network"]
            .filter(source => evidence.some(item => item.source === source))
            .map(humanSource);
    }

    supportingSources = [...new Set(supportingSources)];

    const chips = supportingSources.length
        ? supportingSources
            .slice(0, 6)
            .map(source => `<span class="hypothesis-chip">${escapeHTML(source)}</span>`)
            .join("")
        : `<span class="hypothesis-chip">NO SUPPORTING EVIDENCE RECORDED</span>`;

    container.innerHTML = `
        <div class="hypothesis-title">${escapeHTML(statement)}</div>
        <div class="hypothesis-text">${escapeHTML(stored?.reason || stored?.description || (stored ? "Stored by the incident reasoning layer." : derivedText))}</div>
        <div class="hypothesis-meta"><span>CONFIDENCE</span><strong>${escapeHTML(confidenceLabel)}</strong></div>
        <div class="confidence-bar"><div class="confidence-fill" style="width:${confidenceWidth}%"></div></div>
        <div class="hypothesis-evidence">
            <div class="hypothesis-evidence-label">SUPPORTING EVIDENCE</div>
            <div class="hypothesis-chip-row">${chips}</div>
        </div>
        ${stored ? "" : `<div class="derived-note">Derived presentation only — no stored hypothesis object was exposed by this response.</div>`}
    `;
}

/* =========================================================
   CONTAINMENT
========================================================= */

function renderContainment(detail) {
    const container = document.getElementById("containment");
    if (!container) return;

    const actions = detail?.actions || [];
    const verifications = detail?.verifications || [];
    const firewall = actions.some(a => a.action_type === "firewall_block");
    const quarantine = actions.some(a => a.action_type === "quarantine_host");
    const failure = verifications.some(v => normalizeResult(v.result) === "FAILURE");
    const verified = verifications.some(v => v.method === "verify_host_isolation" && normalizeResult(v.result) === "SUCCESS");

    const step = (num, tone, title, detailText) => `
        <div class="containment-step">
            <div class="step-top"><span class="step-badge ${tone}">${tone === "done" ? "✓" : tone === "failed" ? "!" : tone === "adapt" ? "↻" : num}</span><strong>${title}</strong></div>
            <span class="detail">${detailText}</span>
        </div>`;

    container.innerHTML = `
        ${step("1", firewall ? "done" : "", "Source IP containment", firewall ? "Initial firewall action executed." : "No firewall action recorded.")}
        ${step("2", failure ? "failed" : (firewall ? "done" : ""), "Verification", failure ? "Containment failed — remaining traffic detected." : (firewall ? "Response check completed." : "Pending response verification."))}
        ${step("3", quarantine ? "done" : (failure ? "adapt" : ""), "Adaptive response", quarantine ? "FILE-01 quarantine action executed." : (failure ? "Agent escalated to host quarantine." : "Awaiting escalation decision."))}
        ${step("4", verified ? "done" : "", "Final verification", verified ? "Host isolation independently verified." : "Deterministic verifier has not confirmed isolation.")}
        <div class="containment-final ${verified ? "success" : failure ? "failure" : ""}">${verified ? "✓ CONTAINMENT VERIFIED" : failure ? "! RESPONSE INSUFFICIENT — ADAPTATION REQUIRED" : "AWAITING VERIFIED RESPONSE"}</div>
    `;
    setText("containment-state", verified ? "VERIFIED" : failure ? "ADAPTING" : "MONITORING");
}

/* =========================================================
   TIMELINE / AGENT TRACE
========================================================= */

function eventTone(event) {
    const title = String(event?.title || "").toUpperCase();
    const result = normalizeResult(event?.result);
    if (result === "FAILURE") return "failure";
    if (result === "SUCCESS") return "success";
    if (title.includes("ADAPTING") || title.includes("REPLANNING")) return "adaptation";
    return "normal";
}

function renderTimeline(timeline = []) {
    const container = document.getElementById("timeline");
    if (!container) return;
    container.innerHTML = "";

    if (!timeline.length) {
        container.innerHTML = `<div class="empty-state">No timeline events recorded.</div>`;
        return;
    }

    timeline.forEach((event, index) => {
        const item = document.createElement("div");
        const tone = eventTone(event);
        item.className = `timeline-item ${tone}`;
        item.innerHTML = `
            <div class="timeline-marker">${index + 1}</div>
            <div class="timeline-content">
                <div class="timeline-top"><span>${escapeHTML(event.type || "event")}</span><span>${time(event.timestamp)}</span></div>
                <strong>${escapeHTML(event.title || "Incident event")}</strong>
                <span>${escapeHTML(event.description || "No description recorded.")}</span>
                <button type="button" class="timeline-inspect">INSPECT</button>
                <div class="timeline-more" hidden>
                    <div>Trigger: <strong>${escapeHTML(event.triggered_by || event.tool || event.type || "—")}</strong></div>
                    ${event.target ? `<div>Target: <strong>${escapeHTML(event.target)}</strong></div>` : ""}
                    ${event.result ? `<div>Result: <strong>${escapeHTML(event.result)}</strong></div>` : ""}
                </div>
            </div>`;

        const inspect = item.querySelector(".timeline-inspect");
        const more = item.querySelector(".timeline-more");
        inspect.addEventListener("click", () => {
            more.hidden = !more.hidden;
            inspect.textContent = more.hidden ? "INSPECT" : "HIDE";
        });
        container.appendChild(item);
    });
}

function renderAgentFeed(timeline = []) {
    const container = document.getElementById("agent-feed");
    if (!container) return;
    container.innerHTML = "";

    const interesting = timeline.filter(event => ["state_transition", "action", "verification"].includes(event.type));
    if (!interesting.length) {
        container.innerHTML = `<div class="empty-state" style="padding:18px">No agent trace events recorded.</div>`;
        return;
    }

    interesting.forEach(event => {
        const tone = eventTone(event);
        let actor = "ORCHESTRATOR";
        if (event.type === "action") actor = "AGENT DECISION";
        if (event.type === "verification") actor = "DETERMINISTIC VERIFIER";
        if (String(event.title || "").toUpperCase().includes("REPLANNING")) actor = "REPLANNER";

        const item = document.createElement("div");
        item.className = `agent-event ${tone}`;
        item.innerHTML = `
            <div class="agent-event-header"><span>${actor}</span><time>${time(event.timestamp)}</time></div>
            <strong>${escapeHTML(event.title || event.type || "Agent event")}</strong>
            <p>${escapeHTML(event.description || "No description recorded.")}</p>
        `;
        container.appendChild(item);
    });
}

/* =========================================================
   ENVIRONMENT / OUTCOME
========================================================= */

function setBadge(id, value) {
    const node = document.getElementById(id);
    if (!node) return;
    node.textContent = value;
    node.className = `state-badge ${statusTone(value)}`;
}

function renderEnvironment(detail) {
    const actions = detail?.actions || [];
    const verifications = detail?.verifications || [];
    const incident = detail?.incident || {};

    const firewall = actions.some(a => a.action_type === "firewall_block");
    const isolated = verifications.some(v => v.method === "verify_host_isolation" && normalizeResult(v.result) === "SUCCESS");
    const hadFailure = verifications.some(v => normalizeResult(v.result) === "FAILURE");
    const blockedSources = new Set();

    actions.filter(a => a.action_type === "firewall_block").forEach(a => {
        const target = a.target || a?.tool_call?.target || a?.tool_call?.args?.ip;
        if (target) blockedSources.add(target);
    });

    setBadge("host-state", isolated ? "ISOLATED" : "PENDING");
    setBadge("host-isolated", isolated ? "ISOLATED" : "EXPOSED");
    setText("host-name", incident.host_id || incident.host || "FILE-01");
    setBadge("firewall-state", firewall ? "BLOCKED" : "OPEN");
    setBadge("network-connections", isolated ? "NONE" : (hadFailure ? "ACTIVE" : "TRACKED"));
    setBadge("network-blocked", blockedSources.size ? `${blockedSources.size} SOURCE${blockedSources.size > 1 ? "S" : ""}` : "NONE");
}

function renderFinal(incident, detail) {
    const verifications = detail?.verifications || [];
    const verified = verifications.some(v => v.method === "verify_host_isolation" && normalizeResult(v.result) === "SUCCESS");
    const failed = verifications.some(v => normalizeResult(v.result) === "FAILURE");
    const icon = document.getElementById("final-icon");

    if (icon) {
        icon.textContent = verified ? "✓" : failed ? "!" : "…";
        icon.className = `final-icon ${verified ? "success" : failed ? "failure" : "warning"}`;
    }

    setText("final-title", verified ? "Containment verified" : failed ? "Initial response insufficient" : "Containment pending");
    setText("final-text", verified
        ? `${incident?.host_id || incident?.host || "FILE-01"} is isolated and the active threat path has been contained.`
        : failed
            ? "The verifier observed remaining activity, so the response must adapt before the incident can be resolved."
            : "The incident has not yet reached a verified containment state.");
    setText("final-host", verified ? "ISOLATED" : "EXPOSED");
    setText("final-network", verified ? "NONE" : "ACTIVE");
    setText("final-threat", verified ? "CONTAINED" : "ACTIVE");
}

/* =========================================================
   OPERATIONS
========================================================= */

async function executeOperation(operation, target, button = null) {
    if (!target || !String(target).trim()) {
        showToast("A valid operation target is required.", "error");
        return;
    }

    const pretty = operation === "firewall_block" ? "block source" : "quarantine host";
    const confirmed = window.confirm(`Execute ${pretty} on ${target}?`);
    if (!confirmed) return;

    if (button) {
        button.disabled = true;
        button.dataset.originalText = button.textContent;
        button.textContent = "EXECUTING…";
    }

    try {
        const data = await api("/api/tools/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ operation, target })
        });
        showToast(`Operation completed: ${data?.operation || operation} → ${data?.target || target}`, "success");
        await refreshDashboard();
    } catch (error) {
        console.error("Operation error:", error);
        showToast(`Operation failed: ${error.message}`, "error");
    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = button.dataset.originalText || "EXECUTE";
        }
    }
}

function runOperationFromUI(operation, inputId, button) {
    const input = document.getElementById(inputId);
    executeOperation(operation, input?.value?.trim(), button);
}

/* =========================================================
   INCIDENT LOAD / REFRESH
========================================================= */

async function loadIncident(incidentId, { quiet = false } = {}) {
    if (!incidentId || loadingIncident) return;
    loadingIncident = true;

    try {
        const detail = await api(`/api/incidents/${encodeURIComponent(incidentId)}`);
        const dashboard = await api(`/api/dashboard/${encodeURIComponent(incidentId)}`);
        const timeline = await api(`/api/incidents/${encodeURIComponent(incidentId)}/timeline`);

        renderHeader(detail?.incident || {});
        renderMetrics(dashboard, detail);
        renderThreatPath(detail);
        renderEvidence(detail?.evidence || []);
        renderHypothesis(detail);
        renderContainment(detail);
        renderAgentFeed(Array.isArray(timeline) ? timeline : []);
        renderTimeline(Array.isArray(timeline) ? timeline : []);
        renderEnvironment(detail);
        renderFinal(detail?.incident || {}, detail);
        await loadIncidentQueue();

        if (!quiet) showToast(`Loaded incident ${incidentId}`, "info");
    } catch (error) {
        console.error("Incident load failed:", error);
        showToast(`Incident load failed: ${error.message}`, "error");
        throw error;
    } finally {
        loadingIncident = false;
    }
}

async function refreshDashboard() {
    try {
        if (!currentIncidentId) {
            await initialize();
            return;
        }
        await loadIncident(currentIncidentId, { quiet: true });
    } catch (_) {}
}

async function initialize() {
    try {
        const params = new URLSearchParams(window.location.search);
        const requested = params.get("incident");
        const incidents = await api("/api/incidents");

        if (!incidents.length) {
            throw new Error("No incidents available.");
        }

        currentIncidentId = requested && incidents.some(i => i.incident_id === requested)
            ? requested
            : incidents[0].incident_id;

        await loadIncident(currentIncidentId, { quiet: true });

        if (refreshHandle) clearInterval(refreshHandle);
        refreshHandle = setInterval(() => refreshDashboard(), 5000);
    } catch (error) {
        console.error(error);
        document.body.insertAdjacentHTML("beforeend", `<div class="fatal-error">Sentinel dashboard error:<br>${escapeHTML(error.message)}</div>`);
    }
}

window.executeOperation = executeOperation;
window.runOperationFromUI = runOperationFromUI;
window.refreshDashboard = refreshDashboard;
window.closeEvidenceModal = closeEvidenceModal;

initialize();
