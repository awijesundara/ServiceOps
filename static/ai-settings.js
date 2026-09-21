/* Admin > AI assistance: services, sharing rules and the privacy tester. DOM nodes only, no innerHTML. */
(function () {
  "use strict";

  const root = document.querySelector("[data-ai-admin]");
  if (!root) return;
  const csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  const data = JSON.parse(document.getElementById("ai-data").textContent);
  const $ = function (name, scope) { return (scope || root).querySelector("[data-ai-" + name + "]"); };
  const cards = $("cards"), empty = $("empty"), dialog = $("dialog"), form = $("form");
  let services = data.services.slice();

  const PROVIDER_NAMES = { self_hosted: "Your own server", openai_compatible: "Hosted service", openai: "OpenAI", anthropic: "Claude" };
  const STATUS = { ready: "Working", untested: "Not tested yet", failing: "Not responding", off: "Paused" };
  const FIXED = { openai: true, anthropic: true };

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function call(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body || {})
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (json) {
        if (!response.ok) throw new Error(json.error || "Something went wrong. Please try again.");
        return json;
      });
    });
  }

  /* ---------- service cards ---------- */

  function button(label, handler, cls) {
    const node = el("button", cls || "button", label);
    node.type = "button";
    node.addEventListener("click", handler);
    return node;
  }

  function card(service) {
    const node = el("article", "aiadm-card" + (service.enabled ? "" : " is-off"));
    const top = el("div", "aiadm-card-top");
    top.appendChild(el("h3", "", service.name));
    top.appendChild(el("span", "ai-route-chip is-" + (service.external ? "external" : "private"), service.external ? "Outside" : "Private"));
    node.appendChild(top);
    node.appendChild(el("p", "aiadm-card-sub", (PROVIDER_NAMES[service.provider] || service.provider) + " · " + (service.model || "no model")));
    const status = el("p", "aiadm-status is-" + service.status);
    status.appendChild(el("span", "aiadm-dot"));
    status.appendChild(document.createTextNode(STATUS[service.status] || service.status));
    node.appendChild(status);
    const load = el("div", "aiadm-load");
    const bar = el("progress");
    bar.max = service.max_concurrency; bar.value = Math.min(service.load, service.max_concurrency);
    bar.setAttribute("aria-label", "Busy: " + service.load + " of " + service.max_concurrency);
    load.appendChild(bar);
    load.appendChild(el("span", "muted", service.load ? "Busy " + service.load + "/" + service.max_concurrency : "Free"));
    node.appendChild(load);
    if (service.context) node.appendChild(el("p", "muted aiadm-fine", "Remembers about " + service.context.toLocaleString() + " tokens"));
    const note = el("p", "aiadm-testnote", "");
    note.setAttribute("role", "status");
    node.appendChild(note);
    const actions = el("div", "aiadm-card-actions");
    actions.appendChild(button("Test", function () { test(service, note); }));
    actions.appendChild(button("Edit", function () { openDialog(service); }));
    actions.appendChild(button(service.enabled ? "Pause" : "Use", function () {
      call("/admin/ai/services", { id: service.id, enabled: !service.enabled }).then(replace).catch(function (e) { note.textContent = e.message; });
    }));
    const remove = button("Remove", function () {
      if (!remove.dataset.armed) {
        remove.dataset.armed = "1"; remove.textContent = "Confirm remove";
        remove.setAttribute("aria-label", "Confirm removing " + service.name);
        setTimeout(function () {
          delete remove.dataset.armed; remove.textContent = "Remove"; remove.setAttribute("aria-label", "Remove " + service.name);
        }, 4000);
        return;
      }
      call("/admin/ai/services/" + encodeURIComponent(service.id) + "/delete").then(function () {
        services = services.filter(function (s) { return s.id !== service.id; });
        draw(); preview();
      }).catch(function (e) { note.textContent = e.message; });
    }, "button danger-quiet");
    remove.setAttribute("aria-label", "Remove " + service.name);
    actions.appendChild(remove);
    node.appendChild(actions);
    return node;
  }

  function draw() {
    cards.textContent = "";
    services.forEach(function (service) { cards.appendChild(card(service)); });
    empty.hidden = services.length > 0;
  }

  function replace(json) {
    const updated = json.service;
    services = services.filter(function (s) { return s.id !== "legacy"; }); // an unmigrated single setup becomes a real service
    const index = services.findIndex(function (s) { return s.id === updated.id; });
    if (index === -1) services.push(updated); else services[index] = updated;
    draw(); preview();
  }

  function test(service, note) {
    note.textContent = "Testing…";
    note.classList.remove("is-bad");
    call("/admin/ai/services/" + encodeURIComponent(service.id) + "/test").then(function (json) {
      note.textContent = json.message + " (" + (json.ms / 1000).toFixed(1) + "s)";
      note.classList.toggle("is-bad", !json.ok);
      const index = services.findIndex(function (s) { return s.id === service.id; });
      services[index] = json.service;
      const status = note.parentNode.querySelector(".aiadm-status");
      if (status) { status.className = "aiadm-status is-" + json.service.status; status.lastChild.textContent = STATUS[json.service.status]; }
    }).catch(function (e) { note.textContent = e.message; note.classList.add("is-bad"); });
  }

  /* ---------- add / edit dialog ---------- */

  const f = function (name) { return dialog.querySelector('[data-ai-f="' + name + '"]'); };
  const dStatus = $("detect-status", dialog), dError = $("dialog-error", dialog);
  const stepPick = dialog.querySelector('[data-ai-step="pick"]'), stepDetails = dialog.querySelector('[data-ai-step="details"]');
  let timer = null;

  function showStep(name) {
    stepPick.hidden = name !== "pick";
    stepDetails.hidden = name !== "details";
  }

  function syncProvider() {
    const fixed = Boolean(FIXED[f("provider").value]);
    dialog.querySelector('[data-ai-row="endpoint"]').hidden = fixed;
    $("where", dialog).textContent = f("provider").value === "self_hosted"
      ? "This service runs on your own network. Requests to it never leave your organization."
      : "This service is hosted outside your organization. Sensitive requests are never sent to it.";
  }

  function fillDetails(service, defaults) {
    dError.hidden = true;
    dStatus.textContent = "Enter the details, then connect.";
    dStatus.classList.remove("is-error");
    $("models", dialog).textContent = "";
    f("token").value = "";
    f("api_key").value = "";
    const s = service || {};
    f("id").value = s.id || "";
    f("provider").value = s.provider || defaults.provider;
    f("name").value = s.name || defaults.name || "";
    f("endpoint").value = s.endpoint !== undefined && service ? s.endpoint : (defaults.endpoint || "");
    f("model").value = s.model || "";
    f("priority").value = s.priority || 100;
    f("weight").value = s.weight || 1;
    f("max_concurrency").value = s.max_concurrency || 1;
    f("enabled").checked = service ? s.enabled : true;
    $("keyhint", dialog).textContent = service && s.has_key ? "A key is saved. Leave blank to keep it." : "Leave blank if the server needs none.";
    $("dialog-title", dialog).textContent = service ? "Edit " + s.name : "Add an AI service";
    syncProvider();
  }

  function openDialog(service) {
    if (service) { fillDetails(service, {}); showStep("details"); } else { showStep("pick"); }
    if (!dialog.open) dialog.showModal();
    if (service) f("name").focus();
  }

  root.querySelector("[data-ai-add]").addEventListener("click", function () { $("dialog-title", dialog).textContent = "Add an AI service"; openDialog(null); });
  dialog.querySelectorAll("[data-ai-preset]").forEach(function (b) {
    b.addEventListener("click", function () {
      const p = b.dataset.aiPreset.split("|");
      fillDetails(null, { provider: p[0], endpoint: p[1], name: p[2] || (PROVIDER_NAMES[p[0]] || "") });
      showStep("details");
      (FIXED[p[0]] ? f("api_key") : f("endpoint")).focus();
    });
  });
  $("back", dialog).addEventListener("click", function () { showStep("pick"); });

  function detect() {
    dStatus.classList.remove("is-error");
    dStatus.textContent = "Connecting…";
    call("/admin/ai/models", {
      provider: f("provider").value, endpoint: f("endpoint").value, api_key: f("api_key").value, service_id: f("id").value,
      model: f("model").value, external_consent: true
    }).then(function (json) {
      const list = $("models", dialog);
      list.textContent = "";
      json.models.forEach(function (name) { const o = document.createElement("option"); o.value = name; list.appendChild(o); });
      if (!f("model").value || json.models.indexOf(f("model").value) === -1) f("model").value = json.models[0];
      f("token").value = json.discovery_token || "";
      if (!f("name").value) f("name").value = f("model").value.slice(0, 60);
      const context = (json.context || {})[f("model").value];
      let message = "Connected. Found " + json.models.length + (json.models.length === 1 ? " model." : " models.");
      if (context) message += " It remembers about " + context.toLocaleString() + " tokens.";
      dStatus.textContent = message;
    }).catch(function (e) { dStatus.textContent = e.message; dStatus.classList.add("is-error"); });
  }
  $("detect", dialog).addEventListener("click", detect);
  function auto() {
    clearTimeout(timer);
    const fixed = FIXED[f("provider").value];
    const ready = fixed ? f("api_key").value.length > 8 : /^https?:\/\/[^\s/]+/i.test(f("endpoint").value) && !/HOST/.test(f("endpoint").value);
    if (ready && !f("model").value) timer = setTimeout(detect, 1200);
  }
  f("endpoint").addEventListener("input", auto);
  f("api_key").addEventListener("input", auto);
  f("model").addEventListener("input", function () { f("token").value = ""; });

  $("save", dialog).addEventListener("click", function () {
    dError.hidden = true;
    const body = {
      id: f("id").value || undefined, name: f("name").value, provider: f("provider").value, endpoint: f("endpoint").value,
      model: f("model").value, api_key: f("api_key").value, discovery_token: f("token").value,
      priority: Number(f("priority").value), weight: Number(f("weight").value), max_concurrency: Number(f("max_concurrency").value),
      enabled: f("enabled").checked
    };
    call("/admin/ai/services", body).then(function (json) { replace(json); dialog.close(); }).catch(function (e) {
      dError.textContent = e.message; dError.hidden = false;
    });
  });

  /* ---------- live check of the rules ---------- */

  const verdict = $("verdict"), tryInput = $("try"), tryKind = $("try-kind");
  let previewTimer = null;

  function settings() {
    const on = function (name) { const n = form.elements[name]; return Boolean(n && n.checked); };
    const value = function (name) { const n = form.elements[name]; return n ? n.value : ""; };
    return {
      routing_mode: value("routing_mode"), external_scope: value("external_scope"), external_consent: on("external_consent"),
      detect_personal: on("detect_personal"), detect_credentials: on("detect_credentials"), detect_financial: on("detect_financial"),
      sensitive_terms: value("sensitive_terms")
    };
  }

  function preview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(function () {
      const text = tryInput.value.trim();
      if (!text) { verdict.textContent = "Type something above to check it."; verdict.className = "aiadm-verdict"; return; }
      call("/admin/ai/preview", Object.assign(settings(), { text: text, kinds: [tryKind.value] })).then(function (json) {
        verdict.textContent = "";
        const names = json.eligible.map(function (e) { return e.name + (e.external ? " (outside)" : ""); });
        if (json.blocked) {
          verdict.className = "aiadm-verdict is-blocked";
          verdict.textContent = (json.sensitive ? "Sensitive: " + json.reasons.join(", ") + ". " : "") + "No service may handle this. " + json.blocked;
        } else if (json.sensitive) {
          verdict.className = "aiadm-verdict is-private";
          verdict.textContent = "Sensitive (" + json.reasons.join(", ") + "). Stays on your own AI: " + names.join(", ") + ".";
        } else {
          verdict.className = "aiadm-verdict is-ok";
          verdict.textContent = "Not sensitive. Could be answered by: " + names.join(", ") + ".";
        }
      }).catch(function (e) { verdict.textContent = e.message; verdict.className = "aiadm-verdict is-blocked"; });
    }, 350);
  }
  tryInput.addEventListener("input", preview);
  tryKind.addEventListener("change", preview);
  form.querySelectorAll("[data-ai-live]").forEach(function (n) { n.addEventListener("change", preview); n.addEventListener("input", preview); });

  draw();
})();
