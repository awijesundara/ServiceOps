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

  const PROVIDER_NAMES = { self_hosted: tr("Your own server"), openai_compatible: tr("Hosted service"), openai: "OpenAI", anthropic: "Claude" };
  const STATUS = { ready: tr("Working"), untested: tr("Not tested yet"), failing: tr("Not responding"), off: tr("Paused") };
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
        if (!response.ok) throw new Error(json.error || tr("Something went wrong. Please try again."));
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
    top.appendChild(el("span", "ai-route-chip is-" + (service.external ? "external" : "private"), service.external ? tr("Outside") : tr("Private")));
    node.appendChild(top);
    node.appendChild(el("p", "aiadm-card-sub", (PROVIDER_NAMES[service.provider] || service.provider) + " · " + (service.model || tr("no model"))));
    const status = el("p", "aiadm-status is-" + service.status);
    status.appendChild(el("span", "aiadm-dot"));
    status.appendChild(document.createTextNode(STATUS[service.status] || service.status));
    node.appendChild(status);
    const load = el("div", "aiadm-load");
    const bar = el("progress");
    bar.max = service.max_concurrency; bar.value = Math.min(service.load, service.max_concurrency);
    bar.setAttribute("aria-label", tr("Busy: {load} of {limit}", { load: service.load, limit: service.max_concurrency }));
    load.appendChild(bar);
    load.appendChild(el("span", "muted", service.load ? tr("Busy {load}/{limit}", { load: service.load, limit: service.max_concurrency }) : tr("Free")));
    node.appendChild(load);
    const tierName = { lite: tr("Fast model"), standard: tr("Balanced model"), pro: tr("Advanced model") }[service.tier];
    if (tierName) node.appendChild(el("p", "muted aiadm-fine", tierName));
    const box = service.allowance;
    if (box) {
      const wrap = el("div", "aiadm-allow" + (box.ok ? "" : " is-used"));
      const line = function (label, used, limit) {
        if (limit === null || limit === undefined) return;
        const row = el("div", "aiadm-allow-row");
        row.appendChild(el("span", "", tr("{period}: {used} of {limit}", { period: label, used: used.toLocaleString(), limit: limit.toLocaleString() })));
        const bar = el("progress"); bar.max = Math.max(1, limit); bar.value = Math.min(used, limit);
        bar.setAttribute("aria-label", tr("{period}: {used} of {limit}", { period: label, used: used, limit: limit }));
        row.appendChild(bar);
        wrap.appendChild(row);
      };
      line(tr("Today"), box.rpd_used, service.limits.rpd);
      line(tr("This minute"), box.rpm_used, service.limits.rpm);
      if (!box.ok) {
        const when = box.reason === "none" ? tr("No allowance on this plan") : box.reason === "day"
          ? tr("Used up for today, back in about {hours} h", { hours: Math.max(1, Math.round(box.resets_in / 3600)) })
          : tr("Busy, back in about {seconds} s", { seconds: box.wait });
        wrap.appendChild(el("p", "aiadm-allow-note", when));
      }
      node.appendChild(wrap);
    }
    const today = service.today || { requests: 0, tokens: 0 };
    node.appendChild(el("p", "muted aiadm-fine", (today.requests === 1
      ? tr("Today: {count} request · {tokens} tokens", { count: today.requests, tokens: today.tokens.toLocaleString() })
      : tr("Today: {count} requests · {tokens} tokens", { count: today.requests, tokens: today.tokens.toLocaleString() }))));
    if (service.context) node.appendChild(el("p", "muted aiadm-fine", tr("Remembers about {tokens} tokens", { tokens: service.context.toLocaleString() })));
    const note = el("p", "aiadm-testnote", "");
    note.setAttribute("role", "status");
    node.appendChild(note);
    const actions = el("div", "aiadm-card-actions");
    actions.appendChild(button(tr("Test"), function () { test(service, note); }));
    actions.appendChild(button(tr("Edit"), function () { openDialog(service); }));
    actions.appendChild(button(service.enabled ? tr("Pause") : tr("Use"), function () {
      call("/admin/ai/services", { id: service.id, enabled: !service.enabled }).then(replace).catch(function (e) { note.textContent = e.message; });
    }));
    const remove = button(tr("Remove"), function () {
      if (!remove.dataset.armed) {
        remove.dataset.armed = "1"; remove.textContent = tr("Confirm remove");
        remove.setAttribute("aria-label", tr("Confirm removing {name}", { name: service.name }));
        setTimeout(function () {
          delete remove.dataset.armed; remove.textContent = tr("Remove"); remove.setAttribute("aria-label", tr("Remove {name}", { name: service.name }));
        }, 4000);
        return;
      }
      call("/admin/ai/services/" + encodeURIComponent(service.id) + "/delete").then(function () {
        services = services.filter(function (s) { return s.id !== service.id; });
        draw(); preview();
      }).catch(function (e) { note.textContent = e.message; });
    }, "button danger-quiet");
    remove.setAttribute("aria-label", tr("Remove ") + service.name);
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
    note.textContent = tr("Testing…");
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
  let timer = null, limitsTouched = false, quotas = {};
  const bulk = dialog.querySelector("[data-ai-bulk]"), bulkList = dialog.querySelector("[data-ai-bulk-list]");
  const NOT_CHAT = /(embed|tts|image|imagen|veo|aqa|audio|transcri|live|robotics|lyria|omni|computer-use|deep-research|antigravity)/i;

  function updatePresetButton() {
    const preset = quotas[f("model").value];
    const button = $("use-preset", dialog);
    button.hidden = !preset;
    $("preset-note", dialog).textContent = preset ? (preset.rpd_limit === 0 ? tr("Google lists no free-tier allowance for this model.") : "") : "";
    if (preset && !limitsTouched && !f("rpd").value && !f("rpm").value) applyPreset(false);
  }

  function applyPreset(touch) {
    const preset = quotas[f("model").value];
    if (!preset) return;
    f("rpm").value = preset.rpm_limit; f("tpm").value = preset.tpm_limit; f("rpd").value = preset.rpd_limit; f("tz").value = preset.quota_tz;
    limitsTouched = touch !== false;
  }

  ["rpm", "tpm", "rpd", "tz"].forEach(function (name) { f(name).addEventListener("input", function () { limitsTouched = true; }); });
  $("use-preset", dialog).addEventListener("click", function () { applyPreset(true); });

  function showStep(name) {
    stepPick.hidden = name !== "pick";
    stepDetails.hidden = name !== "details";
  }

  function syncProvider() {
    const fixed = Boolean(FIXED[f("provider").value]);
    dialog.querySelector('[data-ai-row="endpoint"]').hidden = fixed;
    $("where", dialog).textContent = f("provider").value === "self_hosted"
      ? tr("This service runs on your own network. Requests to it never leave your organization.")
      : tr("This service is hosted outside your organization. Sensitive requests are never sent to it.");
  }

  function syncProxy() {
    dialog.querySelector('[data-ai-row="proxy_url"]').hidden = f("proxy_mode").value !== "custom";
  }

  function fillDetails(service, defaults) {
    dError.hidden = true;
    dStatus.textContent = tr("Enter the details, then connect.");
    dStatus.classList.remove("is-error");
    allModels = [];
    closeList();
    $("model-hint", dialog).textContent = tr("Connect first to see every model, or type a name.");
    f("token").value = "";
    f("api_key").value = "";
    const s = service || {};
    f("proxy_mode").value = s.proxy_mode || "default";
    f("proxy_url").value = "";
    f("id").value = s.id || "";
    f("provider").value = s.provider || defaults.provider;
    f("name").value = s.name || defaults.name || "";
    f("endpoint").value = s.endpoint !== undefined && service ? s.endpoint : (defaults.endpoint || "");
    f("model").value = s.model || "";
    f("priority").value = s.priority || 100;
    f("weight").value = s.weight || 1;
    f("max_concurrency").value = s.max_concurrency || 1;
    f("enabled").checked = service ? s.enabled : true;
    const lim = s.limits || {};
    f("rpm").value = lim.rpm === null || lim.rpm === undefined ? "" : lim.rpm;
    f("tpm").value = lim.tpm === null || lim.tpm === undefined ? "" : lim.tpm;
    f("rpd").value = lim.rpd === null || lim.rpd === undefined ? "" : lim.rpd;
    f("tz").value = lim.tz || "UTC";
    limitsTouched = Boolean(service);
    quotas = {};
    bulk.hidden = true;
    bulkList.textContent = "";
    updatePresetButton();
    $("keyhint", dialog).textContent = service && s.has_key ? tr("A key is saved. Leave blank to keep it.") : tr("Leave blank if the server needs none.");
    $("proxyhint", dialog).textContent = service && s.has_proxy
      ? tr("A proxy is saved. Leave blank to keep it. Credentials are never shown again.")
      : tr("Credentials are encrypted and are never shown again.");
    $("dialog-title", dialog).textContent = service ? tr("Edit {name}", { name: s.name }) : tr("Add an AI service");
    syncProvider();
    syncProxy();
  }

  function openDialog(service) {
    if (service) { fillDetails(service, {}); showStep("details"); } else { showStep("pick"); }
    if (!dialog.open) dialog.showModal();
    if (service) f("name").focus();
  }

  root.querySelector("[data-ai-add]").addEventListener("click", function () { $("dialog-title", dialog).textContent = tr("Add an AI service"); openDialog(null); });
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
    dStatus.textContent = tr("Connecting…");
    call("/admin/ai/models", {
      provider: f("provider").value, endpoint: f("endpoint").value, api_key: f("api_key").value, service_id: f("id").value,
      model: f("model").value, external_consent: true,
      proxy_mode: f("proxy_mode").value, proxy_url: f("proxy_url").value
    }).then(function (json) {
      allModels = json.models.slice();
      quotas = json.quotas || {};
      // Offer the other models on the same account: each has its own allowance, so together they go further.
      bulkList.textContent = "";
      const extra = json.models.filter(function (name) { return name !== f("model").value && quotas[name] && quotas[name].rpd_limit > 0 && !NOT_CHAT.test(name); }).slice(0, 12);
      extra.forEach(function (name, index) {
        const li = el("li", "");
        const label = el("label", "aiadm-switch");
        const box = document.createElement("input");
        box.type = "checkbox"; box.value = name; box.checked = index < 4;
        label.appendChild(box);
        const text = el("span", "");
        text.appendChild(el("strong", "", name));
        text.appendChild(el("small", "", tr("{daily} requests a day, {minute} a minute", { daily: quotas[name].rpd_limit.toLocaleString(), minute: quotas[name].rpm_limit })));
        label.appendChild(text);
        li.appendChild(label);
        bulkList.appendChild(li);
      });
      bulk.hidden = extra.length === 0 || Boolean(f("id").value);
      $("model-hint", dialog).textContent = tr("{count} models found. Click the box to see them all, or type to search.", { count: json.models.length });
      if (!f("model").value || json.models.indexOf(f("model").value) === -1) f("model").value = json.models[0];
      f("token").value = json.discovery_token || "";
      if (!f("name").value) f("name").value = f("model").value.slice(0, 60);
      const context = (json.context || {})[f("model").value];
      let message = json.models.length === 1 ? tr("Connected. Found {count} model.", { count: json.models.length })
        : tr("Connected. Found {count} models.", { count: json.models.length });
      if (context) message += " " + tr("It remembers about {tokens} tokens.", { tokens: context.toLocaleString() });
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
  f("proxy_mode").addEventListener("change", syncProxy);

  /* ---------- searchable model list: every model, filtered as you type ---------- */
  let allModels = [], activeIndex = -1;
  const modelList = $("model-list", dialog), modelBox = f("model");

  function closeList() { modelList.hidden = true; modelBox.setAttribute("aria-expanded", "false"); activeIndex = -1; }

  function openList(filter) {
    const needle = (filter || "").trim().toLowerCase();
    const shown = allModels.filter(function (name) { return !needle || name.toLowerCase().indexOf(needle) !== -1; });
    modelList.textContent = "";
    shown.forEach(function (name, index) {
      const item = el("li", "aiadm-model-item" + (name === modelBox.value ? " is-current" : ""), name);
      item.id = "ai-model-opt-" + index;
      item.dataset.model = name;
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", name === modelBox.value ? "true" : "false");
      if (index === 0 && !needle && /latest/i.test(name)) item.appendChild(el("span", "aiadm-model-tag", tr("suggested")));
      item.addEventListener("mousedown", function (event) { event.preventDefault(); choose(name); });
      modelList.appendChild(item);
    });
    if (!shown.length) modelList.appendChild(el("li", "aiadm-model-none", allModels.length ? tr("No model matches. You can still use what you typed.") : tr("Connect first to list models.")));
    modelList.hidden = false;
    modelBox.setAttribute("aria-expanded", "true");
    activeIndex = -1;
  }

  function choose(name) {
    modelBox.value = name;
    updatePresetButton();
    if (!f("name").value) f("name").value = name.slice(0, 60);
    closeList();
  }

  function highlight(index) {
    const items = modelList.querySelectorAll(".aiadm-model-item");
    if (!items.length) return;
    activeIndex = (index + items.length) % items.length;
    items.forEach(function (item, i) { item.classList.toggle("is-active", i === activeIndex); });
    modelBox.setAttribute("aria-activedescendant", items[activeIndex].id);
    items[activeIndex].scrollIntoView({ block: "nearest" });
  }

  modelBox.addEventListener("focus", function () { if (allModels.length) openList(""); });
  modelBox.addEventListener("click", function () { if (allModels.length && modelList.hidden) openList(""); });
  modelBox.addEventListener("input", function () { openList(modelBox.value); });
  modelBox.addEventListener("blur", closeList);
  modelBox.addEventListener("keydown", function (event) {
    if (event.key === "ArrowDown") { event.preventDefault(); if (modelList.hidden) openList(""); highlight(activeIndex + 1); }
    else if (event.key === "ArrowUp") { event.preventDefault(); highlight(activeIndex - 1); }
    else if (event.key === "Enter" && !modelList.hidden && activeIndex >= 0) { event.preventDefault(); choose(modelList.querySelectorAll(".aiadm-model-item")[activeIndex].dataset.model); }
    else if (event.key === "Escape" && !modelList.hidden) { event.stopPropagation(); closeList(); }
  });

  $("save", dialog).addEventListener("click", function () {
    dError.hidden = true;
    const body = {
      id: f("id").value || undefined, name: f("name").value, provider: f("provider").value, endpoint: f("endpoint").value,
      model: f("model").value, api_key: f("api_key").value,
      proxy_mode: f("proxy_mode").value, proxy_url: f("proxy_url").value,
      discovery_token: allModels.indexOf(f("model").value) !== -1 ? f("token").value : "",
      priority: Number(f("priority").value), weight: Number(f("weight").value), max_concurrency: Number(f("max_concurrency").value),
      enabled: f("enabled").checked
    };
    if (limitsTouched || f("id").value) {
      const num = function (name) { return f(name).value === "" ? null : Number(f(name).value); };
      body.limits = { rpm: num("rpm"), tpm: num("tpm"), rpd: num("rpd"), tz: f("tz").value };
    }
    const picked = Array.prototype.map.call(bulkList.querySelectorAll("input:checked"), function (box) { return box.value; });
    call("/admin/ai/services", body).then(function (json) {
      replace(json);
      if (!picked.length || f("id").value) return null;
      return call("/admin/ai/services/bulk", { provider: body.provider, endpoint: body.endpoint, from_service_id: json.service.id, models: picked })
        .then(function (many) { many.services.forEach(function (s) { replace({ service: s }); }); });
    }).then(function () { dialog.close(); }).catch(function (e) {
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
      sensitive_terms: value("sensitive_terms"),
      sensitive_patterns: value("sensitive_patterns"), safe_patterns: value("safe_patterns")
    };
  }

  function preview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(function () {
      const text = tryInput.value.trim();
      if (!text) { verdict.textContent = tr("Type something above to check it."); verdict.className = "aiadm-verdict"; return; }
      call("/admin/ai/preview", Object.assign(settings(), { text: text, kinds: [tryKind.value] })).then(function (json) {
        verdict.textContent = "";
        if (json.pattern_errors && json.pattern_errors.length) {
          verdict.className = "aiadm-verdict is-blocked";
          verdict.textContent = tr("Pattern problem: {error}", { error: json.pattern_errors[0] });
          return;
        }
        const names = json.eligible.map(function (e) { return e.external ? tr("{name} (outside)", { name: e.name }) : e.name; });
        if (json.blocked) {
          verdict.className = "aiadm-verdict is-blocked";
          verdict.textContent = (json.sensitive ? tr("Sensitive: {reasons}.", { reasons: json.reasons.join(", ") }) + " " : "") +
            tr("No service may handle this.") + " " + json.blocked;
        } else if (json.sensitive) {
          verdict.className = "aiadm-verdict is-private";
          verdict.textContent = tr("Sensitive ({reasons}). Stays on your own AI: {names}.", { reasons: json.reasons.join(", "), names: names.join(", ") });
        } else {
          verdict.className = "aiadm-verdict is-ok";
          verdict.textContent = tr("Not sensitive. Could be answered by: {names}.", { names: names.join(", ") });
        }
      }).catch(function (e) { verdict.textContent = e.message; verdict.className = "aiadm-verdict is-blocked"; });
    }, 350);
  }
  tryInput.addEventListener("input", preview);
  tryKind.addEventListener("change", preview);
  form.querySelectorAll("[data-ai-live]").forEach(function (n) { n.addEventListener("change", preview); n.addEventListener("input", preview); });

  // The save bar appears only once something has changed, so it never sits on top of the page for no reason.
  const savebar = $("savebar");
  function showSave(event) {
    if (event && event.target.closest && event.target.closest("[data-ai-tester]")) return;  // trying a sentence is not a setting
    if (savebar.hidden) { savebar.hidden = false; savebar.classList.add("is-shown"); } }
  form.addEventListener("input", showSave);
  form.addEventListener("change", showSave);

  draw();
})();
