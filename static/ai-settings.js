/* Admin > AI assistance: quick presets and automatic model detection. */
(function () {
  "use strict";

  const csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  const $ = function (name) { return document.querySelector("[data-ai-" + name + "]"); };
  const preset = $("preset"), provider = $("provider"), endpoint = $("endpoint"), key = $("key"),
    detect = $("detect"), status = $("detect-status"), model = $("model"), list = $("models"), row = $("endpoint-row");
  if (!provider || !detect) return;
  const consent = document.querySelector('input[name="external_consent"]');
  const FIXED = { openai: true, anthropic: true };

  function syncProvider() {
    row.hidden = Boolean(FIXED[provider.value]);
    if (FIXED[provider.value]) endpoint.value = "";
  }

  function setStatus(message, bad) {
    status.textContent = message;
    status.classList.toggle("is-error", Boolean(bad));
  }

  function fill(models) {
    list.textContent = "";
    models.forEach(function (name) {
      const option = document.createElement("option");
      option.value = name;
      list.appendChild(option);
    });
    if (!model.value || models.indexOf(model.value) === -1) {
      if (models.length === 1 || !model.value) model.value = models[0];
    }
  }

  function run() {
    setStatus("Connecting…");
    detect.disabled = true;
    fetch("/admin/ai/models", {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        provider: provider.value, endpoint: endpoint.value, api_key: key.value,
        external_consent: Boolean(consent && consent.checked)
      })
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) { return { ok: response.ok, body: body }; });
    }).then(function (result) {
      if (!result.ok) { setStatus(result.body.error || "Could not detect models. Enter the model identifier manually.", true); return; }
      fill(result.body.models);
      const chosen = model.value;
      const context = (result.body.context || {})[chosen];
      let message = "Connected. " + result.body.models.length + (result.body.models.length === 1 ? " model" : " models") +
        " found; " + chosen + " is selected. Save to apply.";
      if (context) message += " Context window: " + context + " tokens.";
      if (context && context < 8192) message += " That is small for incident investigations; start the server with a context of at least 8192 (llama.cpp: -c 8192).";
      setStatus(message, Boolean(context && context < 8192));
    }).catch(function () {
      setStatus("Could not reach ServiceOps. Try again.", true);
    }).then(function () { detect.disabled = false; });
  }

  if (preset) {
    preset.addEventListener("change", function () {
      if (!preset.value) return;
      const parts = preset.value.split("|");
      provider.value = parts[0];
      endpoint.value = parts[1] || "";
      syncProvider();
      (FIXED[parts[0]] ? key : endpoint).focus();
      preset.value = "";
    });
  }
  provider.addEventListener("change", syncProvider);
  detect.addEventListener("click", run);
  // Detect as soon as there is enough to try, so the model does not have to be looked up by hand.
  let timer = null;
  function auto() {
    clearTimeout(timer);
    const ready = FIXED[provider.value] ? key.value.length > 8 : /^https?:\/\/[^\s/]+/i.test(endpoint.value) && !/HOST/.test(endpoint.value);
    if (ready) timer = setTimeout(run, 1200);
  }
  endpoint.addEventListener("input", auto);
  key.addEventListener("input", auto);
  syncProvider();
})();
