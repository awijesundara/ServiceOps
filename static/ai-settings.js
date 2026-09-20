/* Admin > AI assistance: quick presets and automatic model detection. */
(function () {
  "use strict";

  const csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  const $ = function (name) { return document.querySelector("[data-ai-" + name + "]"); };
  const preset = $("preset"), provider = $("provider"), endpoint = $("endpoint"), key = $("key"),
    detect = $("detect"), status = $("detect-status"), model = $("model"), list = $("models"), row = $("endpoint-row");
  if (!provider || !detect) return;
  const consent = document.querySelector('input[name="external_consent"]');
  const token = $("discovery-token");
  let generation = 0, controller = null, profiles = {};
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
      model.value = models.length === 1 ? models[0] : "";
    }
  }

  function invalidate() {
    generation += 1;
    if (controller) controller.abort();
    if (token) token.value = "";
    profiles = {};
    detect.disabled = false;
  }

  function run() {
    clearTimeout(timer);
    invalidate();
    const requestGeneration = generation;
    controller = new AbortController();
    setStatus("Connecting…");
    detect.disabled = true;
    fetch("/admin/ai/models", {
      method: "POST", signal: controller.signal, credentials: "same-origin", cache: "no-store",
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        provider: provider.value, endpoint: endpoint.value, api_key: key.value, model: model.value, clear_key: Boolean(clearKey && clearKey.checked),
        external_consent: Boolean(consent && consent.checked)
      })
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) { return { ok: response.ok, body: body }; });
    }).then(function (result) {
      if (requestGeneration !== generation) return;
      if (!result.ok) { setStatus(result.body.error || "Could not detect models. Enter the model identifier manually.", true); return; }
      fill(result.body.models);
      if (token) token.value = result.body.discovery_token || "";
      profiles = result.body.profiles || {};
      const chosen = model.value;
      const profile = profiles[chosen] || {};
      let message = "Model discovery succeeded. " + result.body.models.length + " model(s) found. " +
        (chosen ? chosen + " is selected. " : "Choose a model from the list. ");
      if (profile.context_tokens) message += "Context: " + profile.context_tokens + " tokens (" + profile.context_source + "). ";
      else message += "Runtime context was not reported; a conservative budget will be used. ";
      message += "Inference and optional capabilities are not yet verified. Save, then test the connection.";
      setStatus(message, false);
    }).catch(function (error) {
      if (requestGeneration !== generation || error.name === "AbortError") return;
      setStatus("Could not reach ServiceOps. Try again.", true);
    }).then(function () { if (requestGeneration === generation) detect.disabled = false; });
  }

  if (preset) {
    preset.addEventListener("change", function () {
      if (!preset.value) return;
      invalidate();
      const parts = preset.value.split("|");
      provider.value = parts[0];
      endpoint.value = parts[1] || "";
      syncProvider();
      (FIXED[parts[0]] ? key : endpoint).focus();
      preset.value = "";
    });
  }
  provider.addEventListener("change", function () { invalidate(); syncProvider(); });
  detect.addEventListener("click", run);
  // Detect as soon as there is enough to try, so the model does not have to be looked up by hand.
  let timer = null;
  function auto() {
    clearTimeout(timer);
    invalidate();
    const ready = FIXED[provider.value] ? key.value.length > 8 : /^https?:\/\/[^\s/]+/i.test(endpoint.value) && !/HOST/.test(endpoint.value);
    if (ready && (provider.value === "self_hosted" || (consent && consent.checked))) timer = setTimeout(run, 1200);
  }
  endpoint.addEventListener("input", auto);
  key.addEventListener("input", auto);
  if (consent) consent.addEventListener("change", auto);
  const clearKey = document.querySelector('input[name="clear_key"]');
  if (clearKey) clearKey.addEventListener("change", invalidate);
  model.addEventListener("change", function () {
    if (profiles[model.value]) run();
    else invalidate();
  });
  syncProvider();
})();
