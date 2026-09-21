/* AI investigation and chat front end.
 *
 * Progress arrives by short polling of /ai/runs/<id>/stream (works unchanged through
 * the Cloudflare tunnel and never holds a web worker). Model text is only ever
 * rendered through AIRender, which builds DOM nodes and never uses innerHTML. */
(function () {
  "use strict";

  const csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  const TERMINAL = ["completed", "failed", "cancelled"];
  const PILL = {
    queued: "Waiting for the assistant", running: "Working", completed: "Complete",
    failed: "Could not finish", cancelled: "Stopped"
  };

  function get(url) {
    return fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin", cache: "no-store" })
      .then(function (response) {
        if (!response.ok) { const error = new Error("http " + response.status); error.status = response.status; throw error; }
        return response.json();
      });
  }

  function post(url) {
    return fetch(url, { method: "POST", headers: { "X-CSRF-Token": csrf, Accept: "application/json" }, credentials: "same-origin" });
  }

  function element(tag, className, text) {
    const created = document.createElement(tag);
    if (className) created.className = className;
    if (text !== undefined) created.textContent = text;
    return created;
  }

  function sourceMap(sources) {
    const map = {};
    (sources || []).forEach(function (source) { map[source.id] = source; });
    return map;
  }

  function renderSteps(list, steps) {
    list.textContent = "";
    steps.forEach(function (step) {
      const item = element("li", "ai-step is-" + step.state);
      item.appendChild(element("span", "ai-step-mark"));
      const body = element("span", "ai-step-body");
      body.appendChild(element("strong", "", step.label));
      if (step.detail) body.appendChild(element("small", "", step.detail));
      item.appendChild(body);
      item.appendChild(element("time", "ai-step-time", step.t + "s"));
      list.appendChild(item);
    });
  }

  const THINKING_LABELS = {
    "Verified your access": "Checking access",
    "Confirmed who is asking": "Checking access",
    "Collected evidence": "Reviewing evidence",
    "Looked up records you can access": "Reviewing records",
    "Adapted to model context": "Preparing context",
    "Sending to the model": "Preparing answer",
    "The model is reasoning": "Thinking",
    "Writing the answer": "Writing answer",
    "Checked your access again": "Finishing"
  };

  function thinkingLabel(data) {
    if (data.text) return "Writing answer";
    if (data.reasoning) return "Thinking";
    const steps = data.steps || [];
    const current = steps.slice().reverse().find(function (step) { return step.state === "active"; }) || steps[steps.length - 1];
    return current ? (THINKING_LABELS[current.label] || "Working") : (data.status === "queued" ? "Getting ready" : "Working");
  }

  function renderSources(list, sources) {
    list.textContent = "";
    (sources || []).forEach(function (source) {
      const item = element("li", "ai-source");
      const link = element("a", "ai-cite", source.id);
      link.href = source.url;
      item.appendChild(link);
      item.appendChild(element("span", "ai-source-title", source.title));
      item.appendChild(element("span", "badge", source.kind === "ci" ? "CI" : source.kind));
      list.appendChild(item);
    });
  }

  function summarize(usage) {
    const parts = [];
    if (usage.duration_ms) parts.push("Answered in " + (usage.duration_ms / 1000).toFixed(1) + "s");
    if (usage.first_token_ms) parts.push("first words after " + (usage.first_token_ms / 1000).toFixed(1) + "s");
    const tokens = usage.completion_tokens || usage.output_tokens;
    if (tokens) parts.push(tokens + " tokens written");
    return parts.join(" · ");
  }

  /* One streaming answer: used by the investigation page and by each chat turn. */
  function RunView(root, options) {
    options = options || {};
    this.root = root;
    this.id = options.id || root.dataset.aiRun;
    this.seq = -1;
    this.delay = 600;
    this.began = Date.now();
    this.finished = false;
    this.onDone = options.onDone || function () {};
    const find = function (name) { return root.querySelector("[data-ai-" + name + "]"); };
    this.ui = {
      status: find("status"), steps: find("steps"), thinking: find("thinking"), thinkingLabel: find("thinking-label"), elapsed: find("elapsed"),
      reasoning: find("reasoning"), reasoningText: find("reasoning-text"), answer: find("answer"),
      notice: find("notice"), sources: find("sources"), stop: find("stop"), copy: find("copy"), stats: find("stats")
    };
    const self = this;
    if (this.ui.stop) this.ui.stop.addEventListener("click", function () { self.stop(); });
    if (this.ui.copy) this.ui.copy.addEventListener("click", function () { self.copy(); });
    this.clock = setInterval(function () { self.tick(); }, 1000);
  }

  RunView.prototype.tick = function () {
    if (this.finished || !this.ui.elapsed) return;
    this.ui.elapsed.textContent = Math.round((Date.now() - this.began) / 1000) + "s";
  };

  RunView.prototype.start = function () { this.poll(); return this; };

  RunView.prototype.poll = function () {
    const self = this;
    get("/ai/runs/" + this.id + "/stream?after=" + this.seq).then(function (data) {
      self.delay = 600;
      self.apply(data);
    }).catch(function (error) {
      if (error.status === 403 || error.status === 404) { self.fail("You no longer have access to this answer."); return; }
      self.delay = Math.min(self.delay * 2, 5000);
    }).then(function () {
      if (!self.finished) setTimeout(function () { self.poll(); }, self.delay);
    });
  };

  RunView.prototype.apply = function (data) {
    const ui = this.ui;
    if (ui.status) {
      ui.status.textContent = PILL[data.status] || data.status;
      ui.status.dataset.state = data.status;
    }
    if (!data.changed) return;
    this.seq = data.seq;
    if (ui.thinking) {
      ui.thinking.hidden = TERMINAL.indexOf(data.status) !== -1;
      if (ui.thinkingLabel) ui.thinkingLabel.textContent = thinkingLabel(data);
    }
    if (ui.answer) {
      ui.answer.hidden = !data.text;
      ui.answer.textContent = "";
      ui.answer.appendChild(window.AIRender.render(data.text || "", sourceMap(data.sources)));
      ui.answer.setAttribute("aria-busy", TERMINAL.indexOf(data.status) === -1 ? "true" : "false");
      ui.answer.classList.toggle("is-streaming", data.status === "running" && Boolean(data.text));
    }
    if (TERMINAL.indexOf(data.status) !== -1) this.complete(data);
  };

  RunView.prototype.complete = function (data) {
    this.finished = true;
    clearInterval(this.clock);
    const ui = this.ui;
    this.text = data.text || "";
    if (ui.answer) ui.answer.hidden = !this.text;
    if (ui.stop) ui.stop.hidden = true;
    if (ui.copy) ui.copy.hidden = !this.text;
    if (ui.sources) renderSources(ui.sources, data.sources);
    if (ui.elapsed && data.usage && data.usage.duration_ms) ui.elapsed.textContent = (data.usage.duration_ms / 1000).toFixed(1) + "s";
    if (ui.stats) ui.stats.textContent = data.usage ? summarize(data.usage) : "";
    if (ui.thinking) ui.thinking.hidden = true;
    if (ui.notice) {
      const hint = data.error || (data.usage && data.usage.truncated
        ? "The answer was cut off at the length limit. An administrator can raise the maximum output length in Admin → AI." : "");
      ui.notice.hidden = !hint;
      ui.notice.textContent = hint;
    }
    this.onDone(data);
  };

  RunView.prototype.fail = function (message) {
    this.finished = true;
    clearInterval(this.clock);
    if (this.ui.notice) { this.ui.notice.hidden = false; this.ui.notice.textContent = message; }
    if (this.ui.stop) this.ui.stop.hidden = true;
  };

  RunView.prototype.stop = function () {
    const self = this;
    if (this.ui.stop) this.ui.stop.disabled = true;
    post("/ai/runs/" + this.id + "/cancel").then(function () { self.seq = -1; });
  };

  RunView.prototype.copy = function () {
    const text = window.AIRender.plainText(this.text);
    const button = this.ui.copy;
    const done = function () { if (button) { const label = button.textContent; button.textContent = "Copied"; setTimeout(function () { button.textContent = label; }, 1500); } };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done);
  };

  window.AIChat = { RunView: RunView, get: get, post: post, element: element, renderSteps: renderSteps, renderSources: renderSources, sourceMap: sourceMap, summarize: summarize };

  document.querySelectorAll("[data-ai-run]").forEach(function (root) { new RunView(root).start(); });
})();
