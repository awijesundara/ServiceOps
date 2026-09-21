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

  function postJson(url, body) {
    return fetch(url, { method: "POST", headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json", Accept: "application/json" },
      credentials: "same-origin", body: JSON.stringify(body || {}) }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (json) {
        if (!response.ok) throw new Error(json.error || "That did not work. Please try again.");
        return json;
      });
    });
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
    const box = list.closest("details");
    if (box) {
      box.hidden = !(sources && sources.length);
      box.querySelector("summary").textContent = "Sources (" + (sources ? sources.length : 0) + ")";
    }
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

  /* Where the answer was produced, in plain words. Only shown once an answer exists. */
  function renderRoute(holder, route) {
    if (!holder) return;
    holder.textContent = "";
    holder.hidden = !(route && (route.location === "private" || route.location === "external"));
    if (holder.hidden) return;
    // The exact model that wrote the answer, so nobody has to guess which AI they are reading.
    const label = (route.location === "private" ? "Private" : "External") + (route.model ? " · " + route.model : " AI");
    const chip = element("span", "ai-route-chip is-" + route.location, label);
    chip.title = (route.name ? route.name + ": " : "") + (route.reason || "");
    holder.appendChild(chip);
    if (route.sensitive && route.reason) holder.appendChild(element("span", "ai-route-note", route.reason));
  }

  /* Follow-up questions and a ticket draft under an answer. The draft only opens the normal ticket form
     pre-filled; nothing is created until the person submits it there. */
  function renderExtras(holder, route, withSuggestions) {
    if (!holder) return;
    holder.textContent = "";
    const draft = route && route.draft;
    if (draft && draft.url) {
      const card = element("div", "ai-draft");
      card.appendChild(element("p", "ai-draft-label", "Draft " + draft.kind + " ready for you"));
      card.appendChild(element("strong", "", draft.title));
      card.appendChild(element("p", "ai-draft-body", draft.description));
      card.appendChild(element("p", "ai-draft-meta", "Impact " + draft.impact + " · Urgency " + draft.urgency + " · " + draft.category));
      const open = element("a", "primary ai-draft-open", "Review and create");
      open.href = draft.url;
      card.appendChild(open);
      card.appendChild(element("small", "", "Nothing is created until you submit the form."));
      holder.appendChild(card);
    }
    if (withSuggestions && route && route.remember) {
      const card = element("div", "ai-remember");
      card.appendChild(element("span", "", "Remember this? “" + route.remember + "”"));
      const yes = element("button", "ai-remember-yes", "Remember");
      const no = element("button", "ai-remember-no", "No thanks");
      yes.type = no.type = "button";
      yes.addEventListener("click", function () {
        yes.disabled = no.disabled = true;
        postJson("/ai/chat/memories", { text: route.remember }).then(function () { card.textContent = "Saved. You can review it under Memory."; })
          .catch(function (e) { card.textContent = e.message; });
      });
      no.addEventListener("click", function () { card.remove(); holder.hidden = !holder.childNodes.length; });
      card.appendChild(yes);
      card.appendChild(no);
      holder.appendChild(card);
    }
    if (route && route.pages && route.pages.length) {
      const row = element("div", "ai-suggest ai-pages");
      route.pages.forEach(function (page) {
        const link = element("a", "ai-suggest-chip ai-page-chip", "Open " + page.label + " →");
        link.href = page.url;
        row.appendChild(link);
      });
      holder.appendChild(row);
    }
    if (withSuggestions && route && route.suggestions && route.suggestions.length) {
      const row = element("div", "ai-suggest");
      route.suggestions.forEach(function (text) {
        const chip = element("button", "ai-suggest-chip", text);
        chip.type = "button";
        chip.addEventListener("click", function () { document.dispatchEvent(new CustomEvent("ai-chat-ask", { detail: text })); });
        row.appendChild(chip);
      });
      holder.appendChild(row);
    }
    holder.hidden = !holder.childNodes.length;
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
    this.shown = 0;
    this.target = "";
    this.delay = 600;
    this.began = Date.now();
    this.finished = false;
    this.onDone = options.onDone || function () {};
    const find = function (name) { return root.querySelector("[data-ai-" + name + "]"); };
    this.ui = {
      status: find("status"), steps: find("steps"), thinking: find("thinking"), thinkingLabel: find("thinking-label"), elapsed: find("elapsed"),
      reasoning: find("reasoning"), reasoningText: find("reasoning-text"), answer: find("answer"),
      notice: find("notice"), route: find("route"), extras: find("extras"), sources: find("sources"), stop: find("stop"), copy: find("copy"),
      action: find("action"), stats: find("stats")
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
      // Words arrive in bursts a few times a second. Reveal them steadily, like a person typing, so the
      // answer flows instead of jumping. The complete text is always what is finally shown.
      this.target = data.text || "";
      this.sources = sourceMap(data.sources);
      ui.answer.setAttribute("aria-busy", TERMINAL.indexOf(data.status) === -1 ? "true" : "false");
      if (this.target.length < this.shown) this.shown = 0;
      this.type();
    }
    if (TERMINAL.indexOf(data.status) !== -1) this.complete(data);
  };

  RunView.prototype.paint = function (final) {
    const ui = this.ui;
    const text = final ? this.target : this.target.slice(0, this.shown);
    ui.answer.hidden = !text;
    ui.answer.textContent = "";
    ui.answer.appendChild(window.AIRender.render(text, final ? this.sources : {}));
    ui.answer.classList.toggle("is-streaming", !final && Boolean(text));
  };

  RunView.prototype.type = function () {
    if (this.typing || !this.ui.answer) return;
    const self = this;
    const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) { this.shown = this.target.length; this.paint(false); return; }
    this.typing = true;
    const step = function () {
      const backlog = self.target.length - self.shown;
      if (backlog <= 0) { self.typing = false; if (self.done) self.finalize(); return; }
      // Catch up faster when far behind, slower when close, so the pace looks even.
      self.shown += Math.max(1, Math.ceil(backlog / (self.done ? 6 : 18)));
      self.paint(false);
      setTimeout(step, 28);
    };
    step();
  };

  RunView.prototype.finalize = function () {
    if (!this.ui.answer) return;
    this.shown = this.target.length;
    this.paint(true);
    this.ui.answer.classList.remove("is-streaming");
  };

  RunView.prototype.complete = function (data) {
    this.finished = true;
    clearInterval(this.clock);
    const ui = this.ui;
    this.text = data.text || "";
    this.target = this.text;
    this.sources = sourceMap(data.sources);
    this.done = true;
    if (ui.answer) { if (this.typing) { /* finishes typing, then shows citations */ } else this.finalize(); }
    if (ui.stop) ui.stop.hidden = true;
    if (ui.copy) ui.copy.hidden = !this.text;
    if (ui.action) ui.action.hidden = data.status !== "completed" || !this.text;
    if (ui.sources) renderSources(ui.sources, data.sources);
    renderRoute(ui.route, data.route);
    renderExtras(ui.extras, data.route, this.suggest !== false);
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

  window.AIChat = { RunView: RunView, get: get, post: post, element: element, renderSteps: renderSteps, renderRoute: renderRoute, renderExtras: renderExtras, postJson: postJson, renderSources: renderSources, sourceMap: sourceMap, summarize: summarize };

  document.querySelectorAll("[data-ai-run]").forEach(function (root) { new RunView(root).start(); });
})();
