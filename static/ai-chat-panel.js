/* Chat assistant: floating widget on every page and the full /ai/chat page.
 *
 * Everything the model wrote is drawn by AIRender (DOM nodes only, never innerHTML).
 * Who may see what is decided on the server for every message; nothing here grants access. */
(function () {
  "use strict";

  const root = document.querySelector("[data-chat]");
  if (!root || !window.AIChat || !window.AIRender) return;

  const csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  const $ = function (name) { return root.querySelector("[data-chat-" + name + "]"); };
  const ui = {
    scope: $("scope"), log: $("log"), welcome: $("welcome"), form: $("form"), input: $("input"), count: $("count"),
    send: $("send"), stop: $("stop"), error: $("error"), history: $("history"), list: root.querySelector("[data-chat-history-list]"),
    empty: $("history-empty"), toggle: $("history-toggle"), fresh: $("new"),
    userTurn: $("user-turn"), aiTurn: $("ai-turn")
  };
  const launcher = document.querySelector("[data-chat-launch]");
  const widget = root.classList.contains("is-widget");
  const MAX = 2000;
  const state = { conversation: null, active: null, loaded: false, busy: false };

  function keep(key, value) { try { if (value) sessionStorage.setItem(key, value); else sessionStorage.removeItem(key); } catch (e) { /* storage may be blocked */ } }
  function kept(key) { try { return sessionStorage.getItem(key); } catch (e) { return null; } }

  function remember(id) { try { if (id) sessionStorage.setItem("ai-chat-conversation", id); else sessionStorage.removeItem("ai-chat-conversation"); } catch (e) { /* storage may be blocked */ } }
  function recalled() { try { return sessionStorage.getItem("ai-chat-conversation"); } catch (e) { return null; } }

  function showError(message) {
    ui.error.hidden = !message;
    ui.error.textContent = message || "";
  }

  function uuid() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, function (c) {
      return (c ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))).toString(16);
    });
  }

  function send(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body || {})
    }).then(function (response) {
      if (response.ok) return response.json();
      const messages = {
        400: "That message could not be sent. Check it and try again.",
        403: "You no longer have access to the assistant, or this chat belongs to a different role.",
        404: "That conversation is no longer available.",
        409: "Wait for the current answer to finish, or stop it first.",
        429: "You are sending messages too quickly. Wait a moment and try again."
      };
      const error = new Error(messages[response.status] || "The assistant is unavailable right now.");
      error.status = response.status;
      throw error;
    });
  }

  function scrollDown() { ui.log.scrollTop = ui.log.scrollHeight; }

  function userTurn(text) {
    const node = ui.userTurn.content.firstElementChild.cloneNode(true);
    node.querySelector("[data-chat-text]").textContent = text;
    ui.log.appendChild(node);
    return node;
  }

  function aiTurn() {
    const node = ui.aiTurn.content.firstElementChild.cloneNode(true);
    ui.log.appendChild(node);
    return node;
  }

  function staticAnswer(node, message) {
    const view = node.querySelector(".ai-run");
    const q = function (name) { return view.querySelector("[data-ai-" + name + "]"); };
    q("status").hidden = true;
    const answer = q("answer");
    answer.hidden = false;
    answer.setAttribute("aria-busy", "false");
    const failed = message.status !== "completed";
    if (failed) {
      answer.appendChild(window.AIRender.render(
        message.status === "cancelled" ? "Stopped. No answer was kept." : "The assistant could not complete this request.", {}));
    } else {
      answer.appendChild(window.AIRender.render(message.content, window.AIChat.sourceMap(message.sources)));
    }
    q("thinking").hidden = true;
    if (message.sources && message.sources.length) window.AIChat.renderSources(q("sources"), message.sources);
    window.AIChat.renderRoute(q("route"), message.route);
    const copy = q("copy");
    if (!failed && message.content && !message.withheld) {
      copy.hidden = false;
      copy.addEventListener("click", function () {
        if (navigator.clipboard) navigator.clipboard.writeText(window.AIRender.plainText(message.content));
        copy.textContent = "Copied";
        setTimeout(function () { copy.textContent = "Copy"; }, 1500);
      });
    }
  }

  function setBusy(busy) {
    state.busy = busy;
    ui.send.disabled = busy;
    ui.stop.hidden = !busy;
  }

  function attach(node, runId) {
    const view = new window.AIChat.RunView(node.querySelector(".ai-run"), {
      id: runId,
      onDone: function () { state.active = null; setBusy(false); scrollDown(); refreshHistory(); ui.input.focus(); }
    });
    view.ui.stop = null;
    state.active = view;
    setBusy(true);
    view.start();
    // Keep the newest words in view while the answer is being written.
    const follow = setInterval(function () { if (view.finished) clearInterval(follow); else scrollDown(); }, 500);
  }

  function clearLog() {
    if (state.active) { state.active.finished = true; clearInterval(state.active.clock); state.active = null; }
    Array.prototype.slice.call(ui.log.children).forEach(function (child) { if (child !== ui.welcome) child.remove(); });
    setBusy(false);
  }

  function render(conversation) {
    clearLog();
    state.conversation = conversation ? conversation.id : null;
    remember(state.conversation);
    ui.welcome.hidden = Boolean(conversation && conversation.messages.length);
    if (!conversation) return;
    conversation.messages.forEach(function (message) {
      if (message.role === "user") { userTurn(message.content); return; }
      const node = aiTurn();
      if (message.status === "pending" && message.run_id) attach(node, message.run_id);
      else staticAnswer(node, message);
    });
    scrollDown();
    // Keep a copy so the next page shows this chat instantly instead of an empty panel.
    const settled = conversation.messages.every(function (m) { return m.status !== "pending"; });
    keep("ai-chat-cache", settled ? JSON.stringify(conversation) : null);
  }

  function open(id) {
    showError("");
    return window.AIChat.get("/ai/chat/conversations/" + encodeURIComponent(id)).then(function (conversation) {
      // Skip the redraw when nothing changed since the cached copy was shown.
      if (state.conversation === conversation.id && kept("ai-chat-cache") === JSON.stringify(conversation)) return;
      render(conversation);
    }).catch(function (error) {
      remember(null);
      if (error.status === 403 || error.status === 404) { render(null); return; }
      showError("Could not load that conversation.");
    });
  }

  function refreshHistory() {
    return window.AIChat.get("/ai/chat/conversations").then(function (data) {
      ui.scope.textContent = data.scope;
      ui.list.textContent = "";
      ui.empty.hidden = data.conversations.length > 0;
      data.conversations.forEach(function (item) {
        const row = window.AIChat.element("li", item.id === state.conversation ? "is-current" : "");
        const openButton = window.AIChat.element("button", "ai-history-open", item.title);
        openButton.type = "button";
        openButton.addEventListener("click", function () { open(item.id); if (widget) toggleHistory(false); });
        const remove = window.AIChat.element("button", "ai-history-delete", "Delete");
        remove.type = "button";
        remove.setAttribute("aria-label", "Delete conversation: " + item.title);
        remove.addEventListener("click", function () {
          if (!remove.dataset.armed) {
            remove.dataset.armed = "1"; remove.textContent = "Confirm delete";
            remove.setAttribute("aria-label", "Confirm deleting conversation: " + item.title);
            setTimeout(function () {
              delete remove.dataset.armed; remove.textContent = "Delete";
              remove.setAttribute("aria-label", "Delete conversation: " + item.title);
            }, 4000);
            return;
          }
          send("/ai/chat/conversations/" + encodeURIComponent(item.id) + "/delete").then(function () {
            if (state.conversation === item.id) render(null);
            refreshHistory();
          }).catch(function (error) { showError(error.message); });
        });
        row.appendChild(openButton);
        row.appendChild(remove);
        ui.list.appendChild(row);
      });
    }).catch(function (error) {
      ui.scope.textContent = error.status === 403 ? "The assistant is not available for your account right now." : "Could not check your access.";
    });
  }

  function toggleHistory(force) {
    const show = typeof force === "boolean" ? force : ui.history.hidden;
    ui.history.hidden = !show;
    ui.toggle.setAttribute("aria-expanded", show ? "true" : "false");
  }

  function submit(text) {
    text = text.trim();
    if (!text || state.busy) return;
    showError("");
    setBusy(true);
    send("/ai/chat/messages", {
      text: text, conversation_id: state.conversation, request_key: uuid()
    }).then(function (data) {
      state.conversation = data.conversation_id;
      remember(state.conversation);
      ui.welcome.hidden = true;
      userTurn(text);
      ui.input.value = "";
      keep("ai-chat-draft", null);
      updateCount();
      attach(aiTurn(), data.run_id);
      scrollDown();
    }).catch(function (error) {
      setBusy(false);
      showError(error.message);
      if (error.status === 403) ui.scope.textContent = "The assistant is not available for your account right now.";
    });
  }

  function updateCount() {
    ui.count.textContent = ui.input.value.length + " / " + MAX;
  }

  ui.form.addEventListener("submit", function (event) { event.preventDefault(); submit(ui.input.value); });
  ui.input.addEventListener("input", function () { updateCount(); keep("ai-chat-draft", ui.input.value); });
  ui.input.value = kept("ai-chat-draft") || "";
  updateCount();
  ui.input.addEventListener("keydown", function (event) {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) { event.preventDefault(); submit(ui.input.value); }
  });
  ui.stop.addEventListener("click", function () { if (state.active) state.active.stop(); });
  ui.fresh.addEventListener("click", function () { render(null); ui.welcome.hidden = false; refreshHistory(); ui.input.focus(); if (widget) toggleHistory(false); });
  ui.toggle.addEventListener("click", function () { toggleHistory(); });
  root.querySelectorAll("[data-chat-suggest]").forEach(function (button) {
    button.addEventListener("click", function () { submit(button.dataset.chatSuggest); });
  });

  function start() {
    if (state.loaded) return;
    state.loaded = true;
    refreshHistory();
    const previous = recalled();
    if (previous) {
      try {
        const cached = JSON.parse(kept("ai-chat-cache") || "null");
        if (cached && cached.id === previous) render(cached);
      } catch (e) { /* fall through to the server copy */ }
      open(previous);
    }
  }

  if (widget) {
    const close = root.querySelector("[data-chat-close]");
    const show = function (visible, focus) {
      root.hidden = !visible;
      launcher.setAttribute("aria-expanded", visible ? "true" : "false");
      launcher.hidden = visible;
      document.documentElement.classList.toggle("ai-chat-open", visible);
      keep("ai-chat-open", visible ? "1" : null);
      if (visible) { start(); if (focus !== false) ui.input.focus(); } else if (focus !== false) { launcher.focus(); }
    };
    launcher.addEventListener("click", function () { show(true); });
    close.addEventListener("click", function () { show(false); });
    root.addEventListener("keydown", function (event) { if (event.key === "Escape") show(false); });
    // The chat stays open across pages: reopen it quietly, without stealing focus from the page.
    if (kept("ai-chat-open") === "1") show(true, false);
  } else {
    if (window.matchMedia && window.matchMedia("(max-width: 700px)").matches) toggleHistory(false);
    start();
    ui.input.focus();
  }
})();
