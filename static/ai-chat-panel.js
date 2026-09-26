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
    userTurn: $("user-turn"), aiTurn: $("ai-turn"), memory: $("memory"), memoryList: root.querySelector("[data-chat-memory-list]"),
    memoryEmpty: $("memory-empty"), memoryToggle: $("memory-toggle"), memoryClear: $("memory-clear"), model: $("model")
  };
  const launcher = document.querySelector("[data-chat-launch]");
  const widget = root.classList.contains("is-widget");
  const MAX = 2000;
  const state = { conversation: null, active: null, loaded: false, busy: false };

  function keep(key, value) { try { if (value) sessionStorage.setItem(key, value); else sessionStorage.removeItem(key); } catch (e) { /* storage may be blocked */ } }
  function kept(key) { try { return sessionStorage.getItem(key); } catch (e) { return null; } }

  function remember(id) { try { if (id) sessionStorage.setItem("ai-chat-conversation", id); else sessionStorage.removeItem("ai-chat-conversation"); } catch (e) { /* storage may be blocked */ } }
  function recalled() { try { return sessionStorage.getItem("ai-chat-conversation"); } catch (e) { return null; } }

  // Whether the widget is open has to survive full page navigations (this is a
  // classic multi-page app, not an SPA), but sessionStorage is invisible to the
  // server at render time -- that gap is what used to show as a flash of the
  // launcher button before this script could react. A small, non-sensitive
  // cookie lets the server pre-render the correct state instead (see the
  // `ai-chat-open` class on <html> in base.html and the matching CSS override
  // in ai-chat.css); this is purely UI-state, never read for anything else, so
  // it carries no CSRF or data-exposure surface.
  function setChatOpenCookie(open) {
    try { document.cookie = "ai_chat_open=" + (open ? "1" : "") + "; path=/; SameSite=Lax" + (open ? "" : "; Max-Age=0"); } catch (e) { /* cookies may be blocked */ }
  }

  // Which AI service to ask for next time -- a lasting preference (unlike the
  // conversation pointer above, which is per-tab session state), so this is
  // localStorage, not sessionStorage. Purely a per-viewer convenience: the
  // server never trusts it, re-validates the id on every send, and silently
  // ignores one that no longer names an enabled connection.
  function rememberModel(id) { try { if (id) localStorage.setItem("ai-chat-model", id); else localStorage.removeItem("ai-chat-model"); } catch (e) { /* storage may be blocked */ } }
  function recalledModel() { try { return localStorage.getItem("ai-chat-model"); } catch (e) { return null; } }

  function loadModels() {
    if (!ui.model) return;
    window.AIChat.get("/ai/chat/connections").then(function (data) {
      const rows = data.connections || [];
      ui.model.hidden = rows.length < 2;  // nothing to choose between "Automatic" and one service
      if (!ui.model.hidden) {
        const previous = recalledModel();
        ui.model.textContent = "";
        ui.model.appendChild(window.AIChat.element("option", "", "Automatic")).value = "";
        rows.forEach(function (row) {
          const option = window.AIChat.element("option", "", row.name + (row.external ? " (External)" : ""));
          option.value = row.id;
          ui.model.appendChild(option);
        });
        ui.model.value = rows.some(function (row) { return row.id === previous; }) ? previous : "";
      }
    }).catch(function () { /* the picker is a convenience; leave it hidden on failure */ });
  }
  if (ui.model) ui.model.addEventListener("change", function () { rememberModel(ui.model.value || null); });

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
        message.status === "cancelled" ? "Stopped. No answer was kept." : (message.error || "The assistant could not complete this request. Please try again."), {}));
    } else {
      answer.appendChild(window.AIRender.render(message.content, window.AIChat.sourceMap(message.sources)));
    }
    q("thinking").hidden = true;
    if (message.sources && message.sources.length) window.AIChat.renderSources(q("sources"), message.sources);
    window.AIChat.renderRoute(q("route"), message.route);
    window.AIChat.renderExtras(q("extras"), message.route, Boolean(message.latest));
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
    const lastAssistant = conversation.messages.map(function (m) { return m.role; }).lastIndexOf("assistant");
    conversation.messages.forEach(function (message, index) {
      message.latest = index === lastAssistant;
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
      // A short badge; the full description is one hover away.
      ui.scope.textContent = data.scope.split(":")[0] + " access";
      ui.scope.title = data.scope;
      ui.memoryToggle.hidden = !data.memory_enabled;
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

  function refreshMemory() {
    return window.AIChat.get("/ai/chat/memories").then(function (data) {
      ui.memoryList.textContent = "";
      ui.memoryEmpty.hidden = data.notes.length > 0;
      ui.memoryClear.hidden = data.notes.length === 0;
      data.notes.forEach(function (note) {
        const row = window.AIChat.element("li", "");
        row.appendChild(window.AIChat.element("span", "ai-memory-text", note.text));
        const remove = window.AIChat.element("button", "ai-history-delete", "Remove");
        remove.type = "button";
        remove.setAttribute("aria-label", "Remove note: " + note.text);
        remove.addEventListener("click", function () {
          send("/ai/chat/memories/" + encodeURIComponent(note.id) + "/delete").then(refreshMemory).catch(function (e) { showError(e.message); });
        });
        row.appendChild(remove);
        ui.memoryList.appendChild(row);
      });
    }).catch(function () { ui.memory.hidden = true; });
  }

  ui.memoryToggle.addEventListener("click", function () {
    const show = ui.memory.hidden;
    ui.memory.hidden = !show;
    ui.memoryToggle.setAttribute("aria-expanded", show ? "true" : "false");
    if (show) refreshMemory();
  });
  ui.memoryClear.addEventListener("click", function () {
    if (!ui.memoryClear.dataset.armed) {
      ui.memoryClear.dataset.armed = "1"; ui.memoryClear.textContent = "Confirm: forget everything";
      setTimeout(function () { delete ui.memoryClear.dataset.armed; ui.memoryClear.textContent = "Forget everything"; }, 4000);
      return;
    }
    delete ui.memoryClear.dataset.armed; ui.memoryClear.textContent = "Forget everything";
    send("/ai/chat/memories/clear").then(refreshMemory).catch(function (e) { showError(e.message); });
  });

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
      text: text, conversation_id: state.conversation, request_key: uuid(),
      preferred_connection_id: (ui.model && ui.model.value) || undefined
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
    ui.count.hidden = ui.input.value.length < MAX - 300;  // only worth showing near the limit
    ui.count.textContent = ui.input.value.length + " / " + MAX;
    ui.input.style.height = "auto";
    ui.input.style.height = Math.min(ui.input.scrollHeight, 140) + "px";
  }

  document.addEventListener("ai-chat-ask", function (event) { if (!state.busy) submit(String(event.detail || "")); });
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

  // The widget header's "..." options menu (New chat/History/Memory/Open full page)
  // is a plain <details>, which has no built-in "close after picking one" or
  // "close on an outside click" behavior -- add both, matching how every other
  // dropdown-like control in the chat panel already closes itself after use.
  const menu = root.querySelector(".ai-chat-menu");
  if (menu) {
    menu.querySelectorAll("[data-chat-new], [data-chat-history-toggle], [data-chat-memory-toggle], a").forEach(function (item) {
      item.addEventListener("click", function () { menu.open = false; });
    });
    document.addEventListener("click", function (event) { if (menu.open && !menu.contains(event.target)) menu.open = false; });
    menu.addEventListener("keydown", function (event) { if (event.key === "Escape") { menu.open = false; menu.querySelector("summary").focus(); } });
  }

  function start() {
    if (state.loaded) return;
    state.loaded = true;
    refreshHistory();
    loadModels();
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
    const CLOSE_MS = 150;  // matches .ai-chat.is-widget.is-closing's animation-duration in ai-chat.css
    const reduceMotion = function () { return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches; };
    const show = function (visible, focus) {
      root.classList.remove("is-restoring");  // an explicit toggle always gets the real open/close animation
      if (visible) {
        root.classList.remove("is-closing");
        root.hidden = false;
      } else if (reduceMotion()) {
        root.hidden = true;
      } else {
        // Play the close animation before actually hiding it -- [hidden] is
        // display:none, which can't itself be transitioned or animated.
        root.classList.add("is-closing");
        setTimeout(function () { root.hidden = true; root.classList.remove("is-closing"); }, CLOSE_MS);
      }
      launcher.setAttribute("aria-expanded", visible ? "true" : "false");
      launcher.hidden = visible;
      document.documentElement.classList.toggle("ai-chat-open", visible);
      setChatOpenCookie(visible);
      if (visible) { start(); if (focus !== false) ui.input.focus(); } else if (focus !== false) { launcher.focus(); }
    };
    launcher.addEventListener("click", function () { show(true); });
    close.addEventListener("click", function () { show(false); });
    root.addEventListener("keydown", function (event) { if (event.key === "Escape") show(false); });
    // The chat stays open across pages. The server already rendered the correct
    // state (the "ai-chat-open" class on <html>, from the cookie above) before
    // this script ever ran -- there is no flash to fix here, just two things
    // left to do: make it *really* open (the actual `hidden` property, not just
    // the CSS override that bridged the first paint) and populate its content,
    // without replaying the entrance animation since nothing visibly "opened."
    if (document.documentElement.classList.contains("ai-chat-open")) {
      root.classList.add("is-restoring");
      root.hidden = false;
      launcher.hidden = true;
      launcher.setAttribute("aria-expanded", "true");
      start();
    }
  } else {
    if (window.matchMedia && window.matchMedia("(max-width: 700px)").matches) toggleHistory(false);
    start();
    ui.input.focus();
  }
})();
