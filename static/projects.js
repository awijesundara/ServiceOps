/* Project management pages (B-443): board drag and drop, inline status
 * changes on the list, auto-submitting selects, the project key suggestion
 * and the activity tabs. Everything works without this script through the
 * plain forms; it only makes common actions faster. */
(function () {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const notify = (message, category) => (typeof showToast === "function" ? showToast(message, category) : null);

  async function postJson(url, payload) {
    const response = await fetch(url, {
      method: "POST",
      headers: {"Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": csrf},
      body: JSON.stringify(payload),
    });
    let data = {};
    try { data = await response.json(); } catch (error) { data = {}; }
    if (!response.ok) throw new Error(data.error || tr("The change could not be saved."));
    return data;
  }

  // --- New project: suggest a key from the name until the user types one.
  const keyInput = document.querySelector("[data-project-key]");
  const nameInput = document.querySelector("[data-project-name]");
  if (keyInput && nameInput) {
    let keyEdited = false;
    keyInput.addEventListener("input", () => { keyEdited = true; keyInput.value = keyInput.value.toUpperCase(); });
    nameInput.addEventListener("input", () => {
      if (keyEdited) return;
      const words = nameInput.value.match(/[A-Za-z0-9]+/g) || [];
      let key = words.length > 1 ? words.map(word => word[0]).join("") : (words[0] || "").slice(0, 4);
      key = key.toUpperCase().replace(/^[0-9]+/, "").slice(0, 10);
      keyInput.value = key.length >= 2 ? key : "";
    });
  }

  // --- People picker: chips plus a searchable list over a <select multiple>.
  // The select stays in the form (hidden) as the source of truth.
  let pickerCount = 0;
  document.querySelectorAll("select[multiple][data-people-picker]").forEach(select => {
    pickerCount += 1;
    const listId = `people-picker-${pickerCount}`;
    const wrapper = document.createElement("div");
    wrapper.className = "people-picker";
    const chips = document.createElement("div");
    chips.className = "people-chips";
    const input = document.createElement("input");
    input.type = "text";
    input.className = "people-search";
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-expanded", "false");
    input.setAttribute("aria-controls", listId);
    input.setAttribute("aria-label", select.getAttribute("aria-label") || select.closest("label")?.firstChild?.textContent?.trim() || tr("Add a person"));
    input.placeholder = select.dataset.pickerPlaceholder || tr("Add a person…");
    const list = document.createElement("ul");
    list.id = listId;
    list.className = "people-options";
    list.setAttribute("role", "listbox");
    list.hidden = true;
    select.hidden = true;
    select.parentNode.insertBefore(wrapper, select.nextSibling);
    wrapper.append(chips, input, list);
    let active = -1;

    function renderChips() {
      chips.replaceChildren(...Array.from(select.selectedOptions).map(option => {
        const chip = document.createElement("span");
        chip.className = "people-chip";
        chip.textContent = option.textContent;
        const remove = document.createElement("button");
        remove.type = "button";
        remove.textContent = "×";
        remove.setAttribute("aria-label", tr("Remove {name}", {name: option.textContent}));
        remove.addEventListener("click", () => { option.selected = false; changed(); input.focus(); });
        chip.append(remove);
        return chip;
      }));
    }
    function changed() {
      renderChips();
      select.dispatchEvent(new Event("change", {bubbles: true}));
    }
    function choices() {
      const needle = input.value.trim().toLowerCase();
      return Array.from(select.options).filter(option => !option.selected && option.textContent.toLowerCase().includes(needle)).slice(0, 50);
    }
    function renderList() {
      const options = choices();
      active = Math.min(active, options.length - 1);
      list.replaceChildren(...options.map((option, index) => {
        const item = document.createElement("li");
        item.id = `${listId}-${index}`;
        item.setAttribute("role", "option");
        item.setAttribute("aria-selected", String(index === active));
        item.textContent = option.textContent;
        item.addEventListener("mousedown", event => { event.preventDefault(); choose(option); });
        return item;
      }));
      if (!options.length) {
        const empty = document.createElement("li");
        empty.className = "people-none";
        empty.textContent = select.dataset.pickerEmpty || tr("No matching people");
        list.append(empty);
      }
      list.hidden = false;
      input.setAttribute("aria-expanded", "true");
      input.setAttribute("aria-activedescendant", active >= 0 ? `${listId}-${active}` : "");
    }
    function close() {
      list.hidden = true;
      active = -1;
      input.setAttribute("aria-expanded", "false");
      input.removeAttribute("aria-activedescendant");
    }
    function choose(option) {
      option.selected = true;
      input.value = "";
      changed();
      renderList();
    }
    input.addEventListener("focus", renderList);
    input.addEventListener("input", () => { active = 0; renderList(); });
    input.addEventListener("blur", close);
    input.addEventListener("keydown", event => {
      const options = choices();
      if (event.key === "ArrowDown") { event.preventDefault(); active = Math.min(active + 1, options.length - 1); renderList(); }
      else if (event.key === "ArrowUp") { event.preventDefault(); active = Math.max(active - 1, 0); renderList(); }
      else if (event.key === "Enter" && !list.hidden && options[active]) { event.preventDefault(); choose(options[active]); }
      else if (event.key === "Escape") { close(); }
      else if (event.key === "Backspace" && !input.value && select.selectedOptions.length) {
        select.selectedOptions[select.selectedOptions.length - 1].selected = false;
        changed();
      }
    });
    renderChips();
  });

  // --- Filters start collapsed on phones unless a filter is active.
  document.querySelectorAll("details[data-collapse-on-phone=true]").forEach(details => {
    if (window.matchMedia("(max-width: 560px)").matches) details.open = false;
  });

  // --- Filter bars apply as soon as a choice changes; Apply stays for
  // typing a search and for pages without this script.
  document.querySelectorAll("form[data-filter-form]").forEach(form => {
    form.querySelectorAll("select").forEach(select => select.addEventListener("change", () => form.requestSubmit()));
    const apply = form.querySelector("[data-filter-apply]");
    const search = form.querySelector('input[name="q"]');
    if (apply && search) {
      apply.textContent = tr("Search");
      apply.classList.remove("primary");
      apply.classList.add("button");
    }
  });

  // --- Selects that save as soon as they change.
  document.querySelectorAll("select[data-autosubmit], select[data-autosave]").forEach(select => {
    select.addEventListener("change", () => select.form?.requestSubmit());
  });

  // --- Comments / history tabs on a work item.
  const tabs = Array.from(document.querySelectorAll("[data-wi-tab]"));
  tabs.forEach(tab => tab.addEventListener("click", () => {
    tabs.forEach(other => {
      const selected = other === tab;
      other.setAttribute("aria-selected", String(selected));
      document.getElementById(other.getAttribute("aria-controls")).hidden = !selected;
    });
  }));

  // --- List: change a status inline.
  document.querySelectorAll("select.wi-inline-status").forEach(select => {
    let previous = select.value;
    select.addEventListener("change", async () => {
      select.disabled = true;
      try {
        const body = new URLSearchParams({status_id: select.value});
        const response = await fetch(`/work-items/${encodeURIComponent(select.dataset.itemKey)}/edit`, {
          method: "POST", headers: {"Accept": "application/json", "X-CSRF-Token": csrf}, body,
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || tr("The change could not be saved."));
        previous = select.value;
        select.dataset.category = data.status.category;
        notify(tr("{key} moved to {status}.", {key: data.key, status: data.status.name}), "success");
      } catch (error) {
        select.value = previous;
        notify(error.message, "error");
      } finally {
        select.disabled = false;
      }
    });
  });

  // --- Markdown toolbar and preview on descriptions and comments.
  const MARKS = [
    ["B", "Bold", "**", "**"], ["I", "Italic", "*", "*"], ["</>", "Code", "`", "`"],
    ["🔗", "Link", "[", "](https://)"], ["•", "Bulleted list", "- ", ""], ["1.", "Numbered list", "1. ", ""],
    ["❝", "Quote", "> ", ""],
  ];
  document.querySelectorAll("textarea[data-markdown]").forEach(area => {
    const bar = document.createElement("div");
    bar.className = "md-toolbar";
    bar.setAttribute("role", "toolbar");
    bar.setAttribute("aria-label", tr("Formatting"));
    MARKS.forEach(([text, label, before, after]) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = text;
      button.title = tr(label);
      button.setAttribute("aria-label", tr(label));
      button.addEventListener("click", () => {
        const start = area.selectionStart, end = area.selectionEnd;
        const chosen = area.value.slice(start, end);
        area.setRangeText(before + chosen + after, start, end, "end");
        if (!chosen) area.selectionStart = area.selectionEnd = start + before.length;
        area.focus();
      });
      bar.append(button);
    });
    const previewButton = document.createElement("button");
    previewButton.type = "button";
    previewButton.className = "md-preview-toggle";
    previewButton.textContent = tr("Preview");
    previewButton.setAttribute("aria-pressed", "false");
    const preview = document.createElement("div");
    preview.className = "md md-preview";
    preview.hidden = true;
    previewButton.addEventListener("click", async () => {
      const showing = preview.hidden;
      previewButton.setAttribute("aria-pressed", String(showing));
      previewButton.textContent = showing ? tr("Write") : tr("Preview");
      if (!showing) { preview.hidden = true; area.hidden = false; area.focus(); return; }
      try {
        const data = await postJson("/projects/markdown-preview", {text: area.value});
        preview.innerHTML = data.html || "";  // HTML built server-side from escaped text
      } catch (error) {
        preview.textContent = error.message;
      }
      area.hidden = true;
      preview.hidden = false;
    });
    bar.append(previewButton);
    area.before(bar);
    area.after(preview);
  });

  // --- List: select work items and change them together.
  const bulkBar = document.querySelector("[data-bulk-bar]");
  if (bulkBar) {
    const boxes = () => Array.from(document.querySelectorAll("[data-bulk-item]"));
    const count = bulkBar.querySelector("[data-bulk-count]");
    const update = () => {
      const chosen = boxes().filter(box => box.checked).length;
      bulkBar.hidden = chosen === 0;
      count.textContent = tr("{count} selected", {count: chosen});
    };
    boxes().forEach(box => box.addEventListener("change", update));
    document.querySelectorAll("[data-select-all]").forEach(all => all.addEventListener("change", () => {
      all.closest("table").querySelectorAll("[data-bulk-item]").forEach(box => { box.checked = all.checked; });
      update();
    }));
    const action = bulkBar.querySelector("[data-bulk-action]");
    action.addEventListener("change", () => {
      bulkBar.querySelectorAll("[data-bulk-value]").forEach(field => {
        const active = field.dataset.bulkValue === action.value;
        field.hidden = !active;
        field.querySelectorAll("select, input").forEach(control => { control.disabled = !active; });
      });
    });
    bulkBar.addEventListener("submit", event => {
      if (action.value === "delete" && !window.confirm(bulkBar.querySelector("[data-confirm-delete]").dataset.confirmDelete)) {
        event.preventDefault();
      }
    });
  }

  // --- Attachments: drop a file onto the upload area.
  document.querySelectorAll("form[data-drop-upload]").forEach(form => {
    const zone = form.querySelector(".wi-dropzone");
    const input = form.querySelector("input[type=file]");
    ["dragenter", "dragover"].forEach(name => zone.addEventListener(name, event => { event.preventDefault(); zone.classList.add("is-over"); }));
    ["dragleave", "drop"].forEach(name => zone.addEventListener(name, () => zone.classList.remove("is-over")));
    zone.addEventListener("drop", event => {
      event.preventDefault();
      if (!event.dataTransfer.files.length) return;
      input.files = event.dataTransfer.files;
      form.requestSubmit();
    });
  });

  // --- Keyboard shortcuts (Jira's): ? help, c create, / search, and on a
  // work item e edit, i assign to me, w watch, m comment; j/k move through lists.
  const typing = target => target.closest("input, textarea, select, [contenteditable=true]");
  const rows = () => Array.from(document.querySelectorAll(".wi-table tbody tr, .wi-child-list li"));
  let rowIndex = -1;
  function showShortcutHelp() {
    let dialog = document.getElementById("shortcut-help");
    if (!dialog) {
      dialog = document.createElement("dialog");
      dialog.id = "shortcut-help";
      dialog.className = "shortcut-help";
      dialog.setAttribute("aria-labelledby", "shortcut-help-title");
      const title = document.createElement("h2");
      title.id = "shortcut-help-title";
      title.textContent = tr("Keyboard shortcuts");
      const list = document.createElement("dl");
      [["c", "Create a work item"], ["/", "Search"], ["j / k", "Next or previous work item in a list"],
       ["o", "Open the selected work item"], ["e", "Edit the work item"], ["i", "Assign to me"],
       ["w", "Watch or stop watching"], ["m", "Comment"], ["?", "Show these shortcuts"]].forEach(([keys, label]) => {
        const term = document.createElement("dt");
        const kbd = document.createElement("kbd");
        kbd.textContent = keys;
        term.append(kbd);
        const description = document.createElement("dd");
        description.textContent = tr(label);
        list.append(term, description);
      });
      const close = document.createElement("button");
      close.type = "button";
      close.className = "button";
      close.textContent = tr("Close");
      close.addEventListener("click", () => dialog.close());
      dialog.append(title, list, close);
      document.body.append(dialog);
    }
    dialog.showModal();
  }
  document.addEventListener("keydown", event => {
    if (event.ctrlKey || event.metaKey || event.altKey || typing(event.target)) return;
    const key = event.key;
    const click = selector => { const target = document.querySelector(selector); if (target) { event.preventDefault(); target.click(); } };
    if (key === "?") { event.preventDefault(); showShortcutHelp(); }
    else if (key === "c") {
      event.preventDefault();
      const create = document.querySelector('.project-head-actions a.primary, a[data-shortcut="c"]');
      window.location.href = create ? create.href : "/work-items/new";
    } else if (key === "/") {
      const search = document.querySelector('.project-filters input[name="q"]') || document.querySelector('input[type="search"]');
      if (search) { event.preventDefault(); search.focus(); }
    } else if (key === "e") click('[data-shortcut="e"]');
    else if (key === "i") click('[data-shortcut="i"]');
    else if (key === "w") click('[data-shortcut="w"]');
    else if (key === "m") {
      const comment = document.querySelector('[data-shortcut-target="m"]');
      if (comment) { event.preventDefault(); comment.focus(); comment.scrollIntoView({block: "center"}); }
    } else if (key === "j" || key === "k") {
      const all = rows();
      if (!all.length) return;
      event.preventDefault();
      all[rowIndex]?.classList.remove("is-current");
      rowIndex = Math.max(0, Math.min(all.length - 1, rowIndex + (key === "j" ? 1 : -1)));
      all[rowIndex].classList.add("is-current");
      all[rowIndex].querySelector("a")?.focus();
    } else if (key === "o" && rowIndex >= 0) {
      const link = rows()[rowIndex]?.querySelector("a");
      if (link) { event.preventDefault(); link.click(); }
    }
  });

  // --- Board: drag cards between and within columns.
  const board = document.querySelector("[data-project-board]");
  if (!board || board.dataset.canEdit !== "true") return;

  function refreshColumn(status) {
    board.querySelectorAll(`.project-cards[data-drop-status="${status}"]`).forEach(list => {
      const empty = list.querySelector(".project-empty");
      if (empty) empty.hidden = Boolean(list.querySelector(".wi-card"));
    });
  }

  function adjustCount(status, delta) {
    const head = board.querySelector(`.project-board-heads .project-column[data-status="${status}"]`);
    const badge = head?.querySelector(".project-column-count");
    if (!badge) return;
    const count = Number(badge.dataset.count || 0) + delta;
    const limit = Number(badge.dataset.limit || 0);
    badge.dataset.count = String(count);
    badge.textContent = limit ? `${count} / ${limit}` : String(count);
    head.classList.toggle("over-limit", Boolean(limit) && count > limit);
  }

  let dragging = null;
  let origin = null;

  function cardAfterPointer(list, y) {
    const cards = Array.from(list.querySelectorAll(".wi-card:not(.is-dragging)"));
    return cards.find(card => {
      const box = card.getBoundingClientRect();
      return y < box.top + box.height / 2;
    }) || null;
  }

  board.addEventListener("dragstart", event => {
    const card = event.target.closest(".wi-card[draggable=true]");
    if (!card) return;
    dragging = card;
    origin = {list: card.parentElement, next: card.nextElementSibling};
    card.classList.add("is-dragging");
    board.classList.add("is-dragging-card");
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", card.dataset.itemKey);
  });

  board.addEventListener("dragend", () => {
    dragging?.classList.remove("is-dragging");
    board.classList.remove("is-dragging-card");
    board.querySelectorAll(".drop-target").forEach(list => list.classList.remove("drop-target"));
  });

  board.addEventListener("dragover", event => {
    const list = event.target.closest(".project-cards");
    if (!list || !dragging) return;
    event.preventDefault();
    board.querySelectorAll(".drop-target").forEach(other => other !== list && other.classList.remove("drop-target"));
    list.classList.add("drop-target");
    const after = cardAfterPointer(list, event.clientY);
    const empty = list.querySelector(".project-empty");
    list.insertBefore(dragging, after || empty);
  });

  board.addEventListener("drop", async event => {
    const list = event.target.closest(".project-cards");
    if (!list || !dragging) return;
    event.preventDefault();
    const card = dragging;
    const fromStatus = origin.list.dataset.dropStatus;
    const toStatus = list.dataset.dropStatus;
    const previousCard = card.previousElementSibling?.classList.contains("wi-card") ? card.previousElementSibling : null;
    const nextCard = card.nextElementSibling?.classList.contains("wi-card") ? card.nextElementSibling : null;
    const saved = origin;
    refreshColumn(fromStatus);
    refreshColumn(toStatus);
    if (fromStatus !== toStatus) {
      adjustCount(fromStatus, -1);
      adjustCount(toStatus, 1);
    }
    card.classList.add("is-saving");
    try {
      const data = await postJson(`/work-items/${encodeURIComponent(card.dataset.itemKey)}/move`, {
        status_id: Number(toStatus),
        before_id: previousCard ? Number(previousCard.dataset.itemId) : null,
        after_id: nextCard ? Number(nextCard.dataset.itemId) : null,
      });
      if (fromStatus !== toStatus) notify(tr("{key} moved to {status}.", {key: data.key, status: data.status.name}), "success");
    } catch (error) {
      saved.list.insertBefore(card, saved.next && saved.next.parentElement === saved.list ? saved.next : saved.list.querySelector(".project-empty"));
      if (fromStatus !== toStatus) {
        adjustCount(fromStatus, 1);
        adjustCount(toStatus, -1);
      }
      refreshColumn(fromStatus);
      refreshColumn(toStatus);
      notify(error.message, "error");
    } finally {
      card.classList.remove("is-saving");
    }
  });
})();

(function () {
  "use strict";
  const table = document.querySelector("[data-sprint-backlog]");
  if (!table) return;
  let source = null, saving = false;
  table.addEventListener("dragstart", event => {
    const row = event.target.closest("[data-backlog-row][draggable=true]");
    if (!row || saving) { event.preventDefault(); return; }
    source = row.dataset.backlogRow;
    event.dataTransfer.setData("text/plain", source);
    event.dataTransfer.effectAllowed = "move";
  });
  table.addEventListener("dragover", event => {
    const row = event.target.closest("[data-backlog-row]");
    if (source && row && row.dataset.backlogRow !== source) {
      event.preventDefault(); row.classList.add("sprint-drag-target");
    }
  });
  const clear = () => table.querySelectorAll(".sprint-drag-target").forEach(row => row.classList.remove("sprint-drag-target"));
  table.addEventListener("dragleave", clear);
  table.addEventListener("dragend", () => { clear(); source = null; });
  table.addEventListener("drop", async event => {
    const row = event.target.closest("[data-backlog-row]");
    if (!source || !row || saving) return;
    event.preventDefault(); clear();
    if (source === row.dataset.backlogRow) return;
    const key = source; source = null; saving = true;
    try {
      const response = await fetch(table.dataset.saveUrl, {
        method: "POST", headers: {"Content-Type":"application/json", "Accept":"application/json",
          "X-CSRF-Token":document.querySelector('meta[name="csrf-token"]')?.content || ""},
        body: JSON.stringify({item_keys:[key], sprint_id:table.dataset.sprint ? Number(table.dataset.sprint) : null,
          before_key:row.dataset.backlogRow})
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || tr("The backlog could not be updated."));
      window.location.reload();
    } catch (error) {
      console.error("Sprint ranking request failed");
      const status = document.getElementById("sprint-rank-status");
      if (status) status.textContent = error.message || tr("The backlog could not be updated.");
      if (typeof showToast === "function") showToast(error.message || tr("The backlog could not be updated."), "error");
    } finally { saving = false; }
  });
})();

// Reveal the selected section without scrolling the document or moving focus.
(function () {
  "use strict";
  function revealCurrentSection() {
    try {
      document.querySelectorAll('.project-tabs, .project-global-nav').forEach((nav) => {
        const current = nav.querySelector('a[aria-current]');
        if (!current || nav.clientWidth === 0) return;
        const bounds = nav.getBoundingClientRect();
        const selected = current.getBoundingClientRect();
        const shift = selected.left < bounds.left ? selected.left - bounds.left - 8 :
          selected.right > bounds.right ? selected.right - bounds.right + 8 : 0;
        if (shift) nav.scrollBy({left: shift, behavior: 'instant'});
      });
    } catch (error) {
      console.error('Project navigation selection could not be revealed');
    }
  }
  requestAnimationFrame(revealCurrentSection);
  window.addEventListener('resize', revealCurrentSection, {passive: true});
})();
