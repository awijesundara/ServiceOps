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
    input.placeholder = tr("Add a person…");
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
        empty.textContent = tr("No matching people");
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
        notify(tr("{key} moved to {status}.", {key: data.key, status: data.status.name}), "success");
      } catch (error) {
        select.value = previous;
        notify(error.message, "error");
      } finally {
        select.disabled = false;
      }
    });
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
