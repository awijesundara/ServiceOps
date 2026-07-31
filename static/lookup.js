document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".lookup").forEach(initLookup);
  initCIBrowser();
});

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function highlightMatch(label, query) {
  if (!query) return document.createTextNode(label);
  const fragment = document.createDocumentFragment();
  const pattern = new RegExp(`(${escapeRegExp(query)})`, "ig");
  const parts = label.split(pattern);
  parts.forEach((part) => {
    if (part.toLowerCase() === query.toLowerCase()) {
      const mark = document.createElement("mark");
      mark.textContent = part;
      fragment.appendChild(mark);
    } else if (part) {
      fragment.appendChild(document.createTextNode(part));
    }
  });
  return fragment;
}

function initLookup(container) {
  const url = container.dataset.lookupUrl;
  const input = container.querySelector(".lookup-search");
  const hidden = container.querySelector('input[type="hidden"]');
  const results = container.querySelector(".lookup-results");
  const spinner = document.createElement("span");
  spinner.className = "lookup-loading";
  container.insertBefore(spinner, results);
  if (url.includes("/lookup/cis") && !input.disabled) {
    container.classList.add("lookup-has-browse");
    const browseButton = document.createElement("button");
    browseButton.type = "button";
    browseButton.className = "lookup-browse";
    browseButton.setAttribute("aria-label", "Browse configuration items");
    browseButton.title = "Browse configuration items";
    browseButton.textContent = "⌕";
    browseButton.addEventListener("click", () => openCIBrowser(input, hidden));
    container.appendChild(browseButton);
  }
  if (url.includes("/lookup/cis") && hidden) {
    const owningTeamHint = document.createElement("p");
    owningTeamHint.className = "lookup-owning-team muted";
    owningTeamHint.hidden = true;
    container.insertAdjacentElement("afterend", owningTeamHint);
    const showOwningTeam = (owningTeam) => {
      owningTeamHint.textContent = `Owning team: ${owningTeam || "Unassigned"}`;
      owningTeamHint.hidden = false;
    };
    hidden.addEventListener("lookup:change", (event) => {
      const item = event.detail;
      if (item && (item.owning_team || item.value)) {
        showOwningTeam(item.owning_team);
      } else {
        owningTeamHint.hidden = true;
      }
    });
    // A CI already selected when the page loaded (editing an existing
    // record) won't fire lookup:change, so show its owning team from the
    // server-rendered data attribute immediately.
    if (hidden.value && hidden.dataset.owningTeam !== undefined) {
      showOwningTeam(hidden.dataset.owningTeam);
    }
  }
  let items = [];
  let activeIndex = -1;
  let debounceTimer = null;
  let lastQuery = "";

  function render(list, options = {}) {
    items = list;
    activeIndex = -1;
    results.innerHTML = "";
    if (!list.length) {
      if (options.searched) {
        const empty = document.createElement("div");
        empty.className = "lookup-empty";
        empty.textContent = "No matches found.";
        results.appendChild(empty);
        results.hidden = false;
      } else {
        results.hidden = true;
      }
      return;
    }
    list.forEach((item, index) => {
      const row = document.createElement("div");
      row.className = "lookup-result";
      const strong = document.createElement("strong");
      strong.appendChild(highlightMatch(item.label, lastQuery));
      const small = document.createElement("small");
      small.textContent = item.description || "";
      row.append(strong, small);
      row.addEventListener("mousedown", (event) => {
        event.preventDefault();
        select(index);
      });
      results.appendChild(row);
    });
    results.hidden = false;
  }

  function select(index) {
    const item = items[index];
    if (!item) return;
    if (hidden) {
      input.value = item.label;
      hidden.value = item.value;
      hidden.dispatchEvent(new CustomEvent("lookup:change", {bubbles: true, detail: item}));
    } else {
      input.value = item.value;
    }
    results.hidden = true;
  }

  function highlight() {
    [...results.children].forEach((el, index) => el.classList.toggle("active", index === activeIndex));
  }

  input.addEventListener("input", () => {
    if (hidden) {
      hidden.value = "";
      hidden.dispatchEvent(new CustomEvent("lookup:change", {bubbles: true, detail: null}));
    }
    const q = input.value.trim();
    clearTimeout(debounceTimer);
    if (q.length < 2) {
      container.classList.remove("is-loading");
      render([]);
      return;
    }
    container.classList.add("is-loading");
    debounceTimer = setTimeout(async () => {
      let response;
      try {
        response = await fetch(`${url}?q=${encodeURIComponent(q)}`);
      } catch (error) {
        container.classList.remove("is-loading");
        window.showToast?.("Search is unavailable right now. Please try again.", "error");
        return;
      }
      container.classList.remove("is-loading");
      if (!response.ok) {
        window.showToast?.("Search is unavailable right now. Please try again.", "error");
        return;
      }
      lastQuery = q;
      render(await response.json(), {searched: true});
    }, 200);
  });

  input.addEventListener("keydown", (event) => {
    if (results.hidden) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      activeIndex = Math.min(activeIndex + 1, items.length - 1);
      highlight();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      activeIndex = Math.max(activeIndex - 1, 0);
      highlight();
    } else if (event.key === "Enter") {
      if (activeIndex >= 0) {
        event.preventDefault();
        select(activeIndex);
      }
    } else if (event.key === "Escape") {
      results.hidden = true;
    }
  });

  input.addEventListener("blur", () => {
    setTimeout(() => { results.hidden = true; }, 150);
  });
}

let ciBrowserTarget = null;
let ciBrowserFiltersLoaded = false;
let ciBrowserDebounce = null;

function openCIBrowser(input, hidden) {
  const modal = document.getElementById("ci-browser-modal");
  if (!modal) return;
  ciBrowserTarget = {input, hidden};
  const q = modal.querySelector(".ci-browser-q");
  q.value = "";
  modal.querySelector(".ci-browser-class").value = "";
  modal.querySelector(".ci-browser-environment").value = "";
  if (typeof modal.showModal === "function") {
    modal.showModal();
  } else {
    modal.setAttribute("open", "");
  }
  runCIBrowserSearch(true);
  q.focus();
}

function renderCIBrowserResults(payload) {
  const modal = document.getElementById("ci-browser-modal");
  const tbody = modal.querySelector(".ci-browser-table tbody");
  tbody.innerHTML = "";
  if (!payload.results.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.className = "empty";
    cell.textContent = "No matching configuration items.";
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }
  payload.results.forEach((ci) => {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const strong = document.createElement("strong");
    strong.textContent = ci.name;
    nameCell.appendChild(strong);
    row.appendChild(nameCell);
    [ci.ci_class, ci.environment, ci.ip_address, ci.status].forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.appendChild(cell);
    });
    row.addEventListener("click", () => {
      if (ciBrowserTarget) {
        ciBrowserTarget.input.value = ci.name;
        if (ciBrowserTarget.hidden) {
          ciBrowserTarget.hidden.value = ci.id;
          ciBrowserTarget.hidden.dispatchEvent(new CustomEvent("lookup:change", {
            bubbles: true,
            detail: {value: ci.id, label: ci.name, owning_team: ci.owning_team},
          }));
        }
      }
      modal.close ? modal.close() : modal.removeAttribute("open");
    });
    tbody.appendChild(row);
  });
}

function populateCIBrowserFilters(payload) {
  if (ciBrowserFiltersLoaded) return;
  const modal = document.getElementById("ci-browser-modal");
  const classSelect = modal.querySelector(".ci-browser-class");
  const envSelect = modal.querySelector(".ci-browser-environment");
  (payload.classes || []).forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    classSelect.appendChild(option);
  });
  (payload.environments || []).forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    envSelect.appendChild(option);
  });
  ciBrowserFiltersLoaded = true;
}

async function runCIBrowserSearch() {
  const modal = document.getElementById("ci-browser-modal");
  const params = new URLSearchParams({
    q: modal.querySelector(".ci-browser-q").value.trim(),
    ci_class: modal.querySelector(".ci-browser-class").value,
    environment: modal.querySelector(".ci-browser-environment").value,
  });
  let response;
  try {
    response = await fetch(`/internal/lookup/cis/browse?${params.toString()}`);
  } catch (error) {
    window.showToast?.("Configuration item search is unavailable right now.", "error");
    return;
  }
  if (!response.ok) {
    window.showToast?.("Configuration item search is unavailable right now.", "error");
    return;
  }
  const payload = await response.json();
  populateCIBrowserFilters(payload);
  renderCIBrowserResults(payload);
}

function initCIBrowser() {
  const modal = document.getElementById("ci-browser-modal");
  if (!modal) return;
  modal.querySelector("[data-ci-browser-close]").addEventListener("click", () => {
    modal.close ? modal.close() : modal.removeAttribute("open");
  });
  modal.addEventListener("click", (event) => {
    if (event.target === modal) modal.close ? modal.close() : modal.removeAttribute("open");
  });
  modal.querySelector(".ci-browser-q").addEventListener("input", () => {
    clearTimeout(ciBrowserDebounce);
    ciBrowserDebounce = setTimeout(runCIBrowserSearch, 200);
  });
  modal.querySelector(".ci-browser-class").addEventListener("change", runCIBrowserSearch);
  modal.querySelector(".ci-browser-environment").addEventListener("change", runCIBrowserSearch);
}
