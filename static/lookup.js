document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".lookup").forEach(initLookup);
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
    } else {
      input.value = item.value;
    }
    results.hidden = true;
  }

  function highlight() {
    [...results.children].forEach((el, index) => el.classList.toggle("active", index === activeIndex));
  }

  input.addEventListener("input", () => {
    if (hidden) hidden.value = "";
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
