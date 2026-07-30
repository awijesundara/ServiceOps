// Progressively enhances plain <select> elements into searchable comboboxes
// (type to filter, arrow keys + enter to choose) without changing form
// submission at all -- the original <select> stays in the DOM as the source
// of truth for name/value/required/change events; this only adds a visible
// text input + filtered listbox on top of it.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("select").forEach(enhanceSelect);
});

function enhanceSelect(select) {
  if (select.multiple || select.dataset.plain !== undefined) return;
  if (select.closest(".select-enhance, .lookup")) return;
  if (select.options.length < 5) return;

  const wrapper = document.createElement("div");
  wrapper.className = "select-enhance";
  select.parentNode.insertBefore(wrapper, select);
  wrapper.appendChild(select);

  const input = document.createElement("input");
  input.type = "text";
  input.className = "select-enhance-input";
  input.autocomplete = "off";
  input.spellcheck = false;
  if (select.disabled) input.disabled = true;
  if (select.required) input.required = true;
  wrapper.appendChild(input);

  const panel = document.createElement("div");
  panel.className = "lookup-results select-enhance-results";
  panel.hidden = true;
  wrapper.appendChild(panel);

  let activeIndex = -1;

  const realOptions = () => Array.from(select.options).filter((option) => option.value !== "" || option.textContent.trim());

  function syncInputFromSelect() {
    const chosen = select.options[select.selectedIndex];
    input.value = chosen ? chosen.textContent.trim() : "";
  }
  syncInputFromSelect();

  function updateActive(rows) {
    rows.forEach((row, index) => row.classList.toggle("active", index === activeIndex));
    rows[activeIndex]?.scrollIntoView({block: "nearest"});
  }

  function choose(option) {
    select.value = option.value;
    input.value = option.textContent.trim();
    select.dispatchEvent(new Event("change", {bubbles: true}));
    close();
  }

  function close() {
    panel.hidden = true;
    activeIndex = -1;
  }

  function render(query) {
    const q = query.trim().toLowerCase();
    const matches = realOptions().filter((option) => !q || option.textContent.toLowerCase().includes(q));
    panel.innerHTML = "";
    activeIndex = -1;
    if (!matches.length) {
      const empty = document.createElement("div");
      empty.className = "lookup-empty";
      empty.textContent = "No matches found.";
      panel.appendChild(empty);
    } else {
      matches.slice(0, 300).forEach((option) => {
        const row = document.createElement("div");
        row.className = "lookup-result select-enhance-option";
        row.dataset.value = option.value;
        const strong = document.createElement("strong");
        strong.appendChild(highlightMatch(option.textContent.trim(), query.trim()));
        row.appendChild(strong);
        if (option.value === select.value) row.classList.add("current");
        row.addEventListener("mousedown", (event) => {
          event.preventDefault();
          choose(option);
        });
        panel.appendChild(row);
      });
    }
    panel.hidden = false;
  }

  input.addEventListener("focus", () => {
    input.select();
    render("");
  });
  input.addEventListener("input", () => render(input.value));
  input.addEventListener("blur", () => {
    window.setTimeout(() => {
      if (!wrapper.contains(document.activeElement)) {
        syncInputFromSelect();
        close();
      }
    }, 120);
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      if (panel.hidden) { render(input.value); return; }
      const rows = Array.from(panel.querySelectorAll(".select-enhance-option"));
      activeIndex = Math.min(activeIndex + 1, rows.length - 1);
      updateActive(rows);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      const rows = Array.from(panel.querySelectorAll(".select-enhance-option"));
      activeIndex = Math.max(activeIndex - 1, 0);
      updateActive(rows);
    } else if (event.key === "Enter") {
      if (!panel.hidden && activeIndex >= 0) {
        const rows = Array.from(panel.querySelectorAll(".select-enhance-option"));
        const value = rows[activeIndex]?.dataset.value;
        const option = realOptions().find((candidate) => candidate.value === value);
        if (option) {
          event.preventDefault();
          choose(option);
        }
      }
    } else if (event.key === "Escape") {
      syncInputFromSelect();
      close();
    } else if (event.key === "Tab") {
      close();
    }
  });
  select.addEventListener("change", syncInputFromSelect);
}
