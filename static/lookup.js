document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".lookup").forEach(initLookup);
});

function initLookup(container) {
  const url = container.dataset.lookupUrl;
  const input = container.querySelector(".lookup-search");
  const hidden = container.querySelector('input[type="hidden"]');
  const results = container.querySelector(".lookup-results");
  let items = [];
  let activeIndex = -1;
  let debounceTimer = null;

  function render(list) {
    items = list;
    activeIndex = -1;
    results.innerHTML = "";
    if (!list.length) {
      results.hidden = true;
      return;
    }
    list.forEach((item, index) => {
      const row = document.createElement("div");
      row.className = "lookup-result";
      const strong = document.createElement("strong");
      strong.textContent = item.label;
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
      render([]);
      return;
    }
    debounceTimer = setTimeout(async () => {
      const response = await fetch(`${url}?q=${encodeURIComponent(q)}`);
      if (!response.ok) return;
      render(await response.json());
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
