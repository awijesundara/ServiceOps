// Lets a user tick which table columns show, persisted per-browser so it
// survives reloads/pagination without needing a server-side preference.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".columns-picker").forEach((picker) => {
    const toggle = picker.querySelector(".columns-picker-toggle");
    const panel = picker.querySelector(".columns-picker-panel");
    const table = document.querySelector(picker.dataset.columnsTarget);
    if (!toggle || !panel || !table) return;
    const key = `columns:${picker.dataset.columnsKey}`;
    let defaultHidden = [];
    try {
      defaultHidden = JSON.parse(picker.dataset.columnsDefaultHidden || "[]");
    } catch (error) {
      defaultHidden = [];
    }
    const readHidden = () => {
      try {
        const stored = JSON.parse(localStorage.getItem(key));
        return Array.isArray(stored) ? stored : defaultHidden;
      } catch (error) {
        return defaultHidden;
      }
    };
    const apply = () => {
      const hidden = readHidden();
      table.querySelectorAll("[data-col]").forEach((cell) => {
        cell.style.display = hidden.includes(cell.dataset.col) ? "none" : "";
      });
      panel.querySelectorAll("input[type=checkbox]").forEach((checkbox) => {
        checkbox.checked = !hidden.includes(checkbox.value);
      });
    };
    toggle.addEventListener("click", (event) => {
      event.stopPropagation();
      const opening = !picker.classList.contains("is-open");
      picker.classList.toggle("is-open", opening);
      panel.hidden = !opening;
    });
    document.addEventListener("click", (event) => {
      if (!picker.contains(event.target)) {
        picker.classList.remove("is-open");
        panel.hidden = true;
      }
    });
    panel.querySelectorAll("input[type=checkbox]").forEach((checkbox) => {
      checkbox.addEventListener("change", () => {
        const hidden = readHidden().filter((value) => value !== checkbox.value);
        if (!checkbox.checked) hidden.push(checkbox.value);
        localStorage.setItem(key, JSON.stringify(hidden));
        apply();
      });
    });
    apply();
  });
});
