// Incident pages: the hold reason follows the State field, and a new incident's
// short description is checked against similar open incidents so a duplicate can
// be linked to its parent instead of logged twice.
document.addEventListener("DOMContentLoaded", () => {
  const tr = window.ServiceOpsI18n?.tr || ((value) => value);
  const form = document.querySelector("#incident-record-form, #incident-create-form");
  if (!form) return;

  const state = form.querySelector('select[name="state"]');
  const hold = form.querySelector("[data-hold-reason]");
  if (state && hold) {
    const sync = () => {
      const pending = state.value === "Pending";
      hold.hidden = !pending;
      hold.querySelector("select").required = pending;
    };
    state.addEventListener("change", sync);
    sync();
  }

  const title = form.querySelector('input[name="title"]');
  const panel = document.querySelector("[data-similar-incidents]");
  if (!title || !panel) return;
  const list = panel.querySelector("ul");
  const parent = form.querySelector('input[name="parent_incident"]');
  let timer = null;
  let lastQuery = "";

  const render = (rows) => {
    list.replaceChildren();
    panel.hidden = rows.length === 0;
    for (const row of rows) {
      const item = document.createElement("li");
      const link = document.createElement("a");
      link.href = row.url;
      link.target = "_blank";
      link.rel = "noopener";
      link.textContent = row.label;
      const meta = document.createElement("small");
      meta.textContent = row.description;
      item.append(link, meta);
      if (parent) {
        const use = document.createElement("button");
        use.type = "button";
        use.className = "link-button";
        use.textContent = tr("Use as parent");
        use.addEventListener("click", () => {
          parent.value = row.value;
          parent.dispatchEvent(new Event("change", {bubbles: true}));
          use.textContent = tr("Parent set");
        });
        item.append(use);
      }
      list.append(item);
    }
  };

  title.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const query = title.value.trim();
      if (query.length < 6 || query === lastQuery) return;
      lastQuery = query;
      try {
        const target = new URL(panel.dataset.similarIncidents, window.location.origin);
        target.searchParams.set("q", query);
        const response = await fetch(target, {headers: {Accept: "application/json"}});
        if (response.ok) render(await response.json());
      } catch (error) {
        panel.hidden = true; // Suggestions are optional; creating the incident still works.
      }
    }, 400);
  });
});
