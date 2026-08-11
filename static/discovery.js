(() => {
  const rows = [...document.querySelectorAll("[data-device-row]")];
  const query = document.getElementById("device-filter-query");
  const classFilter = document.getElementById("device-filter-class");
  const vendorFilter = document.getElementById("device-filter-vendor");
  const sourceFilter = document.getElementById("device-filter-source");
  const master = document.getElementById("review-select-all-checkbox");
  const summary = document.getElementById("device-selection-summary");
  const empty = document.getElementById("device-filter-empty");

  if (rows.length && query && classFilter && vendorFilter && sourceFilter && master && summary) {
    const checkbox = (row) => row.querySelector('input[name="candidate_id"]');
    const visibleRows = () => rows.filter((row) => !row.hidden);
    const column = { class: 4, vendor: 5, source: 6 };
    const addOptions = (select, field) => {
      [...new Set(rows.map((row) => row.dataset[field]).filter(Boolean))].sort().forEach((value) => {
        const matchingRow = rows.find((row) => row.dataset[field] === value);
        const option = document.createElement("option");
        option.value = value;
        option.textContent = matchingRow.querySelector(`td:nth-child(${column[field]})`).textContent.trim();
        select.append(option);
      });
    };
    addOptions(classFilter, "class");
    addOptions(vendorFilter, "vendor");
    addOptions(sourceFilter, "source");

    const normalize = (value) => (value || "")
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLocaleLowerCase()
      .replace(/\s+/g, " ")
      .trim();
    rows.forEach((row) => {
      row.dataset.searchText = normalize(row.textContent);
    });

    const updateSummary = () => {
      const visible = visibleRows();
      const selected = rows.filter((row) => checkbox(row).checked);
      const selectedVisible = visible.filter((row) => checkbox(row).checked);
      summary.textContent = `${visible.length} of ${rows.length} shown · ${selected.length} selected`;
      master.checked = visible.length > 0 && selectedVisible.length === visible.length;
      master.indeterminate = selectedVisible.length > 0 && selectedVisible.length < visible.length;
      empty.hidden = visible.length !== 0;
    };
    const applyFilters = () => {
      const terms = normalize(query.value).split(" ").filter(Boolean);
      rows.forEach((row) => {
        const searchable = row.dataset.searchText;
        row.hidden = Boolean((terms.length && !terms.every((term) => searchable.includes(term))) ||
          (classFilter.value && row.dataset.class !== classFilter.value) ||
          (vendorFilter.value && row.dataset.vendor !== vendorFilter.value) ||
          (sourceFilter.value && row.dataset.source !== sourceFilter.value));
      });
      updateSummary();
    };
    ["input", "search", "change"].forEach((eventName) => query.addEventListener(eventName, applyFilters));
    [classFilter, vendorFilter, sourceFilter].forEach((control) => control.addEventListener("change", applyFilters));
    rows.forEach((row) => checkbox(row).addEventListener("change", updateSummary));
    master.addEventListener("change", () => {
      visibleRows().forEach((row) => { checkbox(row).checked = master.checked; });
      updateSummary();
    });
    document.querySelectorAll("[data-selection]").forEach((button) => button.addEventListener("click", () => {
      const action = button.dataset.selection;
      const targets = action.endsWith("visible") ? visibleRows() : rows;
      const checked = action.startsWith("select");
      targets.forEach((row) => { checkbox(row).checked = checked; });
      updateSummary();
    }));
    document.getElementById("device-filter-clear")?.addEventListener("click", () => {
      query.value = classFilter.value = vendorFilter.value = sourceFilter.value = "";
      applyFilters();
      query.focus();
    });
    updateSummary();
  }

  document.querySelectorAll(".discovery-run-form").forEach((form) => {
    form.addEventListener("submit", () => {
      const button = form.querySelector("button");
      button.disabled = true;
      button.innerHTML = '<span class="discovery-spinner" aria-hidden="true"></span> Running…';
      const note = document.createElement("span");
      note.className = "discovery-run-note";
      note.textContent = form.dataset.targetType === "subnet" ? "Scanning subnet…" : "Scanning device…";
      form.append(note);
    });
  });

  // Plain <form data-confirm> submits are handled globally by platform.js's
  // delegated listener. Only the button-level case remains here: a button
  // with both `formaction` (targeting a different form than the one it
  // sits in) and its own `data-confirm` -- platform.js's submit listener
  // only ever sees the target <form>, never the button that triggered it,
  // so it can't catch this variant.
  document.querySelectorAll("button[data-confirm][formaction]").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (!window.confirm(button.dataset.confirm)) event.preventDefault();
    });
  });
})();
