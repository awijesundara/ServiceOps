// List filter builder: "choose field / operator / value"
// condition rows that serialize to a `filter` query param (JSON array of
// {field, op, value}), submitted via the list's existing search <form> so
// paging, CSV export links, etc. only need to read one query param.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".list-filter").forEach(initListFilter);
});

const FILTER_OPERATORS = {
  text: [["contains", tr("contains")], ["eq", tr("is")], ["starts_with", tr("starts with")],
         ["is_empty", tr("is empty")], ["is_not_empty", tr("is not empty")]],
  choice: [["eq", tr("is")], ["ne", tr("is not")], ["is_empty", tr("is empty")], ["is_not_empty", tr("is not empty")]],
  date: [["before", tr("before")], ["after", tr("after")]],
};

function initListFilter(container, index) {
  let fields;
  try {
    fields = JSON.parse(container.dataset.filterFields || "{}");
  } catch (error) {
    fields = {};
  }
  const fieldKeys = Object.keys(fields);
  if (!fieldKeys.length) return;

  let initialConditions = [];
  try {
    initialConditions = JSON.parse(container.dataset.filterValue || "[]");
  } catch (error) {
    initialConditions = [];
  }

  const form = container.closest("form") || document.getElementById(container.dataset.filterForm || "");
  const hiddenInput = form ? form.querySelector('input[name="filter"]') : null;
  const toggle = container.querySelector(".list-filter-toggle");
  const builder = container.querySelector(".list-filter-builder");
  const rowsHost = container.querySelector(".list-filter-rows");
  const addButton = container.querySelector(".list-filter-add");
  const clearButton = container.querySelector(".list-filter-clear");
  const workspace = container.closest(".list-workspace");
  const toggles = [...new Set([toggle, ...(workspace ? workspace.querySelectorAll("[data-list-filter-toggle]") : [])].filter(Boolean))];
  if (!builder.id) builder.id = `list-filter-builder-${index}`;
  toggles.forEach(button => button.setAttribute("aria-controls", builder.id));
  let opener = toggle;
  const setExpanded = expanded => toggles.forEach(button => button.setAttribute("aria-expanded", String(expanded)));

  function associateControl(control) {
    if (form?.id) control.setAttribute("form", form.id);
  }

  function operatorOptions(fieldKey) {
    const type = fields[fieldKey] ? fields[fieldKey].type : "text";
    return FILTER_OPERATORS[type] || FILTER_OPERATORS.text;
  }

  function buildValueControl(fieldKey, op, value) {
    const type = fields[fieldKey] ? fields[fieldKey].type : "text";
    const wrap = document.createElement("span");
    wrap.className = "filter-value-wrap";
    if (op === "is_empty" || op === "is_not_empty") {
      return wrap;
    }
    if (type === "choice") {
      const select = document.createElement("select");
      select.className = "filter-value";
      associateControl(select);
      select.setAttribute("aria-label", fields[fieldKey].label);
      (fields[fieldKey].options || []).forEach(([optValue, optLabel]) => {
        const option = document.createElement("option");
        option.value = optValue;
        option.textContent = optLabel;
        if (optValue === value) option.selected = true;
        select.appendChild(option);
      });
      wrap.appendChild(select);
    } else if (type === "date") {
      const input = document.createElement("input");
      input.type = "date";
      input.className = "filter-value";
      associateControl(input);
      input.setAttribute("aria-label", fields[fieldKey].label);
      input.value = value || "";
      wrap.appendChild(input);
    } else {
      const input = document.createElement("input");
      input.type = "text";
      input.className = "filter-value";
      associateControl(input);
      input.setAttribute("aria-label", fields[fieldKey].label);
      input.placeholder = tr("Value");
      input.value = value || "";
      wrap.appendChild(input);
    }
    return wrap;
  }

  function addRow(condition) {
    const initial = condition || {field: fieldKeys[0], op: operatorOptions(fieldKeys[0])[0][0], value: ""};
    const row = document.createElement("div");
    row.className = "filter-row";

    const fieldSelect = document.createElement("select");
    fieldSelect.className = "filter-field";
    associateControl(fieldSelect);
    fieldSelect.setAttribute("aria-label", tr("Field"));
    fieldKeys.forEach((key) => {
      const option = document.createElement("option");
      option.value = key;
      option.textContent = fields[key].label;
      if (key === initial.field) option.selected = true;
      fieldSelect.appendChild(option);
    });

    const opSelect = document.createElement("select");
    opSelect.className = "filter-op";
    associateControl(opSelect);
    opSelect.setAttribute("aria-label", tr("Operator"));
    function refreshOps() {
      opSelect.innerHTML = "";
      operatorOptions(fieldSelect.value).forEach(([opValue, opLabel]) => {
        const option = document.createElement("option");
        option.value = opValue;
        option.textContent = opLabel;
        if (opValue === initial.op) option.selected = true;
        opSelect.appendChild(option);
      });
    }
    refreshOps();

    let valueWrap = buildValueControl(fieldSelect.value, opSelect.value, initial.value);

    const removeButton = document.createElement("button");
    removeButton.type = "button";
    removeButton.className = "filter-row-remove";
    removeButton.setAttribute("aria-label", tr("Remove condition"));
    removeButton.textContent = "×";
    removeButton.addEventListener("click", () => row.remove());

    fieldSelect.addEventListener("change", () => {
      refreshOps();
      const fresh = buildValueControl(fieldSelect.value, opSelect.value, "");
      valueWrap.replaceWith(fresh);
      valueWrap = fresh;
    });
    opSelect.addEventListener("change", () => {
      const fresh = buildValueControl(fieldSelect.value, opSelect.value, "");
      valueWrap.replaceWith(fresh);
      valueWrap = fresh;
    });

    row.append(fieldSelect, opSelect, valueWrap, removeButton);
    rowsHost.appendChild(row);
  }

  (initialConditions.length ? initialConditions : []).forEach(addRow);
  // Applied conditions do not imply an open editor (for example dashboard links).
  builder.hidden = true;
  container.classList.remove("is-open");
  setExpanded(false);

  toggles.forEach(button => button.addEventListener("click", () => {
    opener = button;
    builder.hidden = !builder.hidden;
    container.classList.toggle("is-open", !builder.hidden);
    setExpanded(!builder.hidden);
    if (!builder.hidden && !rowsHost.children.length) addRow();
    if (!builder.hidden && button.hasAttribute("data-list-filter-toggle")) rowsHost.querySelector("select")?.focus();
  }));

  // The builder floats over the list: close it on a click outside it or on
  // Escape. Conditions stay as edited until Apply.
  const closeBuilder = () => {
    builder.hidden = true;
    container.classList.remove("is-open");
    setExpanded(false);
  };
  document.addEventListener("click", (event) => {
    if (!builder.hidden && !event.composedPath().includes(container) && !toggles.some(button => event.composedPath().includes(button))) closeBuilder();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !builder.hidden) {
      closeBuilder();
      opener.focus();
    }
  });

  addButton.addEventListener("click", () => addRow());

  clearButton.addEventListener("click", () => {
    rowsHost.innerHTML = "";
    if (hiddenInput) hiddenInput.value = "";
    if (form) form.submit();
  });

  if (form) {
    form.addEventListener("submit", () => {
      const conditions = [...rowsHost.children].map((row) => ({
        field: row.querySelector(".filter-field").value,
        op: row.querySelector(".filter-op").value,
        value: (row.querySelector(".filter-value") || {}).value || "",
      }));
      if (hiddenInput) hiddenInput.value = conditions.length ? JSON.stringify(conditions) : "";
    });
  }
}

// Pages with native query/status filters share the same left-hand editor.
// Query mirrors have no name: only the existing form input is submitted.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-native-list-filter]").forEach(container => {
    const form = document.getElementById(container.dataset.filterForm);
    const toggle = container.querySelector("[data-list-filter-toggle]");
    const builder = container.querySelector(".list-filter-builder");
    const mirror = container.querySelector("[data-list-query]");
    const query = form?.querySelector('[name="q"]');
    if (!form || !toggle || !builder) {
      console.error("List filter requires a form, trigger and editor.");
      return;
    }
    builder.id = `${form.id}-filters`;
    toggle.setAttribute("aria-controls", builder.id);
    const close = () => {builder.hidden = true; container.classList.remove("is-open"); toggle.setAttribute("aria-expanded", "false");};
    close();
    toggle.addEventListener("click", () => {
      const opening = builder.hidden;
      if (!opening) {close(); return;}
      builder.hidden = false;
      container.classList.add("is-open");
      toggle.setAttribute("aria-expanded", "true");
      (mirror || builder.querySelector('input,select'))?.focus();
    });
    if (mirror && query) {
      mirror.value = query.value;
      mirror.addEventListener("input", () => {query.value = mirror.value;});
      query.addEventListener("input", () => {mirror.value = query.value;});
    }
    document.addEventListener("click", event => {if (!builder.hidden && !event.composedPath().includes(container)) close();});
    document.addEventListener("keydown", event => {if (event.key === "Escape" && !builder.hidden) {close(); toggle.focus();}});
    container.querySelector('[data-list-filter-clear]')?.addEventListener("click", () => {
      if (query) query.value = "";
      if (mirror) mirror.value = "";
      builder.querySelectorAll('[data-list-native-field]').forEach(control => {
        if (control.type === "checkbox") control.checked = false;
        else control.value = "";
      });
      form.requestSubmit();
    });
  });
});
