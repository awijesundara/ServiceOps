// ServiceNow-style list filter builder: "choose field / operator / value"
// condition rows that serialize to a `filter` query param (JSON array of
// {field, op, value}), submitted via the list's existing search <form> so
// paging, CSV export links, etc. only need to read one query param.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".list-filter").forEach(initListFilter);
});

const FILTER_OPERATORS = {
  text: [["contains", "contains"], ["eq", "is"], ["starts_with", "starts with"],
         ["is_empty", "is empty"], ["is_not_empty", "is not empty"]],
  choice: [["eq", "is"], ["ne", "is not"], ["is_empty", "is empty"], ["is_not_empty", "is not empty"]],
  date: [["before", "before"], ["after", "after"]],
};

function initListFilter(container) {
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

  const form = container.closest("form");
  const hiddenInput = form ? form.querySelector('input[name="filter"]') : null;
  const toggle = container.querySelector(".list-filter-toggle");
  const builder = container.querySelector(".list-filter-builder");
  const rowsHost = container.querySelector(".list-filter-rows");
  const addButton = container.querySelector(".list-filter-add");
  const clearButton = container.querySelector(".list-filter-clear");

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
      input.value = value || "";
      wrap.appendChild(input);
    } else {
      const input = document.createElement("input");
      input.type = "text";
      input.className = "filter-value";
      input.placeholder = "Value";
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
    fieldKeys.forEach((key) => {
      const option = document.createElement("option");
      option.value = key;
      option.textContent = fields[key].label;
      if (key === initial.field) option.selected = true;
      fieldSelect.appendChild(option);
    });

    const opSelect = document.createElement("select");
    opSelect.className = "filter-op";
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
    removeButton.setAttribute("aria-label", "Remove condition");
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
  if (initialConditions.length) {
    builder.hidden = false;
    container.classList.add("is-open");
  }

  toggle.addEventListener("click", () => {
    builder.hidden = !builder.hidden;
    container.classList.toggle("is-open", !builder.hidden);
    if (!builder.hidden && !rowsHost.children.length) addRow();
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
