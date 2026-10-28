// Email service form: show only the fields of the chosen connection method,
// and require only the visible ones (the server validates the same rule).
(() => {
  const form = document.querySelector("[data-email-service-form]");
  if (!form) return;
  const update = () => {
    const method = form.querySelector('input[name="method"]:checked')?.value;
    form.querySelectorAll("[data-methods]").forEach(field => {
      const shown = !method || field.dataset.methods.split(" ").includes(method);
      field.hidden = !shown;
      field.querySelectorAll("input, select, textarea").forEach(input => { input.disabled = !shown; });
    });
    form.querySelectorAll("[data-required]").forEach(input => {
      input.required = !input.disabled;
    });
  };
  form.addEventListener("change", event => {
    if (event.target.name === "method") update();
  });
  update();
})();
