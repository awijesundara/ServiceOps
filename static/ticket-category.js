// Progressive enhancement for the ticket category/subcategory fields (ticket_form.html,
// incident_detail.html): filters each subcategory <select> to its category's options,
// and reveals a free-text input when "Other" is picked. A form can carry more than one
// pair (logging and closure categorisation); each subcategory names its category via
// data-ticket-subcategory. The server never trusts any of this -- app.py's
// normalize_ticket_category()/normalize_ticket_subcategory() re-validate whatever was
// actually submitted, so a JS-disabled browser still works (every subcategory stays a
// valid, submittable option; only the filtering is lost).
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("select[data-ticket-category]").forEach((category) => {
    const form = category.closest("form");
    if (!form) return;
    const key = category.dataset.ticketCategory;
    const subcategory = form.querySelector(`select[data-ticket-subcategory="${key}"]`);
    const other = form.querySelector(`[data-ticket-subcategory-other="${key}"]`);
    if (!subcategory) return;

    function categoryName() {
      return category.options[category.selectedIndex] ? category.options[category.selectedIndex].text : "";
    }

    function applyFilter() {
      const name = categoryName();
      let sawSelected = false;
      Array.from(subcategory.options).forEach((option) => {
        if (!option.dataset.categoryName) return; // "Not set" / "Other" always shown
        const matches = option.dataset.categoryName === name;
        option.hidden = !matches;
        if (matches && option.selected) sawSelected = true;
      });
      if (!sawSelected && subcategory.value && subcategory.value !== "__other__") subcategory.value = "";
    }

    function syncOther() {
      if (!other) return;
      other.hidden = subcategory.value !== "__other__";
      if (other.hidden) other.value = "";
    }

    category.addEventListener("change", () => { applyFilter(); syncOther(); });
    subcategory.addEventListener("change", syncOther);
    applyFilter();
    syncOther();
  });
});
