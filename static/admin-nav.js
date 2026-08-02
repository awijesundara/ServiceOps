document.addEventListener("DOMContentLoaded", () => {
  const drawers = [...document.querySelectorAll("[data-platform-drawer]")];
  const closeDrawers = () => drawers.forEach((drawer) => { drawer.hidden = true; });
  document.querySelectorAll("[data-open-platform-drawer]").forEach((button) => {
    button.addEventListener("click", () => {
      const drawer = document.querySelector(`[data-platform-drawer="${button.dataset.openPlatformDrawer}"]`);
      closeDrawers();
      document.querySelectorAll(".sidebar-switcher button").forEach((tab) => tab.classList.remove("active"));
      if (drawer) {
        drawer.hidden = false;
        button.classList.add("active");
        drawer.querySelector("input")?.focus();
      }
    });
  });
  document.querySelectorAll("[data-close-platform-drawer]").forEach((button) => {
    button.addEventListener("click", closeDrawers);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") document.querySelector(".sidebar-panel:not([hidden]) input")?.blur();
  });

  const allFilter = document.querySelector("[data-all-menu-filter]");
  if (allFilter) {
    const applications = [...document.querySelectorAll("[data-all-menu-applications] details")];
    allFilter.addEventListener("input", () => {
      const query = allFilter.value.trim().toLowerCase();
      applications.forEach((application) => {
        const modules = [...application.querySelectorAll("a")];
        const titleMatches = application.querySelector("summary").textContent.toLowerCase().includes(query);
        let visible = 0;
        modules.forEach((module) => {
          const match = !query || titleMatches || module.textContent.toLowerCase().includes(query);
          module.hidden = !match;
          if (match) visible += 1;
        });
        application.hidden = visible === 0;
        if (query && visible) application.open = true;
      });
    });
  }

  const filter = document.querySelector("[data-admin-nav-filter]");
  if (filter) {
    const groups = [...document.querySelectorAll("[data-admin-nav-group]")];
    const empty = document.querySelector("[data-admin-nav-empty]");
    filter.addEventListener("input", () => {
      const query = filter.value.trim().toLowerCase();
      let matches = 0;
      groups.forEach((group) => {
        let groupMatches = 0;
        group.querySelectorAll(".admin-module").forEach((module) => {
          const visible = !query || module.textContent.toLowerCase().includes(query);
          module.hidden = !visible;
          if (visible) groupMatches += 1;
        });
        group.hidden = groupMatches === 0;
        if (query && groupMatches) group.open = true;
        matches += groupMatches;
      });
      if (empty) empty.hidden = matches !== 0;
    });
  }

  document.querySelectorAll("[data-open-nav-menu]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = document.querySelector(`[data-nav-menu="${button.dataset.openNavMenu}"]`);
      if (!target) return;
      document.querySelectorAll("[data-nav-menu]").forEach((menu) => {
        if (menu !== target) menu.open = false;
      });
      target.open = !target.open;
    });
  });
});
