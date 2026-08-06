document.addEventListener("DOMContentLoaded", () => {
  const applicationNav = document.querySelector("[data-application-nav]");
  if (applicationNav) {
    const topGroups = [...applicationNav.querySelectorAll(":scope > .nav-group")];
    topGroups.forEach((group) => {
      group.addEventListener("toggle", () => {
        if (!group.open || applicationNav.classList.contains("is-filtering")) return;
        topGroups.forEach((other) => {
          if (other !== group) other.open = false;
        });
      });
    });

    const menuFilter = applicationNav.querySelector("[data-nav-filter]");
    const emptyState = applicationNav.querySelector("[data-nav-filter-empty]");
    const home = applicationNav.querySelector(".nav-home");
    const normalize = (value) => value.toLocaleLowerCase().replace(/&/g, "and");
    menuFilter?.addEventListener("input", () => {
      const query = normalize(menuFilter.value.trim());
      applicationNav.classList.toggle("is-filtering", Boolean(query));
      let matchCount = 0;

      if (home) {
        const matches = !query || normalize(home.textContent).includes(query);
        home.toggleAttribute("data-filter-match", matches && Boolean(query));
        home.hidden = !matches;
        if (matches) matchCount += 1;
      }

      topGroups.forEach((group) => {
        const directSummary = group.querySelector(":scope > summary");
        const groupMatch = normalize(directSummary?.textContent || "").includes(query);
        let groupMatches = 0;
        group.querySelectorAll("a").forEach((link) => {
          const matches = !query || groupMatch || normalize(link.textContent).includes(query);
          link.hidden = !matches;
          if (matches) groupMatches += 1;
        });
        group.querySelectorAll(".nav-subgroup").forEach((subgroup) => {
          const visibleLinks = [...subgroup.querySelectorAll("a")].some((link) => !link.hidden);
          const subgroupMatch = normalize(subgroup.querySelector(":scope > summary")?.textContent || "").includes(query);
          subgroup.hidden = Boolean(query) && !visibleLinks && !subgroupMatch;
          if (query && (visibleLinks || subgroupMatch)) subgroup.open = true;
        });
        const matches = !query || groupMatch || groupMatches > 0;
        group.toggleAttribute("data-filter-match", matches && Boolean(query));
        group.hidden = !matches;
        if (query && matches) group.open = true;
        matchCount += groupMatches;
      });
      if (emptyState) emptyState.hidden = !query || matchCount > 0;
    });
  }

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
