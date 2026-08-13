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

  // Administration home's Quick Find (B-318): a flat, always-visible search
  // over every admin capability card -- including small, deeply-nested
  // ones like "LDAP directory sync" that have no other menu entry of their
  // own -- matched against both the card's visible text and a data-keywords
  // attribute carrying synonyms (e.g. "active directory", "sso") a card's
  // own title/description wouldn't otherwise contain. Modeled on Salesforce
  // Setup's Quick Find / ServiceNow's Filter Navigator: live-filters in
  // place, never navigates away just from typing.
  const quickFind = document.querySelector("[data-admin-quick-find]");
  if (quickFind) {
    const sections = [...document.querySelectorAll("[data-admin-home-section]")];
    const emptyState = document.querySelector("[data-admin-quick-find-empty]");
    quickFind.addEventListener("input", () => {
      const query = quickFind.value.trim().toLowerCase();
      let totalMatches = 0;
      sections.forEach((section) => {
        let sectionMatches = 0;
        section.querySelectorAll("[data-admin-quick-find-card]").forEach((card) => {
          const haystack = `${card.textContent} ${card.dataset.keywords || ""}`.toLowerCase();
          const matches = !query || haystack.includes(query);
          card.hidden = !matches;
          if (matches) sectionMatches += 1;
        });
        section.hidden = Boolean(query) && sectionMatches === 0;
        totalMatches += sectionMatches;
      });
      if (emptyState) emptyState.hidden = !query || totalMatches > 0;
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
