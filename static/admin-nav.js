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
      showSearchResults(menuFilter.value.trim());
    });

    // The same box also searches pages/settings that have no sidebar link and
    // offers the full global search, so it never dead-ends on "no match".
    const filterForm = applicationNav.querySelector("[data-nav-filter-form]");
    const results = applicationNav.querySelector("[data-nav-search-results]");
    const pages = results?.querySelector("[data-nav-search-pages]");
    const searchAll = results?.querySelector("[data-nav-search-all]");
    let pending = null;
    let lastQuery = "";
    function showSearchResults(raw) {
      if (!filterForm || !results) return;
      lastQuery = raw;
      clearTimeout(pending);
      if (!raw) {
        results.hidden = true;
        return;
      }
      const target = new URL(filterForm.action, window.location.origin);
      target.searchParams.set("q", raw);
      searchAll.href = target.pathname + target.search;
      searchAll.textContent = searchAll.dataset.labelTemplate.replace("__QUERY__", raw);
      results.hidden = false;
      pending = setTimeout(async () => {
        const url = new URL(filterForm.dataset.navSearchUrl, window.location.origin);
        url.searchParams.set("q", raw);
        try {
          const response = await fetch(url, {headers: {Accept: "application/json"}, credentials: "same-origin"});
          if (!response.ok || raw !== lastQuery) return;
          const rows = await response.json();
          if (raw !== lastQuery) return;
          const sidebarLinks = new Set([...applicationNav.querySelectorAll("a[href]")]
            .filter((link) => !link.closest("[data-nav-search-results]")).map((link) => link.getAttribute("href")));
          pages.replaceChildren(...rows.filter((row) => !sidebarLinks.has(row.url)).map((row) => {
            const link = document.createElement("a");
            link.href = row.url;
            link.textContent = row.label;
            return link;
          }));
          pages.previousElementSibling.hidden = pages.children.length === 0;
          if (emptyState && pages.children.length) emptyState.hidden = true;
        } catch (error) {
          // Offline or signed out: the "search everything" link still works.
        }
      }, 150);
    }
    filterForm?.addEventListener("submit", (event) => {
      const raw = menuFilter.value.trim();
      if (!raw) {
        event.preventDefault();
        return;
      }
      const visible = [...applicationNav.querySelectorAll(".nav-group-items a, .nav-home, [data-nav-search-pages] a")]
        .filter((link) => link.offsetParent !== null && !link.hidden);
      if (visible.length === 1) {
        event.preventDefault();
        window.location.assign(visible[0].href);
      }
      // Otherwise the form submits to the full global search.
    });
  }

  // Administration home's Quick Find (B-318): a flat, always-visible search
  // over every admin capability card -- including small, deeply-nested
  // ones like "LDAP directory sync" that have no other menu entry of their
  // own -- matched against both the card's visible text and a data-keywords
  // attribute carrying synonyms (e.g. "active directory", "sso") a card's
  // own title/description wouldn't otherwise contain. It filters in place
  // and never navigates away just from typing.
  // Word matching shared by the in-page filters: every word must appear, in any
  // order, and singular/plural forms match each other ("teams" finds "Team").
  const stem = (word) => {
    if (word.length > 4 && word.endsWith("ies")) return word.slice(0, -3);
    if (word.length > 3 && word.endsWith("s") && !word.endsWith("ss")) return word.slice(0, -1);
    return word;
  };
  const searchWords = (value) => value.toLocaleLowerCase().replace(/&/g, " ").split(/\s+/).filter(Boolean).map(stem);
  const hasAllWords = (text, words) => {
    const haystack = text.toLocaleLowerCase().replace(/&/g, " ");
    return words.every((word) => haystack.includes(word));
  };

  // Administration section quick find (B-318): filters this area's tool cards,
  // lists matching tools from the other areas and matching settings pages, and
  // offers the full global search. Enter opens the best match.
  const quickFind = document.querySelector("[data-admin-quick-find]");
  if (quickFind) {
    const form = quickFind.closest("[data-admin-quick-find-form]");
    const section = document.querySelector("[data-admin-home-section]");
    const grid = section?.querySelector(".settings-level-grid");
    const cards = [...document.querySelectorAll("[data-admin-quick-find-card]")];
    const emptyState = document.querySelector("[data-admin-quick-find-empty]");
    const more = document.querySelector("[data-admin-quick-find-more]");
    const otherCards = [...document.querySelectorAll("[data-admin-other-card]")];
    const otherHeading = document.querySelector("[data-admin-other-heading]");
    const remoteHeading = document.querySelector("[data-admin-remote-heading]");
    const remoteResults = document.querySelector("[data-admin-remote-results]");
    const searchAll = document.querySelector("[data-admin-search-all]");
    const titleOf = (card) => card.querySelector("strong")?.textContent || "";
    let ranked = [];
    let pending = null;
    let lastQuery = "";

    const rank = (candidates, words) => candidates
      .map((card) => {
        const title = hasAllWords(titleOf(card), words);
        const any = title || hasAllWords(`${card.textContent} ${card.dataset.keywords || ""}`, words);
        return {card, score: title ? 2 : any ? 1 : 0};
      });

    quickFind.addEventListener("input", () => {
      const raw = quickFind.value.trim();
      const words = searchWords(raw);
      lastQuery = raw;
      clearTimeout(pending);
      const local = rank(cards, words);
      local.forEach(({card, score}) => {
        card.hidden = words.length > 0 && score === 0;
        // Cards whose own title matches come first.
        card.style.order = words.length && score === 2 ? "-1" : "";
      });
      const others = rank(otherCards, words);
      others.forEach(({card, score}) => {
        card.hidden = !words.length || score === 0;
        card.style.order = score === 2 ? "-1" : "";
      });
      const localHits = local.filter(({score}) => score > 0).sort((a, b) => b.score - a.score);
      const otherHits = others.filter(({score}) => score > 0).sort((a, b) => b.score - a.score);
      ranked = words.length ? [...localHits, ...otherHits].map(({card}) => card) : [];
      if (section) section.hidden = words.length > 0 && localHits.length === 0;
      if (emptyState) emptyState.hidden = !words.length || localHits.length > 0;
      if (!more) return;
      more.hidden = !words.length;
      if (otherHeading) otherHeading.hidden = otherHits.length === 0;
      if (!words.length) return;
      const target = new URL(form.action, window.location.origin);
      target.searchParams.set("q", raw);
      searchAll.href = target.pathname + target.search;
      searchAll.textContent = searchAll.dataset.labelTemplate.replace("__QUERY__", raw);
      pending = setTimeout(async () => {
        const url = new URL(form.dataset.navSearchUrl, window.location.origin);
        url.searchParams.set("q", raw);
        try {
          const response = await fetch(url, {headers: {Accept: "application/json"}, credentials: "same-origin"});
          if (!response.ok || raw !== lastQuery) return;
          const rows = await response.json();
          if (raw !== lastQuery) return;
          const shown = new Set([...cards, ...otherCards].filter((card) => !card.hidden).map((card) => card.getAttribute("href")));
          const links = rows.filter((row) => !shown.has(row.url)).map((row) => {
            const link = document.createElement("a");
            link.href = row.url;
            link.textContent = row.label;
            return link;
          });
          remoteResults.replaceChildren(...links);
          remoteHeading.hidden = links.length === 0;
          ranked = [...ranked, ...links];
        } catch (error) {
          // The "search everything" link still works.
        }
      }, 150);
    });
    form?.addEventListener("submit", (event) => {
      if (!quickFind.value.trim()) {
        event.preventDefault();
        return;
      }
      if (ranked.length) {
        event.preventDefault();
        window.location.assign(ranked[0].href);
      }
      // No tool or page matched: the form runs the full global search.
    });
  }

  const settingsSearch = document.querySelector("[data-settings-menu-search]");
  if (settingsSearch) {
    const navigation = settingsSearch.closest(".settings-console-nav");
    const links = [...navigation.querySelectorAll("nav a")];
    const headings = [...navigation.querySelectorAll("nav > p")];
    const empty = navigation.querySelector("[data-settings-menu-empty]");
    settingsSearch.addEventListener("input", () => {
      const query = settingsSearch.value.trim().toLowerCase();
      let matches = 0;
      links.forEach((link) => {
        const visible = !query || link.textContent.toLowerCase().includes(query);
        link.hidden = !visible;
        if (visible) matches += 1;
      });
      headings.forEach((heading) => {
        let sibling = heading.nextElementSibling;
        let visible = false;
        while (sibling && sibling.tagName !== "P") {
          if (sibling.tagName === "A" && !sibling.hidden) visible = true;
          sibling = sibling.nextElementSibling;
        }
        heading.hidden = Boolean(query) && !visible;
      });
      if (empty) empty.hidden = !query || matches > 0;
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

  document.querySelectorAll("[data-event-search]").forEach((search) => {
    const list = search.closest("fieldset")?.querySelector("[data-event-list]");
    if (!list) return;
    const options = [...list.querySelectorAll(".subscription-option")];
    search.addEventListener("input", () => {
      const words = searchWords(search.value.trim());
      options.forEach((option) => {
        option.hidden = words.length > 0 && !hasAllWords(option.textContent, words);
      });
    });
  });
});
