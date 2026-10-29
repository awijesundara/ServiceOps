function showToast(message, category) {
  let stack = document.querySelector(".toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.className = "toast-stack";
    document.body.appendChild(stack);
  }
  const toast = document.createElement("div");
  toast.className = `toast${category ? ` ${category}` : ""}`;
  toast.setAttribute("role", "status");
  const text = document.createElement("p");
  text.textContent = message;
  const close = document.createElement("button");
  close.type = "button";
  close.className = "toast-close";
  close.setAttribute("aria-label", tr("Dismiss"));
  close.textContent = "×";
  close.addEventListener("click", () => toast.remove());
  toast.append(text, close);
  stack.appendChild(toast);
  setTimeout(() => toast.remove(), 6000);
}
window.showToast = showToast;

// Click-to-enlarge for image attachments: a small inline thumbnail (see
// .attachment-thumb) opens the full image in an in-page overlay instead of
// a new tab, per user request for a less disruptive preview.
function openLightbox(src, title, type) {
  const overlay = document.getElementById("lightbox-overlay");
  if (!overlay) return;
  const img = overlay.querySelector(".lightbox-img");
  const pdf = overlay.querySelector(".lightbox-pdf");
  if (type === "pdf") {
    img.hidden = true;
    img.src = "";
    pdf.hidden = false;
    pdf.src = src;
  } else {
    pdf.hidden = true;
    pdf.src = "";
    img.hidden = false;
    img.src = src;
  }
  overlay.querySelector(".lightbox-caption").textContent = title || "";
  overlay.hidden = false;
  document.body.classList.add("lightbox-open");
}
function closeLightbox() {
  const overlay = document.getElementById("lightbox-overlay");
  if (!overlay) return;
  overlay.hidden = true;
  overlay.querySelector(".lightbox-img").src = "";
  overlay.querySelector(".lightbox-pdf").src = "";
  document.body.classList.remove("lightbox-open");
}
document.addEventListener("click", (event) => {
  const trigger = event.target.closest("[data-lightbox-src]");
  if (trigger) {
    event.preventDefault();
    event.stopPropagation();
    openLightbox(trigger.dataset.lightboxSrc, trigger.dataset.lightboxTitle, trigger.dataset.lightboxType);
    return;
  }
  if (event.target.closest(".lightbox-close") || event.target.id === "lightbox-overlay") closeLightbox();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeLightbox();
});

// Dropdown menus are <details> whose panel floats over the page (top-bar
// menus, "More" menus, pickers). Close them on a click anywhere outside, and
// the innermost one on Escape. In-flow <details> -- sidebar groups, form
// sections like "Edit stage" -- are disclosures, not menus, and stay as set.
const isFloatingMenu = (details) => Array.from(details.children).some((child) => {
  if (child.tagName === "SUMMARY") return false;
  const position = getComputedStyle(child).position;
  return position === "absolute" || position === "fixed";
});
const openFloatingMenus = () => Array.from(document.querySelectorAll("details[open]")).filter(isFloatingMenu);
document.addEventListener("click", (event) => {
  // The path is fixed when the click happens, so a button that removes itself
  // (a "remove" × inside a menu) still counts as inside.
  const path = event.composedPath();
  openFloatingMenus().forEach((details) => {
    if (!path.includes(details)) details.open = false;
  });
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  const menus = openFloatingMenus();
  const innermost = menus.find((details) => !menus.some((other) => other !== details && details.contains(other)));
  if (!innermost) return;
  innermost.open = false;
  innermost.querySelector(":scope > summary")?.focus();
});

// Plain <form method="post"> submits reload the page and the browser resets
// scroll to the top; on long admin/config pages with many independent forms
// that means every save loses your place. Remember where you were per-page
// and restore it once, instead of forcing the user to scroll back down.
if ("scrollRestoration" in history) history.scrollRestoration = "manual";
(() => {
  const key = `scrollY:${location.pathname}`;
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (form instanceof HTMLFormElement && form.method.toLowerCase() !== "get") {
      sessionStorage.setItem(key, String(window.scrollY));
    }
  });
  const saved = sessionStorage.getItem(key);
  if (saved !== null) {
    sessionStorage.removeItem(key);
    const y = parseInt(saved, 10);
    if (!Number.isNaN(y)) {
      requestAnimationFrame(() => window.scrollTo(0, y));
      setTimeout(() => window.scrollTo(0, y), 0);
    }
  }
})();

document.addEventListener("DOMContentLoaded", () => {
  // Wide record tables intentionally scroll inside the page. Give every
  // such region a keyboard stop and an accessible name so keyboard and
  // screen-reader users can reach and operate the horizontal viewport.
  document.querySelectorAll(".task-list-scroll").forEach((region) => {
    region.tabIndex = 0;
    region.setAttribute("role", "region");
    if (!region.getAttribute("aria-label")) region.setAttribute("aria-label", tr("Scrollable records"));
  });

  if ("serviceWorker" in navigator && window.isSecureContext) {
    navigator.serviceWorker.register("/service-worker.js", { scope: "/" });
  }
  const body = document.body;
  const path = location.pathname + location.search;
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const csrfHeaders = {"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrfToken};
  // Adds/moves an entry to the top of a nav-popover list (Favorites,
  // Recently viewed) without a page refresh -- both lists used to only
  // reflect a change after the next full page load, since the click/visit
  // handlers below only patched the star icon or button text, never the
  // list markup itself.
  function upsertNavPopoverEntry(container, urlAttr, emptyAttr, url, label) {
    if (!container) return;
    container.querySelector(`[${emptyAttr}]`)?.remove();
    container.querySelector(`a[${urlAttr}="${CSS.escape(url)}"]`)?.remove();
    const link = document.createElement("a");
    link.href = url;
    link.textContent = label;
    link.setAttribute(urlAttr, url);
    link.classList.add("nav-popover-entry-new");
    container.prepend(link);
    requestAnimationFrame(() => link.classList.remove("nav-popover-entry-new"));
  }
  function removeNavPopoverEntry(container, urlAttr, emptyAttr, emptyText, url) {
    if (!container) return;
    container.querySelector(`a[${urlAttr}="${CSS.escape(url)}"]`)?.remove();
    if (!container.querySelector("a")) {
      const empty = document.createElement("p");
      empty.setAttribute(emptyAttr, "");
      empty.textContent = emptyText;
      container.appendChild(empty);
    }
  }
  if (body.querySelector(".sidebar")) {
    const label = document.title;
    const data = new URLSearchParams({url: path, label});
    fetch("/ui/history", {method: "POST", headers: csrfHeaders, body: data})
      .then((response) => (response.ok ? response.json() : null))
      .then((result) => {
        if (!result) return;
        upsertNavPopoverEntry(
          document.querySelector("[data-history-list]"), "data-history-url", "data-history-empty",
          result.url || path, result.label || label,
        );
      })
      .catch(() => {});
  }
  // "Forgot your password?" only applies to a local account -- an AD/LDAP
  // password reset isn't something ServiceOps's local reset flow can do, so
  // hide the link live as the selected authentication source changes rather
  // than only deciding it once at page render.
  const authProviderSelect = document.querySelector("[data-auth-provider-select]");
  const forgotPasswordLink = document.querySelector("[data-forgot-password-link]");
  if (authProviderSelect && forgotPasswordLink) {
    const syncForgotPasswordVisibility = () => {
      forgotPasswordLink.hidden = authProviderSelect.value !== "local";
    };
    authProviderSelect.addEventListener("change", syncForgotPasswordVisibility);
    syncForgotPasswordVisibility();
  }
  // When both local and directory sign-in are enabled, the username
  // field's ghost text should match whichever is currently selected --
  // the LDAP-flavored placeholder (server-rendered with the site's actual
  // domain from LDAP_BASE_DN) doesn't apply to a local account.
  const usernameInput = document.querySelector("[data-username-input]");
  if (usernameInput && authProviderSelect) {
    const ldapPlaceholder = usernameInput.dataset.ldapPlaceholder || "Username";
    const syncUsernamePlaceholder = () => {
      usernameInput.placeholder = authProviderSelect.value === "ldap" ? ldapPlaceholder : "Username";
    };
    authProviderSelect.addEventListener("change", syncUsernamePlaceholder);
    syncUsernamePlaceholder();
  }
  const navToggle = document.querySelector("[data-nav-toggle]");
  if (navToggle) {
    navToggle.setAttribute("aria-expanded", body.classList.contains("nav-collapsed") ? "false" : "true");
  }
  navToggle?.addEventListener("click", () => {
    const collapsed = body.classList.toggle("nav-collapsed");
    localStorage.setItem("navCollapsed", collapsed ? "1" : "0");
    navToggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
  });
  document.querySelectorAll("[data-print-page]").forEach(button => {
    button.addEventListener("click", () => window.print());
  });
  // A master switch with data-enables="<fieldset id>" enables or greys out
  // the switches that depend on it (email notification types). Disabled
  // fields are not submitted, and the server keeps their saved values.
  document.addEventListener("change", event => {
    const id = event.target.dataset?.enables;
    const group = id && document.getElementById(id);
    if (!group) return;
    group.disabled = !event.target.checked;
    group.querySelectorAll("[data-text-enabled]").forEach(note => {
      note.textContent = event.target.checked ? note.dataset.textEnabled : note.dataset.textDisabled;
    });
  });
  // Confirmation prompts on destructive forms can't use an inline
  // onsubmit="return confirm(...)" attribute -- this app's CSP is
  // script-src 'self' with no 'unsafe-inline', which silently blocks
  // inline event handlers (the form still submits, just with no prompt,
  // exactly the print-button bug this same pattern already fixed once).
  // A single delegated listener reading data-confirm works with the CSP
  // unchanged, same as data-print-page above.
  document.addEventListener("submit", event => {
    const form = event.target.closest("[data-confirm]");
    if (form && !window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });
  // Same CSP issue, different attribute: an inline onchange="this.form.submit()"
  // on a filter <select> is blocked exactly like the confirm() handlers
  // above, so choosing a filter option silently did nothing.
  document.addEventListener("change", event => {
    if (event.target.matches("[data-auto-submit]")) {
      event.target.form?.submit();
    }
  });
  // Warn before a user loses typed-but-unsubmitted work on a long form --
  // a restart (even a graceful one -- see Dockerfile STOPSIGNAL -- still
  // takes the app a few seconds to come back), an accidental back/reload,
  // or a session-timeout redirect could otherwise silently discard
  // everything they typed with no warning at all. Opt-in via
  // data-track-dirty (login/search/filter forms shouldn't prompt) rather
  // than tracking every form on the page. Delegated listeners, same CSP-safe
  // pattern as data-confirm/data-auto-submit above.
  const dirtyForms = new Set();
  document.addEventListener("input", event => {
    const form = event.target.closest("[data-track-dirty]");
    if (form) dirtyForms.add(form);
  });
  document.addEventListener("change", event => {
    const form = event.target.closest("[data-track-dirty]");
    if (form) dirtyForms.add(form);
  });
  document.addEventListener("submit", event => {
    dirtyForms.delete(event.target);
  });
  window.addEventListener("beforeunload", event => {
    if (dirtyForms.size === 0) return;
    event.preventDefault();
    event.returnValue = "";
  });

  const slaTargetType = document.getElementById("sla-target-type");
  const slaClientOrgField = document.getElementById("sla-client-org-field");
  if (slaTargetType && slaClientOrgField) {
    const syncSlaClientOrgField = () => {
      slaClientOrgField.hidden = slaTargetType.value !== "client_ticket";
    };
    slaTargetType.addEventListener("change", syncSlaClientOrgField);
    syncSlaClientOrgField();
  }
  document.querySelectorAll(".org2-toggle:not(.org2-toggle-leaf)").forEach(toggle => {
    toggle.setAttribute("data-org2-toggle", "");
    toggle.addEventListener("click", () => {
      const li = toggle.closest("li");
      const kids = li?.querySelector(":scope > .org2-children");
      if (!kids) return;
      const collapsed = kids.style.display === "none";
      kids.style.display = collapsed ? "" : "none";
      toggle.textContent = collapsed ? "▾" : "▸";
    });
  });
  // Initial scroll position is restored synchronously by nav-init.js (loaded
  // before this deferred script runs) so the sidebar never visibly jumps
  // after paint; this listener only needs to keep saving it going forward.
  const sidebarNav = document.querySelector(".sidebar nav");
  if (sidebarNav) {
    sidebarNav.addEventListener("scroll", () => {
      sessionStorage.setItem("sidebarNavScrollTop", String(sidebarNav.scrollTop));
    });
  }
  document.querySelector("[data-favorite]")?.addEventListener("click", async (event) => {
    // event.currentTarget is only valid during synchronous dispatch -- the
    // browser resets it to null once the handler yields at the first
    // `await`, so it must be captured up front rather than read after the
    // fetch resolves (this was silently throwing and aborting the whole
    // handler before the list/star/toast updates below ever ran).
    const button = event.currentTarget;
    const data = new URLSearchParams({url: path, label: document.querySelector("h1")?.textContent || document.title});
    let response;
    try {
      response = await fetch("/ui/favorite", {method: "POST", headers: csrfHeaders, body: data});
    } catch (error) {
      showToast(tr("Could not reach the server. Check your connection and try again."), "error");
      return;
    }
    if (!response.ok) {
      showToast(tr("Could not update favorites. Please try again."), "error");
      return;
    }
    const result = await response.json();
    button.textContent = result.active
      ? tr("Remove this page from favorites")
      : tr("Add this page to favorites");
    const star = document.querySelector("[data-favorite-star]");
    if (star) star.setAttribute("data-active", result.active ? "true" : "false");
    const favoritesList = document.querySelector("[data-favorites-list]");
    if (result.active) {
      upsertNavPopoverEntry(favoritesList, "data-favorite-url", "data-favorites-empty", result.url, result.label);
      showToast(tr("Added to favorites."), "success");
    } else {
      removeNavPopoverEntry(favoritesList, "data-favorite-url", "data-favorites-empty", tr("No favorites yet."), result.url);
      showToast(tr("Removed from favorites."), "success");
    }
  });
  // Task board: the card moves at once (optimistic), shows "saving" until
  // the server answers, and goes back with a message if it refuses. Lane
  // counts and the empty-lane placeholder follow every move.
  let dragged = null;
  const board = document.querySelector(".task-board");
  function refreshLane(lane, delta) {
    const cards = lane.querySelector(".board-cards");
    const empty = cards.querySelector(".board-empty");
    if (empty) {
      empty.hidden = Boolean(cards.querySelector(".board-card"));
      cards.appendChild(empty);  // keep the placeholder last
    }
    const count = lane.querySelector(".board-count");
    if (count && delta) {
      const value = Math.max(0, Number(count.dataset.count || 0) + delta);
      count.dataset.count = String(value);
      count.textContent = String(value);
    }
  }
  document.querySelectorAll(".board-card[draggable=true]").forEach(card => {
    card.addEventListener("dragstart", event => {
      dragged = card;
      card.classList.add("dragging");
      board?.classList.add("is-dragging");
      if (event.dataTransfer) { event.dataTransfer.effectAllowed = "move"; event.dataTransfer.setData("text/plain", card.dataset.ticket); }
    });
    card.addEventListener("dragend", () => {
      card.classList.remove("dragging");
      board?.classList.remove("is-dragging");
      document.querySelectorAll(".board-lane.drop-target").forEach(lane => lane.classList.remove("drop-target"));
    });
  });
  document.querySelectorAll(".board-lane").forEach(lane => {
    lane.addEventListener("dragover", event => { event.preventDefault(); lane.classList.add("drop-target"); });
    lane.addEventListener("dragleave", event => {
      if (!lane.contains(event.relatedTarget)) lane.classList.remove("drop-target");
    });
    lane.addEventListener("drop", async event => {
      event.preventDefault();
      lane.classList.remove("drop-target");
      const card = dragged;
      dragged = null;
      if (!card) return;
      const source = card.closest(".board-lane");
      if (source === lane) return;
      const before = card.nextSibling;
      lane.querySelector(".board-cards").prepend(card);
      card.classList.add("is-saving");
      refreshLane(lane, 1);
      refreshLane(source, -1);
      const undo = message => {
        source.querySelector(".board-cards").insertBefore(card, before && before.parentNode ? before : null);
        refreshLane(source, 1);
        refreshLane(lane, -1);
        showToast(message, "error");
      };
      const data = new URLSearchParams({state: lane.dataset.state});
      let response;
      try {
        response = await fetch(`/task-board/${card.dataset.ticket}/move`, {method: "POST", headers: csrfHeaders, body: data});
      } catch (error) {
        card.classList.remove("is-saving");
        undo(tr("Could not reach the server. The card was not moved."));
        return;
      }
      card.classList.remove("is-saving");
      if (response.ok) {
        const number = card.querySelector("a")?.textContent || "";
        showToast(tr("{number} moved to {state}.", {number, state: lane.querySelector("h2")?.textContent || lane.dataset.state}), "success");
      } else {
        let message = tr("Could not move this card. Please try again.");
        try {
          message = (await response.json()).error || message;
        } catch (error) {
          // Not a JSON refusal; keep the generic message.
        }
        undo(message);
      }
    });
  });
  document.querySelector("[data-start-tour]")?.addEventListener("click", () => {
    const steps = [
      [".global-search", tr("Search every major ServiceOps record type from here.")],
      [".sidebar", tr("Navigate between workspaces, operations, and administration.")],
      [".nav-menus", tr("Open favorites, history, notifications, help, and preferences.")]
    ];
    let index = 0;
    const endTour = () => {
      document.querySelectorAll(".tour-focus").forEach(el => el.classList.remove("tour-focus"));
      document.querySelector(".tour-popover")?.remove();
    };
    const show = () => {
      document.querySelectorAll(".tour-focus").forEach(el => el.classList.remove("tour-focus"));
      document.querySelector(".tour-popover")?.remove();
      if (index >= steps.length) {
        showToast(tr("Tour complete."), "success");
        return;
      }
      const element = document.querySelector(steps[index][0]);
      element?.classList.add("tour-focus");
      const popover = document.createElement("div");
      popover.className = "tour-popover";
      popover.setAttribute("role", "dialog");
      popover.setAttribute("aria-label", tr("Guided tour"));
      const text = document.createElement("p");
      text.textContent = steps[index][1];
      const actions = document.createElement("div");
      actions.className = "tour-popover-actions";
      const skip = document.createElement("button");
      skip.type = "button";
      skip.textContent = tr("Skip");
      skip.addEventListener("click", endTour);
      const next = document.createElement("button");
      next.type = "button";
      next.className = "primary";
      next.textContent = index === steps.length - 1 ? tr("Done") : tr("Next");
      next.addEventListener("click", () => { index += 1; show(); });
      actions.append(skip, next);
      popover.append(text, actions);
      document.body.appendChild(popover);
    };
    show();
  });
  const tabActivators = {};
  // [data-tab-nav] opts any nav element into the same real show/one-at-a-
  // time-hide tab behavior .record-section-tabs already has on ticket
  // detail pages -- used by the admin settings pages' existing category
  // sidebar (.settings-nav), which previously only scrolled to an anchor
  // while every category's fields stayed rendered and visible at once
  // ("all of them are together," reported directly). Kept as a separate
  // attribute rather than adding the .record-section-tabs class itself so
  // .settings-nav's own vertical-sidebar styling isn't fought by
  // .record-section-tabs' horizontal-top-bar CSS.
  document.querySelectorAll(".record-section-tabs, [data-tab-nav]").forEach(nav => {
    const links = Array.from(nav.querySelectorAll("a"));
    const targets = links
      .map(a => document.getElementById(a.getAttribute("href").slice(1)))
      .filter(Boolean);
    if (!targets.length) return;
    const activate = (id) => {
      links.forEach(a => a.classList.toggle("active", a.getAttribute("href") === `#${id}`));
      targets.forEach(el => { el.classList.toggle("tab-panel-hidden", el.id !== id); });
    };
    targets.forEach(el => { tabActivators[el.id] = activate; });
    links.forEach(a => {
      a.addEventListener("click", (event) => {
        event.preventDefault();
        activate(a.getAttribute("href").slice(1));
        history.replaceState(null, "", a.getAttribute("href"));
      });
    });
    // A link to a section (#affected-cis) wins; otherwise the page may name a
    // default tab (data-default-tab, e.g. a Data Center team's rack view).
    const hashId = location.hash.slice(1);
    const preferred = nav.dataset.defaultTab;
    const initial = targets.some(el => el.id === hashId) ? hashId
      : (preferred && targets.some(el => el.id === preferred) ? preferred : targets[0].id);
    activate(initial);
  });
  document.addEventListener("click", (event) => {
    const link = event.target.closest('a[href^="#"]');
    if (!link || link.closest(".record-section-tabs")) return;
    const id = link.getAttribute("href").slice(1);
    if (!tabActivators[id]) return;
    event.preventDefault();
    tabActivators[id](id);
    document.getElementById(id)?.scrollIntoView({block: "start"});
  });
  document.getElementById("ci-attr-add")?.addEventListener("click", () => {
    const container = document.querySelector(".ci-attr-rows");
    if (!container) return;
    const row = document.createElement("div");
    row.className = "ci-attr-row";
    const keyInput = document.createElement("input");
    keyInput.name = "attr_key";
    keyInput.placeholder = tr("Field name");
    const valueInput = document.createElement("input");
    valueInput.name = "attr_value";
    valueInput.placeholder = tr("Value");
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "link-button ci-attr-remove";
    remove.setAttribute("aria-label", tr("Remove field"));
    remove.textContent = "✕";
    row.append(keyInput, valueInput, remove);
    container.appendChild(row);
    keyInput.focus();
  });
  const ccbCheckbox = document.getElementById("ci-require-ccb");
  if (ccbCheckbox) {
    const envSelect = document.querySelector('select[name="environment"]');
    const classInput = document.querySelector('input[name="ci_class"]');
    const criticalitySelect = document.querySelector('select[name="business_criticality"]');
    const syncCcbCheckbox = () => {
      const isProduction = envSelect && envSelect.value === "Production";
      const isManagement = classInput && classInput.value.toLowerCase().includes("management");
      const isCritical = criticalitySelect && criticalitySelect.value === "Critical";
      const forced = Boolean(isProduction || isManagement || isCritical);
      ccbCheckbox.disabled = forced;
      if (forced) ccbCheckbox.checked = true;
    };
    envSelect?.addEventListener("change", syncCcbCheckbox);
    classInput?.addEventListener("input", syncCcbCheckbox);
    criticalitySelect?.addEventListener("change", syncCcbCheckbox);
    syncCcbCheckbox();
  }
  document.addEventListener("click", (event) => {
    const remove = event.target.closest(".ci-attr-remove");
    if (!remove) return;
    event.preventDefault();
    remove.closest(".ci-attr-row")?.remove();
  });
  const preferenceTabs = Array.from(document.querySelectorAll("[data-pref-tab]"));
  const preferenceTablist = document.querySelector(".preferences-nav");
  const preferenceNarrow = window.matchMedia("(max-width:900px)");
  const activatePreferenceTab = selected => {
    if (!preferenceTabs.some(item => item.dataset.prefTab === selected)) selected = "general";
    preferenceTabs.forEach(item => {
      const active = item.dataset.prefTab === selected;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
      item.tabIndex = active ? 0 : -1;
    });
    document.querySelectorAll("[data-pref-panel]").forEach(panel => {
      panel.hidden = panel.dataset.prefPanel !== selected;
    });
    const displayForm = document.getElementById("display-preferences");
    if (displayForm) displayForm.hidden = selected === "notifications";
    const category = document.querySelector("[data-preference-category]");
    if (category && selected !== "notifications") category.value = selected;
  };
  preferenceTabs.forEach(button => {
    button.addEventListener("click", () => {
      const selected = button.dataset.prefTab;
      activatePreferenceTab(selected);
      history.replaceState(null, "", `#${selected}`);
    });
    button.addEventListener("keydown", event => {
      const nextKey = preferenceNarrow.matches ? "ArrowRight" : "ArrowDown";
      const previousKey = preferenceNarrow.matches ? "ArrowLeft" : "ArrowUp";
      if (![nextKey, previousKey, "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const index = preferenceTabs.indexOf(button);
      const target = event.key === "Home" ? 0 : event.key === "End" ? preferenceTabs.length - 1
        : (index + (event.key === nextKey ? 1 : -1) + preferenceTabs.length) % preferenceTabs.length;
      preferenceTabs[target].click();
      preferenceTabs[target].focus();
    });
  });
  if (preferenceTablist) {
    const updateOrientation = () => preferenceTablist.setAttribute("aria-orientation", preferenceNarrow.matches ? "horizontal" : "vertical");
    updateOrientation();
    preferenceNarrow.addEventListener("change", updateOrientation);
    activatePreferenceTab(location.hash.slice(1));
    window.addEventListener("hashchange", () => activatePreferenceTab(location.hash.slice(1)));
  }
  document.querySelectorAll("input[type=range][data-range-output]").forEach(input => {
    const output = document.getElementById(input.dataset.rangeOutput);
    if (output) input.addEventListener("input", () => { output.value = `${input.value}%`; });
  });
  // A table that scrolls within a panel must remain reachable by keyboard,
  // including panels that begin to overflow only at a narrower viewport.
  const scrollPanels = Array.from(document.querySelectorAll("main section,main .panel,main .table-scroll,main .task-list-scroll"));
  const updateScrollPanels = () => scrollPanels.forEach(panel => {
    const style = getComputedStyle(panel);
    const scrolls = /auto|scroll/.test(style.overflowX) && panel.scrollWidth > panel.clientWidth + 1;
    if (scrolls && !panel.hasAttribute("tabindex")) {
      panel.tabIndex = 0;
      panel.dataset.scrollRegion = "";
    } else if (!scrolls && panel.hasAttribute("data-scroll-region")) {
      panel.removeAttribute("tabindex");
      delete panel.dataset.scrollRegion;
    }
  });
  updateScrollPanels();
  if (scrollPanels.length && window.ResizeObserver) {
    const scrollObserver = new ResizeObserver(updateScrollPanels);
    scrollPanels.forEach(panel => {
      scrollObserver.observe(panel);
      panel.querySelectorAll("table").forEach(table => scrollObserver.observe(table));
    });
  }

  // Approval chains: expand/collapse a grouped chain's earlier (superseded)
  // versions -- see templates/approval_chains.html. A <tr> can't sit inside
  // a <details>, so this is a plain hidden-row toggle instead.
  document.querySelectorAll("[data-approval-history-toggle]").forEach(button => {
    button.addEventListener("click", () => {
      const row = document.querySelector(`[data-approval-history="${CSS.escape(button.dataset.approvalHistoryToggle)}"]`);
      if (!row) return;
      const expanded = button.getAttribute("aria-expanded") === "true";
      row.hidden = expanded;
      button.setAttribute("aria-expanded", String(!expanded));
    });
  });

  // Notification bell: ring/recolor when the latest notification changes.
  // Updates arrive over the live event stream (tools/events_server.py) when
  // it is available, with a slower check as the fallback.
  // A record page names what it shows (data-live-watch) so the live stream
  // can say when someone else changes it.
  const liveWatch = document.querySelector("[data-live-watch]")?.dataset.liveWatch || "";
  let myUserId = null;
  function showLiveBanner(message, action) {
    if (document.querySelector(".live-update-banner")) return;
    const banner = document.createElement("div");
    banner.className = "live-update-banner";
    banner.setAttribute("role", "status");
    const text = document.createElement("span");
    text.textContent = message;
    const reload = document.createElement("button");
    reload.type = "button";
    reload.className = "button primary";
    reload.textContent = action;
    reload.addEventListener("click", () => window.location.reload());
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "link-button";
    dismiss.textContent = tr("Dismiss");
    dismiss.addEventListener("click", () => banner.remove());
    banner.append(text, reload, dismiss);
    document.body.appendChild(banner);
  }

  function showRecordUpdated(data) {
    if (!liveWatch || liveWatch !== `ticket:${data.id}` || (data.actor && data.actor === myUserId)) return;
    showLiveBanner(tr("Someone else just updated this record."), tr("Reload to see it"));
  }

  // Project boards and work items: one banner per burst of other people's changes.
  let watchedChangeTimer = null;
  function showWatchedChanged(data) {
    if (!liveWatch || data.key !== liveWatch || data.self) return;
    clearTimeout(watchedChangeTimer);
    watchedChangeTimer = setTimeout(() => {
      if (liveWatch.startsWith("work_item:")) {
        showLiveBanner(tr("Someone else just updated this work item."), tr("Reload to see it"));
      } else {
        showLiveBanner(tr("Work items in this project have changed."), tr("Refresh"));
      }
    }, 1500);
  }

  // Work lists hear only that some ticket changed; a burst of changes
  // (bulk updates, imports) shows one banner after it settles.
  let listChangeTimer = null;
  function showListUpdated(data) {
    if (liveWatch !== "tickets" || data.self) return;
    clearTimeout(listChangeTimer);
    listChangeTimer = setTimeout(() => showLiveBanner(tr("Tickets in this list have changed."), tr("Refresh")), 1500);
  }

  const notificationMenu = document.querySelector(".notification-menu[data-poll-url]");
  if (notificationMenu) {
    const pollUrl = notificationMenu.dataset.pollUrl;
    let latestId = Number(notificationMenu.dataset.latestId || 0);
    const SEVERITY_ICON = {critical: "⚠", warning: "⏰"};

    function renderNotifications(data) {
      const summary = notificationMenu.querySelector("summary");
      const list = notificationMenu.querySelector(".notification-preview-list");
      const headSpan = notificationMenu.querySelector(".notification-popover-head span");
      let badge = summary.querySelector(".notification-count");
      if (data.unread_count > 0) {
        if (!badge) {
          badge = document.createElement("b");
          badge.className = "notification-count";
          summary.appendChild(badge);
        }
        badge.textContent = data.unread_count < 100 ? String(data.unread_count) : "99+";
        badge.className = `notification-count severity-${data.severity || "info"}`;
      } else if (badge) {
        badge.remove();
      }
      if (headSpan) {
        headSpan.textContent = data.unread_count > 0 ? tr("{count} unread", { count: data.unread_count }) : "";
        headSpan.hidden = data.unread_count === 0;
      }
      notificationMenu.dataset.severity = data.severity || "";
      if (!list) return;
      if (!data.notifications.length) {
        const emptyNote = document.createElement("p");
        emptyNote.className = "notification-preview-empty";
        emptyNote.textContent = tr("You have no notifications.");
        list.replaceChildren(emptyNote);
        return;
      }
      list.innerHTML = "";
      data.notifications.forEach(n => {
        const icon = SEVERITY_ICON[n.severity] || "ⓘ";
        const cls = `notification-preview severity-${n.severity}${n.read ? "" : " unread"}`;
        const inner = document.createElement("span");
        inner.className = "notification-preview-glyph";
        inner.setAttribute("aria-hidden", "true");
        inner.textContent = icon;
        const textWrap = document.createElement("span");
        textWrap.innerHTML = "<strong></strong><small></small><time></time>";
        textWrap.querySelector("strong").textContent = n.title;
        textWrap.querySelector("small").textContent = n.body;
        textWrap.querySelector("time").textContent = n.created_at_display;
        // Exactly mirrors base.html's server-rendered markup: a real target
        // marks the notification read via POST before redirecting there; no
        // target is a plain link to the notifications list, never marked
        // read from this popover.
        let control;
        if (n.has_target) {
          const form = document.createElement("form");
          form.method = "post";
          form.action = n.mark_read_url;
          const csrfInput = document.createElement("input");
          csrfInput.type = "hidden";
          csrfInput.name = "_csrf_token";
          csrfInput.value = csrfToken;
          form.appendChild(csrfInput);
          control = document.createElement("button");
          control.type = "submit";
          form.appendChild(control);
          list.appendChild(form);
        } else {
          control = document.createElement("a");
          control.href = n.list_url;
          list.appendChild(control);
        }
        control.className = cls;
        control.appendChild(inner);
        control.appendChild(textWrap);
      });
    }

    // One tab per browser leads (Web Locks): it holds the live event stream
    // and does the periodic check, and shares every result with the other
    // tabs (BroadcastChannel). The stream makes the bell instant; checks
    // run every 25 s only without it (60 s after 5 idle minutes, 2 min as
    // a safety net while it is up) and send the last ETag, so an unchanged
    // bell costs a bodiless 304.
    const streamUrl = notificationMenu.dataset.streamUrl;
    const channel = "BroadcastChannel" in window ? new BroadcastChannel("serviceops-notifications") : null;
    let etag = null;
    let live = false;
    let lastActivity = Date.now();
    ["pointerdown", "keydown", "scroll"].forEach(name => window.addEventListener(name, () => { lastActivity = Date.now(); }, {passive: true}));

    function applyNotifications(data) {
      if (notificationMenu.dataset.submitting === "true" || notificationMenu.open) return;
      if (data.latest_id && data.latest_id !== latestId) {
        const isNewArrival = data.latest_id > latestId;
        latestId = data.latest_id;
        if (isNewArrival) {
          notificationMenu.classList.remove("ringing");
          // Force reflow so re-adding the class restarts the animation
          // even if a previous ring is still settling.
          void notificationMenu.offsetWidth;
          notificationMenu.classList.add("ringing");
        }
      }
      renderNotifications(data);
    }

    async function pollNotifications() {
      // Skip while a form submit inside the popover (mark-as-read) is
      // navigating -- avoids clobbering that in-flight state change.
      if (notificationMenu.dataset.submitting === "true" || notificationMenu.contains(document.activeElement)) return;
      try {
        const headers = {Accept: "application/json"};
        if (etag) headers["If-None-Match"] = etag;
        const response = await fetch(pollUrl, {headers, cache: "no-store"});
        if (response.status === 304 || !response.ok) return;
        etag = response.headers.get("ETag");
        const data = await response.json();
        applyNotifications(data);
        channel?.postMessage({type: "notifications", data});
      } catch (error) {
        // A transient network hiccup shouldn't spam the console on a
        // background poll; the next tick tries again.
      }
    }

    function nextCheckDelay() {
      if (live) return 120000;
      if (document.visibilityState !== "visible" || Date.now() - lastActivity > 300000) return 60000;
      return 25000;
    }

    let watchStream = null;
    function openStream({notifications}) {
      if (!streamUrl || !("EventSource" in window)) return null;
      const params = new URLSearchParams({notifications: notifications ? "1" : "0"});
      if (liveWatch) params.set("watch", liveWatch);
      const source = new EventSource(`${streamUrl}?${params}`);
      source.addEventListener("hello", event => {
        try { myUserId = JSON.parse(event.data).user_id; } catch (error) { /* ignore */ }
        if (notifications) live = true;
      });
      if (notifications) {
        source.addEventListener("notification", () => pollNotifications());
        source.addEventListener("resync", () => pollNotifications());
      }
      source.addEventListener("ticket", event => showRecordUpdated(JSON.parse(event.data)));
      source.addEventListener("tickets", event => showListUpdated(JSON.parse(event.data)));
      source.addEventListener("changed", event => showWatchedChanged(JSON.parse(event.data)));
      source.addEventListener("signed-out", () => { source.close(); live = false; });
      source.addEventListener("error", () => {
        // CONNECTING: the browser retries by itself. CLOSED: the server
        // answered without a stream (no events service): stay on checks.
        if (notifications) live = false;
      });
      return source;
    }

    function lead() {
      watchStream?.close();
      openStream({notifications: true});
      const loop = () => pollNotifications().finally(() => setTimeout(loop, nextCheckDelay()));
      setTimeout(loop, nextCheckDelay());
      channel && (channel.onmessage = event => {
        if (event.data?.type === "refresh") pollNotifications();
      });
      return new Promise(() => {});  // keep the lock for this tab's lifetime
    }

    channel?.addEventListener("message", event => {
      if (event.data?.type === "notifications") applyNotifications(event.data.data);
    });
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") channel?.postMessage({type: "refresh"});
    });
    notificationMenu.addEventListener("animationend", () => notificationMenu.classList.remove("ringing"));
    notificationMenu.addEventListener("submit", () => { notificationMenu.dataset.submitting = "true"; });
    if (navigator.locks?.request) {
      navigator.locks.request("serviceops-notifications", {ifAvailable: true}, lock => {
        if (lock) return lead();
        // Another tab leads: watch this page's record only, and take over
        // when the leading tab closes.
        if (liveWatch) watchStream = openStream({notifications: false});
        navigator.locks.request("serviceops-notifications", () => lead());
        return null;
      });
    } else {
      lead();
    }
  }

  const commentForm = document.getElementById("comment-form");
  if (commentForm) {
    const bodyInput = document.getElementById("comment-body-input");
    const parentIdInput = document.getElementById("comment-parent-id");
    const replyBanner = document.getElementById("comment-reply-banner");
    const replyAuthor = document.getElementById("comment-reply-author");
    const replyCancel = document.getElementById("comment-reply-cancel");

    document.querySelectorAll(".comment-reply-toggle").forEach((toggle) => {
      toggle.addEventListener("click", () => {
        parentIdInput.value = toggle.dataset.replyTo;
        replyAuthor.textContent = toggle.dataset.replyAuthor;
        replyBanner.hidden = false;
        bodyInput.focus();
        bodyInput.scrollIntoView({block: "center", behavior: "smooth"});
      });
    });
    if (replyCancel) {
      replyCancel.addEventListener("click", () => {
        parentIdInput.value = "";
        replyBanner.hidden = true;
      });
    }

    // @mention autocomplete: fetches the small, ticket-scoped candidate
    // list once (everyone already authorized to view this ticket -- see
    // ticket_mentionable_users_api, which mirrors the same authorization
    // check the server applies when actually sending mention
    // notifications, so anything offered here will actually work) and
    // filters it client-side as the user types after an "@".
    const suggestionsList = document.getElementById("mention-suggestions");
    let mentionCandidates = null;
    let mentionCandidatesPromise = null;
    let activeMatchStart = -1;

    function loadMentionCandidates() {
      if (mentionCandidatesPromise) return mentionCandidatesPromise;
      const ticketId = commentForm.dataset.ticketId;
      if (!ticketId) return Promise.resolve([]);
      mentionCandidatesPromise = fetch(`/ticket/${ticketId}/mentionable-users`, {headers: {Accept: "application/json"}})
        .then((response) => (response.ok ? response.json() : {users: []}))
        .then((data) => { mentionCandidates = data.users || []; return mentionCandidates; })
        .catch(() => { mentionCandidates = []; return mentionCandidates; });
      return mentionCandidatesPromise;
    }

    function closeSuggestions() {
      suggestionsList.hidden = true;
      suggestionsList.innerHTML = "";
      activeMatchStart = -1;
    }

    function renderSuggestions(users, matchStart) {
      activeMatchStart = matchStart;
      // Display names come from LDAP/SCIM/profile edits: build as text, not HTML.
      suggestionsList.replaceChildren(...users.map((user) => {
        const item = document.createElement("li");
        item.setAttribute("role", "option");
        item.dataset.username = user.username;
        const name = document.createElement("strong");
        name.textContent = user.name;
        const handle = document.createElement("small");
        handle.textContent = `@${user.username}`;
        item.append(name, handle);
        return item;
      }));
      suggestionsList.hidden = users.length === 0;
    }

    bodyInput.addEventListener("input", async () => {
      const cursor = bodyInput.selectionStart;
      const upToCursor = bodyInput.value.slice(0, cursor);
      const match = upToCursor.match(/(?:^|\s)@([a-zA-Z0-9_.-]{0,80})$/);
      if (!match) { closeSuggestions(); return; }
      const partial = match[1].toLowerCase();
      const matchStart = cursor - match[1].length - 1;
      const candidates = await loadMentionCandidates();
      const filtered = candidates.filter((user) =>
        user.username.toLowerCase().startsWith(partial) || user.name.toLowerCase().includes(partial)
      ).slice(0, 6);
      if (bodyInput.selectionStart !== cursor) return; // stale response, user kept typing
      renderSuggestions(filtered, matchStart);
    });

    suggestionsList.addEventListener("mousedown", (event) => {
      const item = event.target.closest("[data-username]");
      if (!item || activeMatchStart < 0) return;
      event.preventDefault();
      const cursor = bodyInput.selectionStart;
      const before = bodyInput.value.slice(0, activeMatchStart);
      const after = bodyInput.value.slice(cursor);
      const inserted = `@${item.dataset.username} `;
      bodyInput.value = before + inserted + after;
      const newCursor = before.length + inserted.length;
      bodyInput.setSelectionRange(newCursor, newCursor);
      closeSuggestions();
      bodyInput.focus();
    });

    bodyInput.addEventListener("blur", () => setTimeout(closeSuggestions, 150));
    bodyInput.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && !suggestionsList.hidden) closeSuggestions();
    });
  }
});

/* Change form: fetch an RT ticket and prefill the change (RT page setting). */
(function () {
  const field = document.querySelector(".rt-link-field");
  if (!field) return;
  const input = field.querySelector("input[name=rt_ticket_id]");
  const button = field.querySelector("[data-rt-fetch]");
  const status = field.querySelector(".rt-link-status");
  const form = field.closest("form");
  const setStatus = (text, kind) => { status.textContent = text; status.dataset.kind = kind || ""; };
  async function fetchRt() {
    const id = input.value.trim().replace(/^#/, "");
    if (!/^\d+$/.test(id)) { setStatus(tr("Enter an RT ticket number."), "error"); input.focus(); return; }
    button.disabled = true;
    setStatus(tr("Fetching RT #{id}…", {id}), "busy");
    try {
      const response = await fetch(`${field.dataset.rtPreviewUrl}?rt_id=${encodeURIComponent(id)}`, {headers: {Accept: "application/json"}});
      const data = await response.json().catch(() => ({}));
      if (!response.ok) { setStatus(data.error || tr("Could not fetch the RT ticket."), "error"); return; }
      if (data.linked_change) { setStatus(tr("RT #{id} is already linked to {number}.", {id, number: data.linked_change.number}), "error"); return; }
      const title = form.querySelector("[name=title]");
      const description = form.querySelector("[name=description]");
      const replace = (element, value) => {
        if (!element || !value) return;
        if (element.value.trim() && element.value.trim() !== value && !window.confirm(tr("Replace the current {field} with the RT ticket's?", {field: element.closest("label")?.querySelector("span")?.textContent || ""}))) return;
        element.value = value;
        element.dispatchEvent(new Event("input", {bubbles: true}));
      };
      replace(title, (data.subject || "").slice(0, 180));
      replace(description, data.description || "");
      const team = form.querySelector("[name=group_id]");
      let teamNote = "";
      if (team && data.team_id) {
        const option = team.querySelector(`option[value="${data.team_id}"]`);
        if (option && !option.disabled) { team.value = String(data.team_id); team.dispatchEvent(new Event("change", {bubbles: true})); teamNote = " " + tr("Owning team set to {team}.", {team: data.team_name}); }
      }
      setStatus(tr("Filled from RT #{id}: {subject}", {id, subject: data.subject || ""}) + teamNote, "ok");
    } catch (error) {
      setStatus(tr("Could not reach the server. Try again."), "error");
    } finally {
      button.disabled = false;
    }
  }
  button.addEventListener("click", fetchRt);
  input.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); fetchRt(); } });
})();

/* Preferences: desktop notifications (Web Push) for this browser. */
(function () {
  const row = document.querySelector("[data-web-push]");
  if (!row) return;
  const button = row.querySelector("[data-web-push-toggle]");
  const csrfHeaders = {"X-CSRF-Token": document.querySelector('meta[name="csrf-token"]')?.content || ""};
  const status = row.querySelector("[data-web-push-status]");
  const testButton = row.querySelector("[data-web-push-test]");
  // Say why the switch is unavailable instead of leaving it dead or hiding it.
  const unavailable = message => { status.textContent = message; button.disabled = true; };
  if (!window.isSecureContext || !("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
    unavailable(tr("This browser does not support desktop notifications. On iPhone or iPad, add ServiceOps to the Home Screen first."));
    return;
  }
  const toKey = text => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - text.length % 4) % 4)), c => c.charCodeAt(0));
  let config = null;
  // The browser's own reason, in words a person can act on.
  function pushErrorMessage(error) {
    const detail = `${error?.name || ""} ${error?.message || ""}`.toLowerCase();
    if (detail.includes("push service")) {
      return tr("This browser could not reach its push service. In Brave, turn on \"Use Google services for push messaging\" in Settings → Privacy and security, then try again.");
    }
    if (error?.name === "NotAllowedError" || detail.includes("permission denied")) {
      return tr("Notifications are blocked for ServiceOps. Allow them in the browser's site settings and in the computer's notification settings, then try again.");
    }
    return tr("Could not change desktop notifications in this browser: {reason}", {reason: (error?.message || error?.name || "unknown error").slice(0, 160)});
  }
  async function current() {
    const registration = await navigator.serviceWorker.ready;
    return registration.pushManager.getSubscription();
  }
  async function render() {
    const subscription = await current();
    button.textContent = subscription ? tr("Turn off") : tr("Turn on");
    if (testButton) testButton.hidden = !subscription;
    button.dataset.on = subscription ? "1" : "";
    if (Notification.permission === "denied") {
      status.textContent = tr("This browser blocks notifications for ServiceOps. Allow them in the browser's site settings.");
      button.disabled = true;
    } else {
      status.textContent = subscription ? tr("On for this browser.") : tr("Show ServiceOps notifications on this computer even when no ServiceOps tab is open.");
    }
  }
  async function toggle() {
    button.disabled = true;
    try {
      const subscription = await current();
      if (subscription) {
        await fetch("/push/subscriptions", {method: "DELETE", headers: {...csrfHeaders, "Content-Type": "application/json"}, body: JSON.stringify({endpoint: subscription.endpoint})});
        await subscription.unsubscribe();
        showToast(tr("Desktop notifications turned off for this browser."), "success");
      } else {
        const permission = await Notification.requestPermission();
        if (permission !== "granted") {
          if (permission === "default") showToast(tr("Allow notifications when the browser asks to turn them on."), "error");
          await render();
          return;
        }
        const registration = await navigator.serviceWorker.ready;
        const options = {userVisibleOnly: true, applicationServerKey: toKey(config.public_key)};
        let created;
        try {
          created = await registration.pushManager.subscribe(options);
        } catch (error) {
          // A subscription left over from an earlier server key blocks a new one: replace it once.
          if (error?.name !== "InvalidStateError") throw error;
          await (await registration.pushManager.getSubscription())?.unsubscribe();
          created = await registration.pushManager.subscribe(options);
        }
        const response = await fetch("/push/subscriptions", {method: "POST", headers: {...csrfHeaders, "Content-Type": "application/json"}, body: JSON.stringify(created.toJSON())});
        if (!response.ok) {
          await created.unsubscribe();
          const detail = await response.json().catch(() => ({}));
          showToast(detail.error?.detail || detail.description || tr("Could not turn on desktop notifications."), "error");
        } else {
          showToast(tr("Desktop notifications are on for this browser."), "success");
        }
      }
    } catch (error) {
      showToast(pushErrorMessage(error), "error");
    } finally {
      button.disabled = false;
      await render();
    }
  }
  fetch("/push/config", {headers: {Accept: "application/json"}}).then(r => r.ok ? r.json() : null).then(data => {
    if (!data) {
      unavailable(tr("Desktop notifications could not be checked. Reload the page to try again."));
      return;
    }
    if (!data.enabled || !data.public_key) {
      unavailable(tr("Desktop notifications are turned off for your organization."));
      const adminHint = row.querySelector("[data-web-push-admin]");
      if (adminHint) adminHint.hidden = false;
      return;
    }
    config = data;
    button.disabled = false;
    button.addEventListener("click", toggle);
    testButton?.addEventListener("click", async () => {
      testButton.disabled = true;
      try {
        const response = await fetch("/push/test", {method: "POST", headers: csrfHeaders});
        const detail = await response.json().catch(() => ({}));
        showToast(response.ok
          ? tr("Test notification sent. It appears on this computer within a few seconds, even with ServiceOps in the background.")
          : (detail.error?.detail || detail.description || tr("Could not send a test notification.")), response.ok ? "success" : "error");
      } finally {
        testButton.disabled = false;
      }
    });
    render();
  }).catch(() => unavailable(tr("Desktop notifications could not be checked. Reload the page to try again.")));
})();

// A change's post-implementation review has its own form, but people often
// type it and press the record's Update button. Carry a typed review into
// that submit as pir_* fields so the server saves it before any move to Closed.
(() => {
  const record = document.getElementById("task-record-form");
  if (!record) return;
  record.addEventListener("submit", () => {
    record.querySelectorAll("input[data-pir-copy]").forEach((input) => input.remove());
    const forms = [...document.querySelectorAll("form[data-change-review-form]")];
    const typed = forms.find((form) => (form.elements.summary?.value || "").trim() && (form.elements.summary.value !== form.elements.summary.defaultValue || form.elements.outcome.value !== [...form.elements.outcome.options].find((o) => o.defaultSelected)?.value));
    if (!typed) return;
    for (const name of ["outcome", "summary", "follow_up_actions"]) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = `pir_${name}`;
      input.value = typed.elements[name]?.value || "";
      input.dataset.pirCopy = "";
      record.append(input);
    }
  });
})();
