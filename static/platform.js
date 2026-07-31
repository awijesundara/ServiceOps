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
  close.setAttribute("aria-label", "Dismiss");
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
  if ("serviceWorker" in navigator && window.isSecureContext) {
    navigator.serviceWorker.register("/service-worker.js", { scope: "/" });
  }
  const body = document.body;
  const path = location.pathname + location.search;
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const csrfHeaders = {"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrfToken};
  if (body.querySelector(".sidebar")) {
    const data = new URLSearchParams({url: path, label: document.title});
    fetch("/ui/history", {method: "POST", headers: csrfHeaders, body: data});
  }
  document.querySelector("[data-nav-toggle]")?.addEventListener("click", () => {
    const collapsed = body.classList.toggle("nav-collapsed");
    localStorage.setItem("navCollapsed", collapsed ? "1" : "0");
  });
  document.querySelectorAll("[data-print-page]").forEach(button => {
    button.addEventListener("click", () => window.print());
  });
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
    const data = new URLSearchParams({url: path, label: document.querySelector("h1")?.textContent || document.title});
    let response;
    try {
      response = await fetch("/ui/favorite", {method: "POST", headers: csrfHeaders, body: data});
    } catch (error) {
      showToast("Could not reach the server. Check your connection and try again.", "error");
      return;
    }
    if (!response.ok) {
      showToast("Could not update favorites. Please try again.", "error");
      return;
    }
    const result = await response.json();
    event.currentTarget.textContent = result.active
      ? "Remove this page from favorites"
      : "Add this page to favorites";
    const star = document.querySelector("[data-favorite-star]");
    if (star) star.setAttribute("data-active", result.active ? "true" : "false");
  });
  let dragged = null;
  document.querySelectorAll(".board-card[draggable=true]").forEach(card => {
    card.addEventListener("dragstart", () => { dragged = card; card.classList.add("dragging"); });
    card.addEventListener("dragend", () => card.classList.remove("dragging"));
  });
  document.querySelectorAll(".board-lane").forEach(lane => {
    lane.addEventListener("dragover", event => event.preventDefault());
    lane.addEventListener("drop", async () => {
      if (!dragged) return;
      const data = new URLSearchParams({state: lane.dataset.state});
      let response;
      try {
        response = await fetch(`/task-board/${dragged.dataset.ticket}/move`, {method: "POST", headers: csrfHeaders, body: data});
      } catch (error) {
        showToast("Could not reach the server. The card was not moved.", "error");
        return;
      }
      if (response.ok) {
        lane.querySelector(".board-cards").appendChild(dragged);
      } else {
        showToast("Could not move this card. Please try again.", "error");
      }
    });
  });
  document.querySelector("[data-start-tour]")?.addEventListener("click", () => {
    const steps = [
      [".global-search", "Search every major ServiceOps record type from here."],
      [".sidebar", "Navigate between workspaces, operations, and administration."],
      [".nav-menus", "Open favorites, history, notifications, help, and preferences."]
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
        showToast("Tour complete.", "success");
        return;
      }
      const element = document.querySelector(steps[index][0]);
      element?.classList.add("tour-focus");
      const popover = document.createElement("div");
      popover.className = "tour-popover";
      popover.setAttribute("role", "dialog");
      popover.setAttribute("aria-label", "Guided tour");
      const text = document.createElement("p");
      text.textContent = steps[index][1];
      const actions = document.createElement("div");
      actions.className = "tour-popover-actions";
      const skip = document.createElement("button");
      skip.type = "button";
      skip.textContent = "Skip";
      skip.addEventListener("click", endTour);
      const next = document.createElement("button");
      next.type = "button";
      next.className = "primary";
      next.textContent = index === steps.length - 1 ? "Done" : "Next";
      next.addEventListener("click", () => { index += 1; show(); });
      actions.append(skip, next);
      popover.append(text, actions);
      document.body.appendChild(popover);
    };
    show();
  });
  const tabActivators = {};
  document.querySelectorAll(".record-section-tabs").forEach(nav => {
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
    const hashId = location.hash.slice(1);
    const initial = targets.some(el => el.id === hashId) ? hashId : targets[0].id;
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
    keyInput.placeholder = "Field name";
    const valueInput = document.createElement("input");
    valueInput.name = "attr_value";
    valueInput.placeholder = "Value";
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "link-button ci-attr-remove";
    remove.setAttribute("aria-label", "Remove field");
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
  document.querySelectorAll("[data-pref-tab]").forEach(button => {
    button.addEventListener("click", () => {
      const selected = button.dataset.prefTab;
      document.querySelectorAll("[data-pref-tab]").forEach(item => item.classList.toggle("active", item === button));
      document.querySelectorAll("[data-pref-panel]").forEach(panel => {
        panel.hidden = panel.dataset.prefPanel !== selected;
      });
    });
  });
});
