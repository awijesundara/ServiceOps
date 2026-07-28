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
  document.querySelector("[data-nav-toggle]")?.addEventListener("click", () => body.classList.toggle("nav-collapsed"));
  const sidebarNav = document.querySelector(".sidebar nav");
  if (sidebarNav) {
    const savedScroll = sessionStorage.getItem("sidebarNavScrollTop");
    if (savedScroll) sidebarNav.scrollTop = parseInt(savedScroll, 10) || 0;
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
    if (star) star.textContent = result.active ? "★" : "☆";
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
