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
    const response = await fetch("/ui/favorite", {method: "POST", headers: csrfHeaders, body: data});
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
      const response = await fetch(`/task-board/${dragged.dataset.ticket}/move`, {method: "POST", headers: csrfHeaders, body: data});
      if (response.ok) lane.querySelector(".board-cards").appendChild(dragged);
    });
  });
  document.querySelector("[data-start-tour]")?.addEventListener("click", () => {
    const steps = [
      [".global-search", "Search every major ServiceOps record type from here."],
      [".sidebar", "Navigate between workspaces, operations, and administration."],
      [".nav-menus", "Open favorites, history, notifications, help, and preferences."]
    ];
    let index = 0;
    const show = () => {
      document.querySelectorAll(".tour-focus").forEach(el => el.classList.remove("tour-focus"));
      if (index >= steps.length) return alert("Tour complete.");
      const element = document.querySelector(steps[index][0]);
      element?.classList.add("tour-focus");
      alert(steps[index][1]);
      index += 1;
      show();
    };
    show();
  });
});
