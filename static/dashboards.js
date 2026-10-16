// Dashboards (B-464): drag-and-drop widget order in the editor. The arrow
// buttons remain the keyboard way to reorder; this only adds dragging.
document.addEventListener("DOMContentLoaded", () => {
  const grid = document.querySelector("[data-dash-layout]");
  if (!grid) return;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  let dragged = null;

  const save = () => {
    const order = Array.from(grid.querySelectorAll("[data-widget-id]")).map((el) => Number(el.dataset.widgetId));
    fetch(grid.dataset.dashLayout, {
      method: "POST",
      headers: {"Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": csrf},
      body: JSON.stringify({order}),
    }).then((response) => {
      if (!response.ok) window.location.reload();
    }).catch(() => window.location.reload());
  };

  grid.addEventListener("dragstart", (event) => {
    dragged = event.target.closest("[data-widget-id]");
    if (!dragged) return;
    dragged.classList.add("is-dragging");
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", dragged.dataset.widgetId);
  });
  grid.addEventListener("dragover", (event) => {
    const target = event.target.closest("[data-widget-id]");
    if (!dragged || !target || target === dragged) return;
    event.preventDefault();
    grid.querySelectorAll(".is-drop-target").forEach((el) => el.classList.remove("is-drop-target"));
    target.classList.add("is-drop-target");
  });
  grid.addEventListener("drop", (event) => {
    const target = event.target.closest("[data-widget-id]");
    if (!dragged || !target || target === dragged) return;
    event.preventDefault();
    const before = target.compareDocumentPosition(dragged) & Node.DOCUMENT_POSITION_FOLLOWING;
    target.parentNode.insertBefore(dragged, before ? target : target.nextSibling);
    save();
  });
  grid.addEventListener("dragend", () => {
    dragged?.classList.remove("is-dragging");
    grid.querySelectorAll(".is-drop-target").forEach((el) => el.classList.remove("is-drop-target"));
    dragged = null;
  });
});
