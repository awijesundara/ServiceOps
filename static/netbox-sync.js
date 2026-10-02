// Live progress and safe cancellation for every inventory sync panel on the
// CMDB import page (NetBox and Snipe-IT share this behaviour).
(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

  // One click is one request: a second click while the first is in flight
  // would only queue a duplicate job or re-post the same import.
  document.querySelectorAll("form[data-submit-once]").forEach(form => {
    form.addEventListener("submit", () => {
      form.setAttribute("aria-busy", "true");
      form.querySelectorAll("button").forEach(button => {
        if (button.disabled) return;
        button.disabled = true;
        if (button.type !== "button") button.dataset.label = button.textContent;
        if (button.type !== "button") button.textContent = "Working…";
      });
    });
  });
  // A page restored from the back/forward cache must not keep buttons locked.
  window.addEventListener("pageshow", event => {
    if (!event.persisted) return;
    document.querySelectorAll("form[data-submit-once]").forEach(form => {
      form.removeAttribute("aria-busy");
      form.querySelectorAll("button[data-label]").forEach(button => {
        button.disabled = false;
        button.textContent = button.dataset.label;
      });
    });
  });

  document.querySelectorAll("[data-sync-progress]").forEach(panel => {
    const status = panel.querySelector("[data-sync-status]");
    const meter = panel.querySelector("[data-sync-meter]");
    const count = panel.querySelector("[data-sync-count]");
    const cancel = panel.querySelector("[data-sync-cancel]");
    if (!status) return;
    let stopped = false;

    async function refresh() {
      if (stopped) return;
      try {
        const response = await fetch(panel.dataset.statusUrl, {headers: {Accept: "application/json"}});
        if (!response.ok) throw new Error("status request failed");
        const job = await response.json();
        status.textContent = `${job.status} · ${job.phase}`;
        if (meter) meter.value = job.percent;
        if (count) count.textContent = `${job.processed} processed${job.total ? ` of ${job.total}` : ""}`;
        if (!["Pending", "Running"].includes(job.status)) {
          stopped = true;
          if (cancel) cancel.hidden = true;
          if (job.error) status.textContent += ` · ${job.error}`;
          // The finished page shows the full result and unlocks the import step.
          window.location.reload();
          return;
        }
      } catch (_error) {
        status.textContent = "Progress temporarily unavailable; retrying.";
      }
      window.setTimeout(refresh, 1500);
    }

    cancel?.addEventListener("click", async () => {
      cancel.disabled = true;
      status.textContent = "Cancellation requested; finishing the current batch safely.";
      await fetch(panel.dataset.cancelUrl, {
        method: "POST", headers: {"X-CSRF-Token": csrf, Accept: "application/json"},
      });
    });
    if (["Pending", "Running"].some(value => status.textContent.startsWith(value))) refresh();
  });
})();
