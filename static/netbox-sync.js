(() => {
  const panel = document.getElementById("netbox-sync-progress");
  if (!panel) return;
  const status = document.getElementById("netbox-sync-status");
  const meter = document.getElementById("netbox-sync-meter");
  const count = document.getElementById("netbox-sync-count");
  const cancel = document.getElementById("netbox-sync-cancel");
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  let stopped = false;

  async function refresh() {
    if (stopped) return;
    try {
      const response = await fetch(panel.dataset.statusUrl, {headers: {Accept: "application/json"}});
      if (!response.ok) throw new Error("status request failed");
      const job = await response.json();
      status.textContent = `${job.status} · ${job.phase}`;
      meter.value = job.percent;
      count.textContent = `${job.processed} processed${job.total ? ` of ${job.total}` : ""}`;
      if (!["Pending", "Running"].includes(job.status)) {
        stopped = true;
        if (cancel) cancel.hidden = true;
        if (job.error) status.textContent += ` · ${job.error}`;
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
})();
