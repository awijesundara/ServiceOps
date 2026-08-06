document.addEventListener("DOMContentLoaded", () => {
  const el = document.getElementById("ci-form-dns");
  if (!el || !el.dataset.ciId) return;
  fetch(`/cmdb/${el.dataset.ciId}/network-info`, { headers: { Accept: "application/json" } })
    .then((response) => (response.ok ? response.json() : Promise.reject()))
    .then((info) => {
      const parts = [];
      (info.addresses || []).forEach((entry) => {
        parts.push(`<div>${entry.ip} → ${entry.hostname || "no PTR record"}</div>`);
      });
      (info.hostnames || []).forEach((entry) => {
        parts.push(`<div>${entry.hostname} → ${(entry.ips || []).join(", ") || "no A/AAAA record"}</div>`);
      });
      el.innerHTML = parts.length ? parts.join("") : "No IP or hostname to resolve.";
    })
    .catch(() => { el.textContent = "Unable to resolve at this time."; });
});
