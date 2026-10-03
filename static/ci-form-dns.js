document.addEventListener("DOMContentLoaded", () => {
  const el = document.getElementById("ci-form-dns");
  if (!el || !el.dataset.ciId) return;
  fetch(`/cmdb/${el.dataset.ciId}/network-info`, { headers: { Accept: "application/json" } })
    .then((response) => (response.ok ? response.json() : Promise.reject()))
    .then((info) => {
      // PTR hostnames are controlled by whoever owns the reverse zone: text only.
      const line = (text) => {
        const div = document.createElement("div");
        div.textContent = text;
        return div;
      };
      const lines = [];
      (info.addresses || []).forEach((entry) => {
        lines.push(line(`${entry.ip} → ${entry.hostname || tr("no PTR record")}`));
      });
      (info.hostnames || []).forEach((entry) => {
        lines.push(line(`${entry.hostname} → ${(entry.ips || []).join(", ") || tr("no A/AAAA record")}`));
      });
      if (lines.length) el.replaceChildren(...lines);
      else el.textContent = tr("No IP or hostname to resolve.");
    })
    .catch(() => { el.textContent = tr("Unable to resolve at this time."); });
});
