/* Rack elevation renderer -- plain hand-rolled SVG, no external charting
   library, matching cmdb-topology.js's "no-CDN policy". U-slots are
   numbered bottom-to-top (U1 at the bottom), the standard physical-rack
   convention. Each mounted CI is drawn as a block spanning its
   rack_position through rack_position + rack_u_height - 1, colored by
   ci_class, and links through to that CI's edit page. */
document.addEventListener("DOMContentLoaded", () => {
  const root = document.getElementById("rack-elevation-root");
  if (!root) return;
  let payload = { rack: { u_height: 42 }, front: [], rear: [], pdus: [], stats: {} };
  try {
    payload = JSON.parse(root.dataset.rack || "{}");
  } catch (error) {
    return;
  }
  const uHeight = payload.rack.u_height || 42;
  const rowHeight = 18;
  const svgHeight = uHeight * rowHeight + 20;

  const svgNS = "http://www.w3.org/2000/svg";
  const colorFor = (ciClass) => {
    const key = (ciClass || "").toLowerCase();
    if (key.includes("switch") || key.includes("router")) return "#f9aa3c";
    if (key === "pdu") return "#c0392b";
    if (key.includes("storage")) return "#7c5cbf";
    return "#003e4c";
  };

  function renderPanel(svg, devices) {
    svg.setAttribute("height", svgHeight);
    svg.setAttribute("viewBox", `0 0 220 ${svgHeight}`);
    svg.innerHTML = "";
    // Outer rack frame.
    const frame = document.createElementNS(svgNS, "rect");
    frame.setAttribute("x", 30); frame.setAttribute("y", 10);
    frame.setAttribute("width", 180); frame.setAttribute("height", uHeight * rowHeight);
    frame.setAttribute("fill", "#f7f9fa"); frame.setAttribute("stroke", "var(--line, #dfe5e8)");
    svg.appendChild(frame);
    for (let u = 1; u <= uHeight; u++) {
      const y = 10 + (uHeight - u) * rowHeight;
      const label = document.createElementNS(svgNS, "text");
      label.textContent = u;
      label.setAttribute("x", 24); label.setAttribute("y", y + rowHeight - 5);
      label.setAttribute("text-anchor", "end"); label.setAttribute("font-size", "8");
      label.setAttribute("fill", "#94a3ac");
      svg.appendChild(label);
      const gridline = document.createElementNS(svgNS, "line");
      gridline.setAttribute("x1", 30); gridline.setAttribute("x2", 210);
      gridline.setAttribute("y1", y); gridline.setAttribute("y2", y);
      gridline.setAttribute("stroke", "#edf0f2");
      svg.appendChild(gridline);
    }
    devices.forEach((device) => {
      const height = Math.max(device.u_height, 1);
      const y = 10 + (uHeight - (device.position + height - 1)) * rowHeight;
      const group = document.createElementNS(svgNS, "a");
      group.setAttribute("href", `/cmdb/${device.id}/edit`);
      const block = document.createElementNS(svgNS, "rect");
      block.setAttribute("x", 32); block.setAttribute("y", y);
      block.setAttribute("width", 176); block.setAttribute("height", height * rowHeight - 2);
      block.setAttribute("fill", colorFor(device.ci_class));
      block.setAttribute("rx", 3);
      const title = document.createElementNS(svgNS, "title");
      title.textContent = `${device.name} · ${device.ci_class} · ${device.status}`;
      block.appendChild(title);
      const text = document.createElementNS(svgNS, "text");
      text.textContent = device.name;
      text.setAttribute("x", 40); text.setAttribute("y", y + (height * rowHeight) / 2 + 3);
      text.setAttribute("font-size", "9.5"); text.setAttribute("fill", "#fff");
      group.appendChild(block);
      group.appendChild(text);
      svg.appendChild(group);
    });
  }

  const front = document.getElementById("rack-elevation-front");
  const rear = document.getElementById("rack-elevation-rear");
  if (front) renderPanel(front, payload.front || []);
  if (rear) renderPanel(rear, payload.rear || []);

  const empty = document.getElementById("rack-elevation-empty");
  if (empty && !(payload.front || []).length && !(payload.rear || []).length) {
    empty.hidden = false;
  }

  const pduList = document.getElementById("rack-pdu-list");
  if (pduList && (payload.pdus || []).length) {
    pduList.innerHTML = payload.pdus.map((pdu) => `
      <a href="/cmdb/${pdu.id}/edit" class="rack-pdu-row">
        <strong>${pdu.name}</strong>
        <span>${pdu.power_watts != null ? pdu.power_watts + "W" : "power not tracked"}</span>
      </a>`).join("");
  }

  const stats = payload.stats || {};
  const setStat = (fillId, labelId, used, total, unit) => {
    const fill = document.getElementById(fillId);
    const label = document.getElementById(labelId);
    if (!fill || !label) return;
    if (used == null || !total) {
      label.textContent = "Not tracked";
      fill.style.width = "0%";
      return;
    }
    const pct = Math.min(100, Math.round((used / total) * 100));
    fill.style.width = `${pct}%`;
    label.textContent = `${used}${unit ? " " + unit : ""} / ${total}${unit ? " " + unit : ""} (${pct}%)`;
  };
  setStat("rack-stat-space", "rack-stat-space-label", stats.space_used_u, stats.space_total_u, "U");
  // Weight/power have no meaningful "total" to bar-fill against (this app
  // has no rack max-load/max-draw schema) -- the bar is just a tracked/
  // not-tracked indicator, not a percentage. The fill <div> has no CSS
  // width of its own, so it defaults to filling its container unless set
  // explicitly here in every branch, including "not tracked".
  if (stats.weight_kg != null) {
    document.getElementById("rack-stat-weight-label").textContent = `${stats.weight_kg} kg`;
    document.getElementById("rack-stat-weight").style.width = "100%";
  } else {
    document.getElementById("rack-stat-weight-label").textContent = "Not tracked";
    document.getElementById("rack-stat-weight").style.width = "0%";
  }
  if (stats.power_watts != null) {
    document.getElementById("rack-stat-power-label").textContent = `${stats.power_watts} W`;
    document.getElementById("rack-stat-power").style.width = "100%";
  } else {
    document.getElementById("rack-stat-power-label").textContent = "Not tracked";
    document.getElementById("rack-stat-power").style.width = "0%";
  }
});
