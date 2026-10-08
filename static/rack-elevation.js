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
  const highlightId = payload.highlight_ci_id;
  let highlightedBlock = null;

  // Compact (embedded-preview) mode shows a window around the highlighted
  // device instead of the whole rack -- a 42U rack with one 1U device in
  // it is mostly empty space, which is exactly what made the embedded
  // preview look sparse/broken rather than compact and focused.
  let winStart = 1, winEnd = uHeight;
  if (payload.compact && highlightId) {
    const all = [...(payload.front || []), ...(payload.rear || []), ...(payload.pdus || [])];
    const target = all.find((d) => d.id === highlightId);
    if (target && target.position != null && !target.placement_note) {
      const height = Math.max(target.u_height || 1, 1);
      winStart = Math.max(1, target.position - 5);
      winEnd = Math.min(uHeight, target.position + height - 1 + 5);
    }
  }
  const windowSize = winEnd - winStart + 1;
  const svgHeight = windowSize * rowHeight + 20;

  const svgNS = "http://www.w3.org/2000/svg";
  const colorFor = (ciClass) => {
    const key = (ciClass || "").toLowerCase();
    if (key.includes("switch") || key.includes("router")) return "#f9aa3c";
    if (key === "pdu") return "#c0392b";
    if (key.includes("storage")) return "#7c5cbf";
    return "#003e4c";
  };

  // Walk through NetBox → exact bundled model → local type illustration.
  // Each failed URL is tried at most once, so a missing image cannot loop.
  function applyArtwork(image, device, svg = false) {
    const urls = [...new Set([device.artwork_url, ...(device.artwork_fallbacks || [])].filter(Boolean))];
    let index = 0;
    // Probe through an HTML image before publishing the URL into an SVG
    // faceplate, so only a successfully loaded candidate is displayed.
    const loader = svg ? new Image() : image;
    if (svg) loader.addEventListener("load", () => image.setAttribute("href", urls[index]));
    const setUrl = () => {
      loader.setAttribute("src", urls[index]);
      // English key kept in the dataset; translated only where it is shown.
      const source = urls[index].includes("/generic-") ? trNoop("Type illustration")
        : urls[index].includes("/device-artwork/") && !urls[index].startsWith("/cmdb/") ? trNoop("Exact model image") : trNoop("NetBox model image");
      image.dataset.artworkSource = source;
      if (image.parentElement) {
        const sourceLabel = image.parentElement.querySelector(".rack-image-source");
        if (sourceLabel) sourceLabel.textContent = `${tr(source)} · ${tr(device.identification?.basis || "")}`;
      }
    };
    loader.addEventListener("error", () => {
      index += 1;
      if (index < urls.length) setUrl();
      else image.remove();
    });
    if (urls.length) setUrl();
  }

  const describe = (device) => [device.name, device.vendor, device.model,
    device.identification?.label || device.ci_class, device.status,
    device.identification?.basis, device.placement_note].filter(Boolean).join(" · ");

  function renderPanel(svg, devices) {
    svg.setAttribute("height", svgHeight);
    svg.setAttribute("viewBox", `0 0 220 ${svgHeight}`);
    svg.innerHTML = "";
    // Outer rack frame.
    const frame = document.createElementNS(svgNS, "rect");
    frame.setAttribute("x", 30); frame.setAttribute("y", 10);
    frame.setAttribute("width", 180); frame.setAttribute("height", windowSize * rowHeight);
    // Colors come from the .rack-elevation-* rules in app.css so themes can restyle them.
    frame.setAttribute("class", "rack-elevation-frame");
    svg.appendChild(frame);
    for (let u = winStart; u <= winEnd; u++) {
      const y = 10 + (winEnd - u) * rowHeight;
      const label = document.createElementNS(svgNS, "text");
      label.textContent = u;
      label.setAttribute("x", 24); label.setAttribute("y", y + rowHeight - 5);
      label.setAttribute("text-anchor", "end"); label.setAttribute("font-size", "8");
      label.setAttribute("class", "rack-elevation-unit");
      svg.appendChild(label);
      const gridline = document.createElementNS(svgNS, "line");
      gridline.setAttribute("x1", 30); gridline.setAttribute("x2", 210);
      gridline.setAttribute("y1", y); gridline.setAttribute("y2", y);
      gridline.setAttribute("class", "rack-elevation-gridline");
      svg.appendChild(gridline);
    }
    devices.forEach((device) => {
      const height = device.u_height;
      const top = device.position + height - 1;
      if (top < winStart || device.position > winEnd) return; // outside the visible window
      const y = 10 + (winEnd - top) * rowHeight;
      const group = document.createElementNS(svgNS, "a");
      group.setAttribute("href", `/cmdb/${device.id}/edit`);
      // This view is iframed into the compact CI-page preview (see
      // rack_elevation_embed.html); without target="_top" a click navigates
      // the iframe itself to the full ci_form.html page, which contains
      // another copy of this same iframe -- an infinite nesting doll rather
      // than a real navigation. Harmless no-op on the full (non-iframed)
      // /cmdb/racks/<id> view.
      group.setAttribute("target", "_top");
      group.setAttribute("aria-label", describe(device));
      const block = document.createElementNS(svgNS, "rect");
      block.setAttribute("x", 32); block.setAttribute("y", y);
      block.setAttribute("width", 176); block.setAttribute("height", height * rowHeight - 2);
      block.setAttribute("fill", colorFor(device.ci_class));
      block.setAttribute("rx", 3);
      if (highlightId && device.id === highlightId) {
        block.setAttribute("stroke", "#f9aa3c");
        block.setAttribute("stroke-width", "3");
        block.classList.add("rack-elevation-highlight");
        highlightedBlock = block;
      }
      const title = document.createElementNS(svgNS, "title");
      title.textContent = describe(device);
      group.appendChild(title);
      group.appendChild(block);
      if (device.artwork_url) {
        const artwork = document.createElementNS(svgNS, "image");
        applyArtwork(artwork, device, true);
        artwork.setAttribute("x", 33); artwork.setAttribute("y", y + 1);
        artwork.setAttribute("width", 174); artwork.setAttribute("height", Math.max(height * rowHeight - 4, 1));
        artwork.setAttribute("preserveAspectRatio", "xMidYMid meet");
        artwork.setAttribute("aria-hidden", "true");
        group.appendChild(artwork);
      }
      const text = document.createElementNS(svgNS, "text");
      text.textContent = device.name.length > 36 ? `${device.name.slice(0, 33)}…` : device.name;
      text.setAttribute("x", 40); text.setAttribute("y", y + height * rowHeight - 3);
      text.setAttribute("font-size", "7"); text.setAttribute("fill", "#fff");
      text.setAttribute("paint-order", "stroke"); text.setAttribute("stroke", "#102a32");
      text.setAttribute("stroke-width", "2"); text.setAttribute("stroke-linejoin", "round");
      group.appendChild(text);
      svg.appendChild(group);
    });
  }

  const front = document.getElementById("rack-elevation-front");
  const rear = document.getElementById("rack-elevation-rear");
  if (front) renderPanel(front, payload.front || []);
  if (rear) renderPanel(rear, payload.rear || []);

  const empty = document.getElementById("rack-elevation-empty");
  if (empty) empty.hidden = ["front", "rear", "pdus", "unplaced"].some((key) => (payload[key] || []).length);

  function renderEquipmentList(id, devices) {
    const list = document.getElementById(id);
    if (!list || !devices.length) return;
    list.replaceChildren(...devices.map((device) => {
      const row = document.createElement("a");
      row.href = `/cmdb/${encodeURIComponent(device.id)}/edit`;
      row.target = "_top";
      row.className = `rack-equipment-row${device.id === highlightId ? " rack-pdu-row-highlight" : ""}`;
      row.setAttribute("aria-label", describe(device));
      const image = document.createElement("img");
      image.alt = "";
      image.width = 240; image.height = 40;
      applyArtwork(image, device);
      const name = document.createElement("strong");
      name.textContent = device.name;
      const detail = document.createElement("span");
      detail.textContent = [device.vendor, device.model, device.identification?.label, device.status,
        device.placement_note, device.power_watts != null ? `${device.power_watts}W` : null].filter(Boolean).join(" · ");
      const source = document.createElement("small");
      source.className = "rack-image-source";
      source.textContent = `${tr(image.dataset.artworkSource || device.artwork_source)} · ${tr(device.identification?.basis || "")}`;
      row.append(image, name, detail, source);
      return row;
    }));
  }
  renderEquipmentList("rack-pdu-list", payload.pdus || []);
  renderEquipmentList("rack-unplaced-list", payload.unplaced || []);
  // The inventory also makes every device discoverable without relying on
  // hover tooltips, tiny SVG labels, or a precise U placement.
  renderEquipmentList("rack-equipment-list", [...(payload.front || []), ...(payload.rear || []), ...(payload.pdus || []), ...(payload.unplaced || [])]);

  if (highlightedBlock) {
    highlightedBlock.scrollIntoView({ behavior: "smooth", block: "center", inline: "center" });
  }

  const stats = payload.stats || {};
  const setStat = (fillId, labelId, used, total, unit) => {
    const fill = document.getElementById(fillId);
    const label = document.getElementById(labelId);
    if (!fill || !label) return;
    if (used == null || !total) {
      label.textContent = tr("Not tracked");
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
  // not-tracked indicator, not a percentage.
  const setTrackedStat = (fillId, labelId, value, unit) => {
    const fill = document.getElementById(fillId);
    const label = document.getElementById(labelId);
    // Guarded the same way setStat() is -- these elements don't exist at
    // all on the compact /embed view (no stats panel there), and calling
    // .textContent on a null getElementById result throws, which was
    // silently breaking the embedded rack preview on every CI page that
    // has one (found via a real headless-browser console-error check, not
    // visible from the screenshot alone).
    if (!fill || !label) return;
    if (value == null) {
      label.textContent = tr("Not tracked");
      fill.style.width = "0%";
      return;
    }
    label.textContent = `${value}${unit ? " " + unit : ""}`;
    fill.style.width = "100%";
  };
  setTrackedStat("rack-stat-weight", "rack-stat-weight-label", stats.weight_kg, "kg");
  setTrackedStat("rack-stat-power", "rack-stat-power-label", stats.power_watts, "W");
});

// Identification bases the server sends (serviceops_core/equipment_artwork.py),
// listed for catalog extraction; they are translated where shown.
trNoop("Exact model"); trNoop("Model family"); trNoop("Name hint"); trNoop("No recognized equipment metadata");
