/* Self-contained force-directed graph renderer for the CMDB topology map --
   no external charting library, consistent with this app's no-CDN policy.
   Progressive disclosure: only "backbone" nodes (infrastructure classes or
   degree >= 2) render initially; everything else starts collapsed behind its
   neighbor as a "+N more" badge, expanded on click. Pan (drag empty canvas)
   and zoom (wheel / buttons) are implemented via an SVG viewBox transform. */
document.addEventListener("DOMContentLoaded", () => {
  const svg = document.getElementById("cmdb-topology-svg");
  const empty = document.getElementById("cmdb-topology-empty");
  const detailPanel = document.getElementById("cmdb-topology-detail");
  const detailBody = document.getElementById("cmdb-topology-detail-body");
  const detailClose = document.getElementById("cmdb-topology-detail-close");
  const zoomInBtn = document.getElementById("cmdb-topology-zoom-in");
  const zoomOutBtn = document.getElementById("cmdb-topology-zoom-out");
  const resetBtn = document.getElementById("cmdb-topology-reset");
  let graph = { nodes: [], edges: [] };
  try {
    graph = svg ? JSON.parse(svg.dataset.graph || "{}") : graph;
  } catch (error) {
    graph = { nodes: [], edges: [] };
  }
  graph.nodes = graph.nodes || [];
  graph.edges = graph.edges || [];
  if (!svg || !graph.nodes.length) {
    if (empty) empty.hidden = false;
    if (svg) svg.hidden = true;
    return;
  }

  const backboneClasses = (svg.dataset.backboneClasses || "Switch,Router,Server")
    .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);

  const width = svg.clientWidth || 900;
  const height = 640;
  const nodes = graph.nodes.map((node, index) => ({
    ...node,
    x: width / 2 + Math.cos(index) * 200 + Math.random() * 40,
    y: height / 2 + Math.sin(index) * 200 + Math.random() * 40,
    vx: 0, vy: 0,
  }));
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const allEdges = graph.edges
    .map((edge) => ({
      source: nodeById.get(edge.source), target: nodeById.get(edge.target),
      type: edge.type, label: edge.label,
    }))
    .filter((edge) => edge.source && edge.target);

  const degree = new Map();
  allEdges.forEach((edge) => {
    degree.set(edge.source.id, (degree.get(edge.source.id) || 0) + 1);
    degree.set(edge.target.id, (degree.get(edge.target.id) || 0) + 1);
  });
  nodes.forEach((node) => {
    node.isBackbone = backboneClasses.includes((node.ci_class || "").toLowerCase())
      || (degree.get(node.id) || 0) >= 2;
    node.expanded = node.isBackbone;
  });

  function visibleNodeSet() {
    const visible = new Set();
    nodes.forEach((node) => { if (node.expanded) visible.add(node.id); });
    // A non-backbone node attached only to an expanded backbone node is shown
    // once that backbone neighbor is expanded (this is the "+N more" reveal).
    allEdges.forEach((edge) => {
      if (visible.has(edge.source.id) && edge.source.expandedChildren) visible.add(edge.target.id);
      if (visible.has(edge.target.id) && edge.target.expandedChildren) visible.add(edge.source.id);
    });
    return visible;
  }

  function collapsedNeighborCount(node) {
    const visible = visibleNodeSet();
    let count = 0;
    allEdges.forEach((edge) => {
      if (edge.source.id === node.id && !visible.has(edge.target.id)) count += 1;
      if (edge.target.id === node.id && !visible.has(edge.source.id)) count += 1;
    });
    return count;
  }

  let panX = 0, panY = 0, zoom = 1;
  function applyViewBox() {
    const w = width / zoom, h = height / zoom;
    svg.setAttribute("viewBox", `${panX} ${panY} ${w} ${h}`);
  }
  applyViewBox();

  svg.addEventListener("wheel", (event) => {
    event.preventDefault();
    const factor = event.deltaY < 0 ? 1.15 : 1 / 1.15;
    zoom = Math.max(0.4, Math.min(4, zoom * factor));
    applyViewBox();
  }, { passive: false });

  let panning = false, panStart = null;
  svg.addEventListener("pointerdown", (event) => {
    if (event.target !== svg) return;
    panning = true;
    panStart = { x: event.clientX, y: event.clientY, panX, panY };
    svg.style.cursor = "grabbing";
  });
  svg.addEventListener("pointermove", (event) => {
    if (!panning || !panStart) return;
    const dx = (event.clientX - panStart.x) / zoom;
    const dy = (event.clientY - panStart.y) / zoom;
    panX = panStart.panX - dx;
    panY = panStart.panY - dy;
    applyViewBox();
  });
  svg.addEventListener("pointerup", () => { panning = false; svg.style.cursor = "grab"; });
  svg.addEventListener("pointerleave", () => { panning = false; svg.style.cursor = "grab"; });

  if (zoomInBtn) zoomInBtn.addEventListener("click", () => { zoom = Math.min(4, zoom * 1.3); applyViewBox(); });
  if (zoomOutBtn) zoomOutBtn.addEventListener("click", () => { zoom = Math.max(0.4, zoom / 1.3); applyViewBox(); });
  if (resetBtn) resetBtn.addEventListener("click", () => { panX = 0; panY = 0; zoom = 1; applyViewBox(); });

  function tick() {
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const distSq = Math.max(dx * dx + dy * dy, 1);
        const force = 1800 / distSq;
        const dist = Math.sqrt(distSq);
        a.vx += (dx / dist) * force; a.vy += (dy / dist) * force;
        b.vx -= (dx / dist) * force; b.vy -= (dy / dist) * force;
      }
    }
    allEdges.forEach((edge) => {
      const dx = edge.target.x - edge.source.x, dy = edge.target.y - edge.source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const pull = (dist - 140) * 0.02;
      edge.source.vx += (dx / dist) * pull; edge.source.vy += (dy / dist) * pull;
      edge.target.vx -= (dx / dist) * pull; edge.target.vy -= (dy / dist) * pull;
    });
    nodes.forEach((node) => {
      if (node.dragging) return;
      node.vx *= 0.85; node.vy *= 0.85;
      node.x += node.vx; node.y += node.vy;
      node.x = Math.max(30, Math.min(width - 30, node.x));
      node.y = Math.max(30, Math.min(height - 30, node.y));
    });
  }

  const svgNS = "http://www.w3.org/2000/svg";
  const edgeEls = allEdges.map((edge) => {
    const line = document.createElementNS(svgNS, "line");
    line.setAttribute("stroke", "#c7d1d5");
    line.setAttribute("stroke-width", "1.5");
    const title = document.createElementNS(svgNS, "title");
    title.textContent = edge.label
      ? `${edge.source.name} — ${edge.type} (${edge.label}) → ${edge.target.name}`
      : `${edge.source.name} — ${edge.type} → ${edge.target.name}`;
    line.appendChild(title);
    const portLabel = document.createElementNS(svgNS, "text");
    if (edge.label) {
      portLabel.textContent = edge.label;
      portLabel.setAttribute("font-size", "9");
      portLabel.setAttribute("text-anchor", "middle");
      portLabel.setAttribute("fill", "#667582");
    }
    return { edge, line, portLabel };
  });

  function showDetail(node) {
    if (!detailPanel || !detailBody) return;
    const outgoing = allEdges.filter((edge) => edge.source.id === node.id || edge.target.id === node.id);
    const rows = outgoing.map((edge) => {
      const isSource = edge.source.id === node.id;
      const neighbor = isSource ? edge.target : edge.source;
      const [localPort, neighborPort] = (edge.label || "").split("<->").map((s) => (s || "").trim());
      return { neighbor, localPort: isSource ? localPort : neighborPort, neighborPort: isSource ? neighborPort : localPort, type: edge.type };
    });
    const isSwitchLike = ["switch", "router"].includes((node.ci_class || "").toLowerCase());
    const heading = isSwitchLike ? "Ports" : "Connected switches/routers";
    const relevant = isSwitchLike ? rows : rows.filter((r) => ["switch", "router"].includes((r.neighbor.ci_class || "").toLowerCase()));
    const tableRows = (relevant.length ? relevant : rows).map((r) => `
      <tr>
        <td>${r.localPort || "—"}</td>
        <td>${r.neighbor.name}${r.neighbor.ci_class ? ` (${r.neighbor.ci_class})` : ""}</td>
        <td>${r.neighborPort || "—"}</td>
      </tr>`).join("");
    detailBody.innerHTML = `
      <h3>${node.name}</h3>
      <p class="muted" style="font-size:12px">${node.ci_class || ""} · ${node.status || ""} · ${node.discovery_source || ""}</p>
      <h4 style="margin-top:14px">${heading}</h4>
      ${rows.length ? `<table class="ci-permissions-table"><thead><tr><th>Local port</th><th>Neighbor</th><th>Neighbor port</th></tr></thead><tbody>${tableRows}</tbody></table>` : '<p class="muted">No connections recorded.</p>'}
      <h4 style="margin-top:14px">Hostname resolution</h4>
      <div id="cmdb-topology-dns" class="muted">Looking up…</div>
    `;
    detailPanel.hidden = false;
    const dnsEl = document.getElementById("cmdb-topology-dns");
    fetch(`/cmdb/${node.id}/network-info`, { headers: { Accept: "application/json" } })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then((info) => {
        const parts = [];
        (info.addresses || []).forEach((entry) => {
          parts.push(`<div>${entry.ip} → ${entry.hostname || "no PTR record"}</div>`);
        });
        (info.hostnames || []).forEach((entry) => {
          parts.push(`<div>${entry.hostname} → ${(entry.ips || []).join(", ") || "no A/AAAA record"}</div>`);
        });
        dnsEl.innerHTML = parts.length ? parts.join("") : "No IP or hostname to resolve.";
      })
      .catch(() => { dnsEl.textContent = "Unable to resolve at this time."; });
  }
  if (detailClose) detailClose.addEventListener("click", () => { detailPanel.hidden = true; });

  const nodeGroups = nodes.map((node) => {
    const group = document.createElementNS(svgNS, "g");
    group.style.cursor = "pointer";
    const circle = document.createElementNS(svgNS, "circle");
    circle.setAttribute("r", "9");
    circle.setAttribute("fill", node.discovery_source === "Manual" ? "#003e4c" : "#f9aa3c");
    circle.setAttribute("stroke", "#fff");
    circle.setAttribute("stroke-width", "2");
    const label = document.createElementNS(svgNS, "text");
    label.textContent = node.name;
    label.setAttribute("font-size", "10.5");
    label.setAttribute("dy", "-13");
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("fill", "#43545b");
    const badge = document.createElementNS(svgNS, "text");
    badge.setAttribute("font-size", "9");
    badge.setAttribute("dy", "22");
    badge.setAttribute("text-anchor", "middle");
    badge.setAttribute("fill", "#f9aa3c");
    const title = document.createElementNS(svgNS, "title");
    title.textContent = `${node.name} · ${node.ci_class} · ${node.status} · ${node.discovery_source}`;
    group.appendChild(circle);
    group.appendChild(label);
    group.appendChild(badge);
    group.appendChild(title);
    svg.appendChild(group);

    let dragOffset = null;
    let moved = false;
    group.addEventListener("pointerdown", (event) => {
      node.dragging = true;
      moved = false;
      group.setPointerCapture(event.pointerId);
      const rect = svg.getBoundingClientRect();
      dragOffset = { x: event.clientX - rect.left - node.x, y: event.clientY - rect.top - node.y };
    });
    group.addEventListener("pointermove", (event) => {
      if (!node.dragging || !dragOffset) return;
      moved = true;
      const rect = svg.getBoundingClientRect();
      node.x = event.clientX - rect.left - dragOffset.x;
      node.y = event.clientY - rect.top - dragOffset.y;
    });
    group.addEventListener("pointerup", () => {
      node.dragging = false; dragOffset = null;
      if (!moved) {
        node.expandedChildren = !node.expandedChildren;
        node.expanded = true;
        showDetail(node);
        rebuild();
      }
    });
    return { node, group, circle, label, badge };
  });

  function rebuild() {
    const visible = visibleNodeSet();
    nodeGroups.forEach(({ node, group, badge }) => {
      const show = visible.has(node.id);
      group.style.display = show ? "" : "none";
      const count = show ? collapsedNeighborCount(node) : 0;
      badge.textContent = count > 0 ? `+${count} more` : "";
    });
    edgeEls.forEach(({ edge, line, portLabel }) => {
      const show = visible.has(edge.source.id) && visible.has(edge.target.id);
      line.style.display = show ? "" : "none";
      portLabel.style.display = show && edge.label ? "" : "none";
      if (portLabel.parentNode !== svg && show && edge.label) svg.appendChild(portLabel);
    });
  }
  rebuild();

  function render() {
    edgeEls.forEach(({ edge, line, portLabel }) => {
      line.setAttribute("x1", edge.source.x); line.setAttribute("y1", edge.source.y);
      line.setAttribute("x2", edge.target.x); line.setAttribute("y2", edge.target.y);
      portLabel.setAttribute("x", (edge.source.x + edge.target.x) / 2);
      portLabel.setAttribute("y", (edge.source.y + edge.target.y) / 2 - 4);
    });
    nodeGroups.forEach(({ node, group }) => {
      group.setAttribute("transform", `translate(${node.x},${node.y})`);
    });
  }

  let frame = 0;
  function step() {
    tick();
    render();
    frame += 1;
    if (frame < 260) requestAnimationFrame(step); else render();
  }
  requestAnimationFrame(step);
});
