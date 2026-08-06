/* Self-contained force-directed graph renderer for the CMDB topology map --
   no external charting library, consistent with this app's no-CDN policy.
   A small, dependency-free physics simulation: nodes repel each other,
   edges pull connected nodes together, everything is drawn as plain SVG. */
document.addEventListener("DOMContentLoaded", () => {
  const svg = document.getElementById("cmdb-topology-svg");
  const empty = document.getElementById("cmdb-topology-empty");
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

  const width = svg.clientWidth || 900;
  const height = 640;
  const nodes = graph.nodes.map((node, index) => ({
    ...node,
    x: width / 2 + Math.cos(index) * 200 + Math.random() * 40,
    y: height / 2 + Math.sin(index) * 200 + Math.random() * 40,
    vx: 0, vy: 0,
  }));
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const edges = graph.edges
    .map((edge) => ({
      source: nodeById.get(edge.source), target: nodeById.get(edge.target),
      type: edge.type, label: edge.label,
    }))
    .filter((edge) => edge.source && edge.target);

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
    edges.forEach((edge) => {
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
  const edgeLines = edges.map((edge) => {
    const line = document.createElementNS(svgNS, "line");
    line.setAttribute("stroke", "#c7d1d5");
    line.setAttribute("stroke-width", "1.5");
    const title = document.createElementNS(svgNS, "title");
    title.textContent = edge.label
      ? `${edge.source.name} — ${edge.type} (${edge.label}) → ${edge.target.name}`
      : `${edge.source.name} — ${edge.type} → ${edge.target.name}`;
    line.appendChild(title);
    svg.appendChild(line);
    let portLabel = null;
    if (edge.label) {
      portLabel = document.createElementNS(svgNS, "text");
      portLabel.textContent = edge.label;
      portLabel.setAttribute("font-size", "9");
      portLabel.setAttribute("text-anchor", "middle");
      portLabel.setAttribute("fill", "#667582");
      svg.appendChild(portLabel);
    }
    return { edge, line, portLabel };
  });

  const nodeGroups = nodes.map((node) => {
    const group = document.createElementNS(svgNS, "g");
    group.style.cursor = "grab";
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
    const title = document.createElementNS(svgNS, "title");
    title.textContent = `${node.name} · ${node.ci_class} · ${node.status} · ${node.discovery_source}`;
    group.appendChild(circle);
    group.appendChild(label);
    group.appendChild(title);
    svg.appendChild(group);

    let dragOffset = null;
    group.addEventListener("pointerdown", (event) => {
      node.dragging = true;
      group.setPointerCapture(event.pointerId);
      const rect = svg.getBoundingClientRect();
      dragOffset = { x: event.clientX - rect.left - node.x, y: event.clientY - rect.top - node.y };
    });
    group.addEventListener("pointermove", (event) => {
      if (!node.dragging || !dragOffset) return;
      const rect = svg.getBoundingClientRect();
      node.x = event.clientX - rect.left - dragOffset.x;
      node.y = event.clientY - rect.top - dragOffset.y;
    });
    group.addEventListener("pointerup", () => { node.dragging = false; dragOffset = null; });
    return { node, group, circle, label };
  });

  function render() {
    edgeLines.forEach(({ edge, line, portLabel }) => {
      line.setAttribute("x1", edge.source.x); line.setAttribute("y1", edge.source.y);
      line.setAttribute("x2", edge.target.x); line.setAttribute("y2", edge.target.y);
      if (portLabel) {
        portLabel.setAttribute("x", (edge.source.x + edge.target.x) / 2);
        portLabel.setAttribute("y", (edge.source.y + edge.target.y) / 2 - 4);
      }
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
