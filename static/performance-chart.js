(() => {
  const container = document.getElementById("performance-charts");
  if (!container) return;
  const empty = document.getElementById("performance-empty");
  const rangeSelect = document.getElementById("performance-range");
  const url = container.dataset.url;

  const SVG_NS = "http://www.w3.org/2000/svg";
  const CHART_WIDTH = 760;
  const CHART_HEIGHT = 140;
  const PADDING = 28;

  function buildPath(values, maxValue) {
    if (!values.length) return "";
    const stepX = values.length > 1 ? (CHART_WIDTH - PADDING * 2) / (values.length - 1) : 0;
    const scaleY = (value) => {
      if (maxValue <= 0) return CHART_HEIGHT - PADDING;
      return CHART_HEIGHT - PADDING - (value / maxValue) * (CHART_HEIGHT - PADDING * 2);
    };
    return values.map((value, index) => {
      const x = PADDING + index * stepX;
      const y = scaleY(value);
      return `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(" ");
  }

  function formatTime(iso) {
    if (!iso) return "";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "";
    return date.toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  }

  function renderChart(title, unit, values, times, color) {
    const wrap = document.createElement("div");
    wrap.className = "performance-chart";
    const heading = document.createElement("h3");
    const latest = values.length ? values[values.length - 1] : 0;
    heading.textContent = `${title}: ${latest}${unit}`;
    wrap.appendChild(heading);

    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", `0 0 ${CHART_WIDTH} ${CHART_HEIGHT + 16}`);
    svg.setAttribute("preserveAspectRatio", "none");
    svg.setAttribute("class", "performance-chart-svg");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `${title} over the selected period, latest value ${latest}${unit}`);

    const maxValue = Math.max(1, ...values);
    [0.25, 0.5, 0.75].forEach((fraction) => {
      const line = document.createElementNS(SVG_NS, "line");
      const y = CHART_HEIGHT - PADDING - fraction * (CHART_HEIGHT - PADDING * 2);
      line.setAttribute("x1", PADDING);
      line.setAttribute("x2", CHART_WIDTH - PADDING);
      line.setAttribute("y1", y);
      line.setAttribute("y2", y);
      line.setAttribute("class", "performance-chart-gridline");
      svg.appendChild(line);
    });

    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", buildPath(values, maxValue));
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", color);
    path.setAttribute("stroke-width", "2");
    path.setAttribute("stroke-linejoin", "round");
    path.setAttribute("stroke-linecap", "round");
    svg.appendChild(path);

    // Without any x-axis reference, this chart is just a wiggly line with
    // no way to tell what time range or which point is "now" -- the exact
    // complaint. Each point gets an invisible-until-hover dot carrying an
    // exact value+timestamp tooltip, and the first/middle/last points get
    // a visible time label along the bottom.
    const stepX = values.length > 1 ? (CHART_WIDTH - PADDING * 2) / (values.length - 1) : 0;
    const scaleY = (value) => {
      if (maxValue <= 0) return CHART_HEIGHT - PADDING;
      return CHART_HEIGHT - PADDING - (value / maxValue) * (CHART_HEIGHT - PADDING * 2);
    };
    const labelIndexes = new Set(
      values.length > 1 ? [0, Math.floor((values.length - 1) / 2), values.length - 1] : [0],
    );
    values.forEach((value, index) => {
      const x = PADDING + index * stepX;
      const y = scaleY(value);
      const dot = document.createElementNS(SVG_NS, "circle");
      dot.setAttribute("cx", x.toFixed(1));
      dot.setAttribute("cy", y.toFixed(1));
      dot.setAttribute("r", "6");
      dot.setAttribute("class", "performance-chart-point");
      const title = document.createElementNS(SVG_NS, "title");
      title.textContent = `${formatTime(times[index])}: ${value}${unit}`;
      dot.appendChild(title);
      svg.appendChild(dot);
      if (labelIndexes.has(index)) {
        const label = document.createElementNS(SVG_NS, "text");
        label.textContent = formatTime(times[index]);
        label.setAttribute("x", x.toFixed(1));
        label.setAttribute("y", CHART_HEIGHT + 12);
        label.setAttribute(
          "text-anchor", index === 0 ? "start" : index === values.length - 1 ? "end" : "middle",
        );
        label.setAttribute("class", "performance-chart-axis-label");
        svg.appendChild(label);
      }
    });

    wrap.appendChild(svg);
    return wrap;
  }

  async function load() {
    const hours = rangeSelect ? rangeSelect.value : "6";
    let response;
    try {
      response = await fetch(`${url}?hours=${encodeURIComponent(hours)}`);
    } catch (error) {
      empty.textContent = "Could not load performance data right now.";
      return;
    }
    if (!response.ok) {
      empty.textContent = "Could not load performance data right now.";
      return;
    }
    const payload = await response.json();
    container.querySelectorAll(".performance-chart").forEach((el) => el.remove());
    if (!payload.points.length) {
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    const times = payload.points.map((point) => point.at);
    const rps = payload.points.map((point) => point.requests_per_sec);
    const latency = payload.points.map((point) => point.avg_latency_ms);
    const errorRate = payload.points.map((point) => Math.round(point.error_rate * 1000) / 10);
    container.appendChild(renderChart("Requests / second", "/s", rps, times, "#0c7c68"));
    container.appendChild(renderChart("Average latency", "ms", latency, times, "#003e4c"));
    container.appendChild(renderChart("Error rate", "%", errorRate, times, "#c0392b"));
  }

  rangeSelect?.addEventListener("change", load);
  load();
})();
