/* Accessible planning controls; all writes remain normal CSRF-protected forms. */
(function () {
  'use strict';
  const tr = window.ServiceOpsI18n?.tr || (text => text);
  const feedback = document.querySelector('[data-plan-feedback]');
  function fail(message, error) {
    console.error('Project planning interaction failed', error?.name || 'Error');
    if (feedback) feedback.textContent = message;
  }
  try {
    const canvas = document.querySelector('[data-plan-canvas]');
    const surface = document.querySelector('[data-plan-surface]');
    const rows = Array.from(document.querySelectorAll('[data-plan-row]'));
    const collapsed = new Set();
    let dependencies = [];
    const data = document.querySelector('[data-plan-dependencies]');
    if (data) dependencies = JSON.parse(data.textContent);
    function draw() {
      try {
        if (!canvas) return;
        const svg = canvas.querySelector('[data-plan-connectors]');
        if (!svg) return;
        svg.querySelectorAll('[data-edge],[data-today],[data-grid]').forEach(node => node.remove());
        const box = canvas.getBoundingClientRect();
        svg.setAttribute('width', String(canvas.scrollWidth));
        svg.setAttribute('height', String(canvas.scrollHeight));
        const firstTrack = canvas.querySelector('[data-plan-track]');
        if (firstTrack && canvas.dataset.todayVisible === 'true') {
          const track = firstTrack.getBoundingClientRect();
          const x = track.left - box.left + track.width * Number(canvas.dataset.todayLeft) / 100;
          const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
          line.setAttribute('x1', String(x)); line.setAttribute('x2', String(x));
          line.setAttribute('y1', '44'); line.setAttribute('y2', String(canvas.scrollHeight));
          line.setAttribute('data-today', '1'); line.classList.add('plan-today-line'); svg.appendChild(line);
        }
        canvas.querySelectorAll('[data-plan-tick]').forEach(tick => {
          const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
          const x = tick.getBoundingClientRect().left - box.left;
          line.setAttribute('x1', String(x)); line.setAttribute('x2', String(x));
          line.setAttribute('y1', '48'); line.setAttribute('y2', String(canvas.scrollHeight));
          line.setAttribute('data-grid', '1'); line.classList.add('plan-grid-line'); svg.appendChild(line);
        });
        const byId = new Map(rows.map(row => [Number(row.dataset.planRow), row]));
        for (const edge of dependencies) {
          const from = byId.get(edge.source), to = byId.get(edge.target);
          if (!from || !to || from.hidden || to.hidden) continue;
          const a = from.querySelector('[data-plan-bar]'), b = to.querySelector('[data-plan-bar]');
          if (!a || !b) continue;
          const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
          const x1 = ra.right - box.left, y1 = ra.top + ra.height / 2 - box.top;
          const x2 = rb.left - box.left, y2 = rb.top + rb.height / 2 - box.top;
          const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          const bend = Math.max(x1 + 14, x2 - 14);
          path.setAttribute('d', `M${x1} ${y1} C${bend} ${y1},${bend} ${y2},${x2} ${y2}`);
          path.setAttribute('marker-end', 'url(#plan-arrow)');
          path.setAttribute('data-edge', '1');
          if (edge.conflict) path.classList.add('dependency-conflict');
          svg.appendChild(path);
        }
      } catch (error) { fail(tr('Dependency lines could not be drawn. The dependency list remains available.'), error); }
    }
    function updateTree() {
      try {
        const byId = new Map(rows.map(row => [row.dataset.planRow, row]));
        for (const row of rows) {
          let parent = row.dataset.parent, hidden = false, visited = new Set();
          while (parent && byId.has(parent)) {
            if (visited.has(parent)) throw new Error('InvalidHierarchy');
            visited.add(parent);
            if (collapsed.has(parent)) { hidden = true; break; }
            parent = byId.get(parent).dataset.parent;
          }
          row.hidden = hidden;
          const toggle = row.querySelector('[data-plan-toggle]');
          const hasChildren = rows.some(child => child.dataset.parent === row.dataset.planRow);
          toggle.hidden = !hasChildren;
          toggle.setAttribute('aria-expanded', String(!collapsed.has(row.dataset.planRow)));
          toggle.textContent = collapsed.has(row.dataset.planRow) ? '▸' : '▾';
        }
        draw();
      } catch (error) { fail(tr('The hierarchy could not be updated. Reload this view.'), error); }
    }
    document.querySelectorAll('[data-plan-toggle]').forEach(button => button.addEventListener('click', () => {
      try {
        const id = button.dataset.planToggle;
        if (collapsed.has(id)) collapsed.delete(id); else collapsed.add(id);
        updateTree();
      } catch (error) { fail(tr('The hierarchy could not be updated. Reload this view.'), error); }
    }));
    document.querySelector('[data-plan-expand]')?.addEventListener('click', () => { collapsed.clear(); updateTree(); });
    document.querySelector('[data-plan-collapse]')?.addEventListener('click', () => { rows.forEach(row => collapsed.add(row.dataset.planRow)); updateTree(); });
    document.querySelector('[data-plan-share]')?.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(location.href); if (feedback) feedback.textContent = tr('View link copied. Recipients still need project access.'); }
      catch (error) { fail(tr('Copy is unavailable. Copy the address from your browser instead.'), error); }
    });
    document.querySelector('[data-plan-fullscreen]')?.addEventListener('click', async () => {
      try {
        if (!document.fullscreenElement) await surface?.requestFullscreen(); else await document.exitFullscreen();
      } catch (error) { fail(tr('Full screen is unavailable in this browser.'), error); }
    });
    window.addEventListener('resize', draw);
    document.addEventListener('fullscreenchange', draw);
    canvas?.querySelectorAll('[data-plan-tick]').forEach(tick => {
      const scale = tick.parentElement.dataset.planScale;
      tick.textContent = new Intl.DateTimeFormat(document.documentElement.lang || 'en', {timeZone: 'UTC', month: 'short', ...(scale === 'weeks' ? {day: 'numeric'} : {year: 'numeric'})}).format(new Date(tick.dataset.planTick + 'T00:00:00Z'));
    });
    updateTree();
    if (document.fonts?.ready) document.fonts.ready.then(draw).catch(error => fail(tr('The timeline font layout could not be refreshed.'), error));
  } catch (error) { fail(tr('Planning controls could not be loaded. Normal page links and forms remain available.'), error); }
})();
