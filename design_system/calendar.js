/* Shared progressive calendar: native values, constraints and server contracts remain authoritative. */
(function () {
  'use strict';
  const pairs = [['planned_start', 'planned_end'], ['starts_at', 'ends_at'], ['start_at', 'end_at'], ['from', 'to'], ['start_date', 'end_date'], ['start_date', 'due_date'], ['start_date', 'release_date'], ['start', 'due']];
  const selector = 'input[type="date"],input[type="datetime-local"]';
  let state = null;
  let serial = 0;
  let failed = false;
  const locale = document.documentElement.lang || 'en';
  const pad = n => String(n).padStart(2, '0');
  const iso = date => `${String(date.getFullYear()).padStart(4, '0')}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  function dateOf(value) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return null;
    const [year, month, day] = value.split('-').map(Number);
    const date = new Date(2000, month - 1, day, 12);
    date.setFullYear(year);
    return iso(date) === value ? date : null;
  }
  const dayValue = input => input.value.slice(0, 10);
  const timeValue = input => input.value.includes('T') ? input.value.split('T')[1] : '09:00';
  function element(tag, text, cls) {
    const node = document.createElement(tag);
    if (text) node.textContent = text;
    if (cls) node.className = cls;
    return node;
  }
  function button(text, action) {
    const node = element('button', text, 'button');
    node.type = 'button';
    node.addEventListener('click', () => safely(action));
    return node;
  }
  const dialog = element('dialog', '', 'ui-calendar');
  dialog.id = 'ui-calendar';
  dialog.setAttribute('aria-labelledby', 'ui-calendar-title');
  dialog.setAttribute('aria-describedby', 'ui-calendar-instruction');
  const title = element('h2', tr('Choose dates'));
  title.id = 'ui-calendar-title';
  const instruction = element('p', '', 'ui-calendar-instruction');
  instruction.id = 'ui-calendar-instruction';
  const heading = element('div', '', 'ui-calendar-heading');
  heading.append(title, instruction);
  const dismiss = button('×', () => dialog.close());
  dismiss.classList.add('ui-calendar-icon', 'ui-calendar-dismiss');
  dismiss.setAttribute('aria-label', tr('Close'));
  const head = element('div', '', 'ui-calendar-head');
  head.append(heading, dismiss);
  // Start and end cards: the date (press to pick it) with its time underneath.
  const stages = element('div', '', 'ui-calendar-stages');
  const startStage = button(tr('Start date'), () => setStage(0));
  const endStage = button(tr('End date'), () => setStage(1));
  const ends = [startStage, endStage].map(stage => {
    const card = element('div', '', 'ui-calendar-end');
    stage.classList.add('ui-calendar-end-date');
    card.append(stage);
    return card;
  });
  stages.append(...ends);
  const nav = element('div', '', 'ui-calendar-nav');
  const prev = button('‹', () => moveMonth(-1));
  prev.classList.add('ui-calendar-icon');
  prev.setAttribute('aria-label', tr('Previous month'));
  const next = button('›', () => moveMonth(1));
  next.classList.add('ui-calendar-icon');
  next.setAttribute('aria-label', tr('Next month'));
  const month = element('select'); month.dataset.plain = ''; month.setAttribute('aria-label', tr('Month'));
  for (let i = 0; i < 12; i++) {
    const option = element('option', new Intl.DateTimeFormat(locale, {month: 'long'}).format(new Date(2020, i, 1)));
    option.value = String(i); month.append(option);
  }
  month.addEventListener('change', () => { state.month = Number(month.value); render(); });
  const year = element('input'); year.type = 'number'; year.setAttribute('aria-label', tr('Year')); year.min = '1'; year.max = '9999';
  year.inputMode = 'numeric';
  year.addEventListener('change', () => {
    const value = Number(year.value);
    if (Number.isInteger(value) && value >= 1 && value <= 9999) { state.year = value; render(); }
    else year.reportValidity();
  });
  const period = element('div', '', 'ui-calendar-period');
  period.append(month, year);
  nav.append(prev, period, next);
  const grid = element('table', '', 'ui-calendar-grid'); grid.setAttribute('role', 'grid');
  const presets = element('div', '', 'ui-calendar-presets');
  presets.setAttribute('role', 'group'); presets.setAttribute('aria-label', tr('Quick choices'));
  const times = element('div', '', 'ui-calendar-times');
  const summary = element('p', '', 'ui-calendar-summary'); summary.setAttribute('role', 'status');
  const error = element('p', '', 'ui-error ui-calendar-error'); error.setAttribute('role', 'alert');
  function safely(action) {
    try { return action(); }
    catch (failure) {
      failed = true;
      console.error('Shared calendar failed; native date inputs remain available', failure?.name || 'Error');
      document.querySelectorAll('.ui-date-input').forEach(input => input.classList.remove('ui-date-input'));
      if (dialog.open) dialog.close();
      const feedback = element('p', tr('The calendar is unavailable. You can still type dates or use your browser calendar.'), 'flash error');
      feedback.setAttribute('role', 'alert');
      (document.querySelector('main') || document.body).prepend(feedback);
    }
  }
  const footer = element('div', '', 'ui-calendar-footer');
  const clear = button(tr('Clear dates'), () => { state.dates = state.fields.map(() => ''); state.stage = 0; render(); });
  clear.classList.add('ui-calendar-clear');
  const close = button(tr('Cancel'), () => dialog.close());
  const apply = button(tr('Apply dates'), commit); apply.classList.add('ui-calendar-apply');
  const actions = element('div', '', 'ui-calendar-actions');
  actions.append(close, apply);
  footer.append(clear, actions);
  dialog.append(head, stages, nav, grid, presets, times, summary, error, footer);
  document.body.append(dialog);
  dialog.addEventListener('close', () => {
    if (state) {
      state.trigger?.setAttribute('aria-expanded', 'false');
      if (state.opener?.isConnected) state.opener.focus();
    }
  });
  // Clicking the backdrop (outside the panel) closes without changes.
  dialog.addEventListener('click', event => { if (event.target === dialog) dialog.close(); });
  function currentDate(day = 1) {
    const date = new Date(2000, state.month, day, 12); date.setFullYear(state.year); return date;
  }
  function inBounds(value, input) {
    const min = input.min.slice(0, 10), max = input.max.slice(0, 10);
    return (!min || value >= min) && (!max || value <= max);
  }
  function formatted(value) {
    const date = dateOf(value);
    return date ? new Intl.DateTimeFormat(locale, {year: 'numeric', month: 'short', day: 'numeric'}).format(date) : tr('Not selected');
  }
  function setStage(stage) {
    state.stage = stage;
    const date = dateOf(state.dates[stage]);
    if (date) { state.month = date.getMonth(); state.year = date.getFullYear(); }
    render();
  }
  function moveMonth(delta) {
    const date = currentDate(); date.setMonth(date.getMonth() + delta);
    if (date.getFullYear() < 1 || date.getFullYear() > 9999) return;
    state.month = date.getMonth(); state.year = date.getFullYear(); render();
  }
  function choose(value) {
    if (!inBounds(value, state.fields[state.stage])) return;
    error.textContent = '';
    if (state.fields.length === 1) state.dates[0] = value;
    else if (state.stage === 0) { state.dates = [value, '']; state.stage = 1; }
    else {
      state.dates[1] = value;
      if (state.dates[0] && state.dates[1] < state.dates[0]) state.dates.reverse();
    }
    render(value);
    if (state.fields.length === 1 || state.dates.every(Boolean)) apply.focus();
  }
  function days(from, to) {
    const a = dateOf(from), b = dateOf(to);
    return a && b ? Math.round((b - a) / 86400000) + 1 : 0;
  }
  function shift(value, count) {
    const date = dateOf(value); date.setDate(date.getDate() + count); return iso(date);
  }
  function preset(label, values) {
    const node = button(label, () => {
      state.dates = values.slice(); state.stage = values.length - 1;
      const date = dateOf(values[0]); state.month = date.getMonth(); state.year = date.getFullYear();
      error.textContent = ''; render(); apply.focus();
    });
    node.classList.add('ui-calendar-chip');
    node.disabled = values.some((value, i) => !inBounds(value, state.fields[i]));
    return node;
  }
  function render(focusDate) {
    month.value = String(state.month); year.value = String(state.year);
    prev.disabled = state.year === 1 && state.month === 0;
    next.disabled = state.year === 9999 && state.month === 11;
    const range = state.fields.length === 2;
    dialog.classList.toggle('is-range', range);
    title.textContent = range ? tr('Choose date window') : tr('Choose date');
    stages.hidden = !range;
    instruction.textContent = range ? (state.stage === 0 ? tr('Select the start date, then select the end date in this calendar.') : tr('Select the end date. Use Apply dates to confirm.')) : tr('Select a date, then use Apply dates to confirm.');
    [startStage, endStage].forEach((node, i) => {
      node.setAttribute('aria-pressed', String(state.stage === i));
      ends[i].classList.toggle('is-active', state.stage === i);
      node.setAttribute('aria-label', `${i ? tr('End date') : tr('Start date')}: ${formatted(state.dates[i])}`);
      node.replaceChildren(element('span', i ? tr('End') : tr('Start'), 'ui-calendar-end-label'),
        element('span', state.dates[i] ? formatted(state.dates[i]) : tr('Not selected'), 'ui-calendar-end-value'));
    });
    grid.replaceChildren();
    const caption = new Intl.DateTimeFormat(locale, {month: 'long', year: 'numeric'}).format(currentDate());
    grid.setAttribute('aria-label', caption);
    const thead = element('thead'), headings = element('tr');
    for (let i = 0; i < 7; i++) {
      const date = new Date(2024, 0, i + 1);
      const th = element('th', new Intl.DateTimeFormat(locale, {weekday: 'narrow'}).format(date));
      th.scope = 'col'; th.title = new Intl.DateTimeFormat(locale, {weekday: 'long'}).format(date);
      th.setAttribute('abbr', th.title); headings.append(th);
    }
    thead.append(headings); grid.append(thead);
    const tbody = element('tbody');
    const offset = (currentDate().getDay() + 6) % 7;
    const count = new Date(state.year, state.month + 1, 0).getDate();
    const today = iso(new Date());
    const [from, to] = state.dates;
    let first = null;
    const weeks = Math.ceil((offset + count) / 7);
    for (let week = 0; week < weeks; week++) {
      const row = element('tr');
      for (let dow = 0; dow < 7; dow++) {
        const cell = element('td');
        const number = week * 7 + dow - offset + 1;
        if (number > 0 && number <= count) {
          const value = iso(currentDate(number));
          const day = button(String(number), () => choose(value));
          day.dataset.calendarDate = value;
          day.className = 'ui-calendar-day';
          day.setAttribute('aria-label', new Intl.DateTimeFormat(locale, {dateStyle: 'full'}).format(currentDate(number)));
          day.disabled = !inBounds(value, state.fields[state.stage]);
          day.tabIndex = -1;
          if (!day.disabled && !first) first = day;
          const selected = state.dates.includes(value);
          const between = range && from && to && value > from && value < to;
          cell.setAttribute('aria-selected', String(Boolean(selected || between)));
          if (selected) day.classList.add('selected');
          if (between) cell.classList.add('in-range');
          if (range && from && to && from !== to) {
            if (value === from) cell.classList.add('range-start');
            if (value === to) cell.classList.add('range-end');
          }
          if (dow > 4) cell.classList.add('weekend');
          if (value === today) day.setAttribute('aria-current', 'date');
          cell.append(day);
        }
        row.append(cell);
      }
      tbody.append(row);
    }
    grid.append(tbody);
    const preferred = focusDate || state.dates[state.stage] || (today.startsWith(`${pad(state.year)}-${pad(state.month + 1)}`) ? today : '');
    const active = [...grid.querySelectorAll('button')].find(node => node.dataset.calendarDate === preferred && !node.disabled) || first;
    if (active) { active.tabIndex = 0; if (focusDate) active.focus(); }
    presets.replaceChildren(...(range
      ? [preset(tr('Today'), [today, today]), preset(tr('Tomorrow'), [shift(today, 1), shift(today, 1)]),
         preset(tr('Next 7 days'), [today, shift(today, 6)]), preset(tr('Next 30 days'), [today, shift(today, 29)])]
      : [preset(tr('Today'), [today]), preset(tr('Tomorrow'), [shift(today, 1)]), preset(tr('In a week'), [shift(today, 7)])]));
    times.replaceChildren();
    ends.forEach(card => card.querySelector('.ui-calendar-time')?.remove());
    state.fields.forEach((input, index) => {
      if (input.type !== 'datetime-local') return;
      const label = element('label', range ? (index === 0 ? tr('Start time') : tr('End time')) : tr('Time'), 'ui-calendar-time');
      const time = element('input'); time.type = 'time'; time.value = state.times[index];
      time.step = input.step || '60'; time.required = true;
      time.addEventListener('input', () => { state.times[index] = time.value; });
      label.append(time);
      if (range) ends[index].append(label); else times.append(label);
    });
    times.hidden = !times.children.length;
    if (range && from && to) {
      const length = days(from, to);
      summary.textContent = `${formatted(from)} → ${formatted(to)} · ${length === 1 ? tr('1 day') : tr('{count} days', {count: length})}`;
    } else {
      summary.textContent = state.dates.map(formatted).join(' → ');
    }
  }
  // While picking the end date, preview the window under the pointer.
  grid.addEventListener('pointerover', event => {
    const target = event.target.closest('[data-calendar-date]');
    grid.querySelectorAll('.preview').forEach(cell => cell.classList.remove('preview'));
    if (!target || !state || state.fields.length !== 2 || state.stage !== 1 || !state.dates[0] || state.dates[1]) return;
    const [low, high] = [state.dates[0], target.dataset.calendarDate].sort();
    grid.querySelectorAll('[data-calendar-date]').forEach(day => {
      if (day.dataset.calendarDate > low && day.dataset.calendarDate < high) day.parentElement.classList.add('preview');
    });
  });
  grid.addEventListener('pointerleave', () => grid.querySelectorAll('.preview').forEach(cell => cell.classList.remove('preview')));
  grid.addEventListener('keydown', event => {
    const target = event.target.closest('[data-calendar-date]');
    if (!target) return;
    const date = dateOf(target.dataset.calendarDate);
    const jumps = {ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7, Home: -((date.getDay() + 6) % 7), End: 6 - ((date.getDay() + 6) % 7)};
    if (event.key in jumps) date.setDate(date.getDate() + jumps[event.key]);
    else if (event.key === 'PageUp' || event.key === 'PageDown') {
      const direction = event.key === 'PageUp' ? -1 : 1;
      // Clamp month/year jumps at the destination's last day (Jan 31 → Feb 28/29).
      const day = date.getDate(); date.setDate(1);
      if (event.shiftKey) date.setFullYear(date.getFullYear() + direction); else date.setMonth(date.getMonth() + direction);
      const last = new Date(date); last.setMonth(last.getMonth() + 1, 0);
      date.setDate(Math.min(day, last.getDate()));
    } else return;
    event.preventDefault();
    const value = iso(date);
    if (date.getFullYear() < 1 || date.getFullYear() > 9999 || !inBounds(value, state.fields[state.stage])) return;
    state.month = date.getMonth(); state.year = date.getFullYear(); render(value);
  });
  function commit() {
    error.textContent = '';
    const fields = state.fields;
    const clearing = state.dates.every(value => !value);
    if (clearing && fields.some(input => input.required)) { error.textContent = tr('These dates are required.'); return; }
    if (!clearing && state.dates.some(value => !dateOf(value))) { error.textContent = tr('Select both the start and end dates.'); return; }
    const values = state.dates.map((value, i) => value && fields[i].type === 'datetime-local' ? `${value}T${state.times[i]}` : value);
    if (fields.length === 2 && values[0] && values[1] && values[1] < values[0]) { error.textContent = tr('The end must be on or after the start.'); return; }
    const previous = fields.map(input => input.value);
    fields.forEach((input, i) => { input.value = values[i]; });
    const invalid = fields.find(input => !input.validity.valid || (input.value && input.type === 'datetime-local' && !state.times[fields.indexOf(input)]));
    if (invalid) {
      const message = invalid.validationMessage || tr('Choose a valid date and time within the allowed window.');
      fields.forEach((input, i) => { input.value = previous[i]; });
      error.textContent = message; return;
    }
    fields.forEach(input => { input.dispatchEvent(new Event('input', {bubbles: true})); input.dispatchEvent(new Event('change', {bubbles: true})); });
    state.refresh(); dialog.close();
  }
  function open(fields, trigger, refresh, opener) {
    if (dialog.open || fields.some(input => input.disabled || input.readOnly)) return;
    const anchor = dateOf(dayValue(fields[0])) || dateOf(fields[0].min.slice(0, 10)) || new Date();
    state = {fields, trigger, refresh, opener, dates: fields.map(dayValue), times: fields.map(timeValue), stage: 0, year: anchor.getFullYear(), month: anchor.getMonth()};
    error.textContent = ''; render();
    trigger?.setAttribute('aria-expanded', 'true');
    dialog.showModal();
    (grid.querySelector('button[tabindex="0"]') || close).focus();
  }
  function enhance(input) {
    if (failed || input.dataset.calendarReady || input.disabled || input.readOnly) return;
    const form = input.form || input.closest('main') || document;
    let fields = [input];
    for (const [start, end] of pairs) {
      if (input.name !== start && input.name !== end) continue;
      const a = [...form.querySelectorAll(selector)].filter(node => node.name === start);
      const b = [...form.querySelectorAll(selector)].filter(node => node.name === end);
      if (a.length === 1 && b.length === 1 && !a[0].disabled && !b[0].disabled && !a[0].readOnly && !b[0].readOnly) { fields = [a[0], b[0]]; break; }
    }
    if (fields.some(node => node.dataset.calendarReady)) return;
    // The start and end fields show the window themselves; either one opens the
    // range picker, so no separate summary button repeats the same dates.
    const trigger = null;
    const refresh = () => {};
    fields.forEach(field => {
      field.dataset.calendarReady = String(++serial);
      field.classList.add('ui-date-input');
      field.setAttribute('aria-haspopup', 'dialog'); field.setAttribute('aria-controls', dialog.id);
      field.addEventListener('click', event => { if (failed) return; event.preventDefault(); safely(() => open(fields, trigger, refresh, field)); });
      field.addEventListener('keydown', event => { if (!failed && (event.key === 'F4' || (event.altKey && event.key === 'ArrowDown'))) { event.preventDefault(); safely(() => open(fields, trigger, refresh, field)); } });
      field.addEventListener('change', refresh);
    });
  }
  function scan(root) {
    if (root.nodeType !== Node.ELEMENT_NODE && root !== document) return;
    if (root.matches?.(selector)) enhance(root);
    root.querySelectorAll(selector).forEach(enhance);
  }
  safely(() => scan(document));
  new MutationObserver(records => records.forEach(record => record.addedNodes.forEach(node => { if (!failed && !dialog.contains(node)) safely(() => scan(node)); }))).observe(document.querySelector('main') || document.body, {childList: true, subtree: true});
}());
