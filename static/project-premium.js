/* Project planning interactions. Mutations use the existing CSRF/session boundary. */
(function () {
  'use strict';
  const tr = window.ServiceOpsI18n?.tr || (value => value);
  function report(element, error) {
    console.error('Project workspace interaction failed', error?.name || 'Error');
    if (element) element.textContent = error?.message || tr('The operation could not be completed. Reload and try again.');
  }
  async function post(url, data) {
    const response = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json', Accept: 'application/json', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || ''}, body: JSON.stringify(data)});
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || tr('The operation could not be completed. Reload and try again.'));
    return body;
  }
  try {
    const board = document.querySelector('[data-program-board]');
    const feedback = document.querySelector('[data-program-feedback]');
    let source = null, saving = false;
    board?.addEventListener('dragstart', event => {
      try {
        const card = event.target.closest('[data-program-card][draggable=true]');
        if (!card || saving) { event.preventDefault(); return; }
        source = Number(card.dataset.programCard);
        event.dataTransfer.setData('text/plain', String(source));
        event.dataTransfer.effectAllowed = 'move';
      } catch (error) { report(feedback, error); }
    });
    const clear = () => board?.querySelectorAll('.program-drop-target').forEach(cell => cell.classList.remove('program-drop-target'));
    board?.addEventListener('dragover', event => {
      try { const cell = event.target.closest('[data-program-drop]'); if (source && cell) { event.preventDefault(); clear(); cell.classList.add('program-drop-target'); } }
      catch (error) { report(feedback, error); }
    });
    board?.addEventListener('dragend', () => { source = null; clear(); });
    board?.addEventListener('drop', async event => {
      try {
        const cell = event.target.closest('[data-program-drop]');
        if (!source || !cell || saving) return;
        event.preventDefault(); clear(); saving = true;
        const item = source; source = null;
        await post(board.dataset.programUrl, {revision: Number(board.dataset.programRevision), item_id: item, team_id: cell.dataset.team ? Number(cell.dataset.team) : null, iteration: cell.dataset.iteration ? Number(cell.dataset.iteration) : cell.dataset.iteration === '0' ? 0 : null});
        location.reload();
      } catch (error) { saving = false; report(feedback, error); }
    });
    document.querySelector('[data-program-search]')?.addEventListener('input', event => {
      try { const q = event.target.value.toLocaleLowerCase(); board?.querySelectorAll('[data-program-card]').forEach(card => { card.hidden = !card.textContent.toLocaleLowerCase().includes(q); }); }
      catch (error) { report(feedback, error); }
    });
    document.querySelectorAll('[data-preserve-scroll]').forEach((region, index) => {
      try {
        const key = 'serviceops-project-scroll:' + location.pathname + ':' + index;
        const saved = JSON.parse(sessionStorage.getItem(key) || 'null');
        if (saved) { region.scrollLeft = saved.left; region.scrollTop = saved.top; }
        region.addEventListener('scroll', () => {
          try { sessionStorage.setItem(key, JSON.stringify({left: region.scrollLeft, top: region.scrollTop})); }
          catch (error) { console.error('Project scroll state could not be saved', error?.name); }
        }, {passive: true});
      } catch (error) { report(feedback, error); }
    });
  } catch (error) { report(document.querySelector('[data-program-feedback]'), error); }

  try {
    const rows = Array.from(document.querySelectorAll('[data-structure-node]'));
    const byId = new Map(rows.map(row => [row.dataset.structureNode, row]));
    const collapsed = new Set();
    let query = '';
    function update() {
      try {
        const keep = new Set();
        if (query) for (const row of rows) if (row.textContent.toLocaleLowerCase().includes(query)) {
          let cursor = row;
          const seen = new Set();
          while (cursor && !seen.has(cursor.dataset.structureNode)) { seen.add(cursor.dataset.structureNode); keep.add(cursor.dataset.structureNode); cursor = byId.get(cursor.dataset.structureParent); }
        }
        for (const row of rows) {
          let parent = row.dataset.structureParent, hide = Boolean(query && !keep.has(row.dataset.structureNode));
          const seen = new Set();
          while (parent && byId.has(parent)) {
            if (seen.has(parent)) throw new Error('InvalidHierarchy');
            seen.add(parent);
            if (!query && collapsed.has(parent)) hide = true;
            parent = byId.get(parent).dataset.structureParent;
          }
          row.hidden = hide;
          const toggle = row.querySelector('[data-structure-toggle]');
          if (toggle) { toggle.hidden = !rows.some(other => other.dataset.structureParent === row.dataset.structureNode); toggle.setAttribute('aria-expanded', String(!collapsed.has(row.dataset.structureNode))); toggle.textContent = collapsed.has(row.dataset.structureNode) ? '▸' : '▾'; }
        }
      } catch (error) { report(document.querySelector('[data-program-feedback]'), error); }
    }
    rows.forEach(row => row.querySelector('[data-structure-toggle]')?.addEventListener('click', () => {
      if (collapsed.has(row.dataset.structureNode)) collapsed.delete(row.dataset.structureNode); else collapsed.add(row.dataset.structureNode);
      update();
    }));
    document.querySelector('[data-structure-search]')?.addEventListener('input', event => { query = event.target.value.toLocaleLowerCase(); update(); });
    document.querySelector('[data-structure-expand]')?.addEventListener('click', () => { collapsed.clear(); update(); });
    document.querySelector('[data-structure-collapse]')?.addEventListener('click', () => { rows.forEach(row => collapsed.add(row.dataset.structureNode)); update(); });
    update();
  } catch (error) { report(null, error); }

  try {
    const canvas = document.querySelector('[data-plan-canvas]');
    document.querySelectorAll('[data-plan-field]').forEach(input => {
      input.addEventListener('change', () => {
        try {
          const field = input.dataset.planField;
          canvas?.classList.toggle('hide-' + field, !input.checked);
          document.querySelectorAll('[data-plan-column="' + field + '"]').forEach(element => { element.hidden = !input.checked; });
          window.dispatchEvent(new Event('resize'));
        } catch (error) { report(document.querySelector('[data-plan-feedback]'), error); }
      });
    });
  } catch (error) { report(document.querySelector('[data-plan-feedback]'), error); }

  document.querySelectorAll('[data-rule-builder]').forEach(form => {
    const feedback = form.querySelector('[data-rule-feedback]');
    try {
      const raw = form.querySelector('textarea[name=config]');
      let config = JSON.parse(raw.value), selected = {kind: 'trigger', index: 0}, rawEdited = false;
      const steps = form.querySelector('[data-rule-steps]'), detail = form.querySelector('[data-rule-detail]');
      const labels = {item_type: tr('Issue Type'), category: tr('Status'), priority: tr('Priority'), flagged: tr('Flagged'), title: tr('Summary')};
      const fields = Object.entries(labels);
      const triggers = [['created', tr('Issue created')], ['updated', tr('Issue updated')], ['transitioned', tr('Issue transitioned')]];
      const branches = [['trigger', tr('Trigger issue')], ['children', tr('Direct children')], ['descendants', tr('Stories and all descendants')], ['parent', tr('Parent issue')], ['linked', tr('Linked work')]];
      const categories = [['todo', tr('To do')], ['in_progress', tr('In progress')], ['done', tr('Done')]];
      const priorities = [['highest', tr('Highest')], ['high', tr('High')], ['medium', tr('Medium')], ['low', tr('Low')], ['lowest', tr('Lowest')]];
      function element(tag, text, className) { const node = document.createElement(tag); if (text) node.textContent = text; if (className) node.className = className; return node; }
      function write(renderAgain = false) { rawEdited = false; raw.value = JSON.stringify(config, null, 2); if (renderAgain) render(); }
      function choose(label, options, value, update) {
        const wrapper = element('label', label), select = element('select'); select.dataset.plain = ''; select.setAttribute('aria-label', label);
        options.forEach(([key, caption]) => { const option = element('option', caption); option.value = key; option.selected = String(value) === key; select.appendChild(option); });
        select.addEventListener('change', () => { try { update(select.value); write(true); } catch (error) { report(feedback, error); } });
        wrapper.appendChild(select); detail.querySelector('.rule-config-fields').appendChild(wrapper); return select;
      }
      function input(label, value, update, multiline = false) {
        const wrapper = element('label', label), field = element(multiline ? 'textarea' : 'input'); field.value = value ?? ''; field.setAttribute('aria-label', label); field.maxLength = multiline ? 4000 : 255;
        field.addEventListener('input', () => { try { update(field.value); write(false); } catch (error) { report(feedback, error); } });
        wrapper.appendChild(field); detail.querySelector('.rule-config-fields').appendChild(wrapper);
      }
      function remove(list, index) {
        const button = element('button', tr('Remove component'), 'danger'); button.type = 'button';
        button.addEventListener('click', () => { try { list.splice(index, 1); selected = {kind: 'trigger', index: 0}; write(true); } catch (error) { report(feedback, error); } });
        detail.appendChild(button);
      }
      function step(kind, index, title, subtitle, icon, nested = false) {
        const button = element('button', '', 'rule-step' + (selected.kind === kind && selected.index === index ? ' active' : '') + (nested ? ' branch-step' : ''));
        button.type = 'button'; button.setAttribute('aria-pressed', String(selected.kind === kind && selected.index === index));
        const badge = element('span', icon, 'rule-step-icon' + (kind === 'trigger' ? ' trigger-icon' : kind === 'branch' ? ' branch-icon' : '')); badge.setAttribute('aria-hidden', 'true');
        const body = element('span', title); body.appendChild(element('small', subtitle)); button.append(badge, body);
        button.addEventListener('click', () => { try { selected = {kind, index}; render(); } catch (error) { report(feedback, error); } }); steps.appendChild(button);
      }
      function renderCondition(list, index) {
        const condition = list[index];
        choose(tr('Field'), fields, condition.field, value => { condition.field = value; condition.value = value === 'item_type' ? 'epic' : value === 'category' ? 'done' : value === 'flagged' ? 'true' : value === 'priority' ? 'medium' : ''; });
        choose(tr('Condition'), [['eq', tr('equals')], ['ne', tr('does not equal')], ['contains', tr('contains')]], condition.operator, value => { condition.operator = value; });
        choose(tr('Compare against'), [['value', tr('Value')], ['field', tr('Trigger field')]], condition.compare_field ? 'field' : 'value', value => {
          if (value === 'field') { condition.compare_field = condition.field; delete condition.value; } else { delete condition.compare_field; condition.value = ''; }
        });
        if (condition.compare_field) choose(tr('Trigger field'), fields, condition.compare_field, value => { condition.compare_field = value; });
        else if (condition.field === 'item_type') choose(tr('Value'), [['epic', tr('Epic')], ['story', tr('Story')], ['task', tr('Task')], ['bug', tr('Bug')], ['subtask', tr('Subtask')]], condition.value, value => { condition.value = value; });
        else if (condition.field === 'category') choose(tr('Value'), categories, condition.value, value => { condition.value = value; });
        else if (condition.field === 'priority') choose(tr('Value'), priorities, condition.value, value => { condition.value = value; });
        else if (condition.field === 'flagged') choose(tr('Value'), [['true', tr('Yes')], ['false', tr('No')]], String(condition.value), value => { condition.value = value; });
        else input(tr('Value'), condition.value, value => { condition.value = value; });
        remove(list, index);
      }
      function render() {
        steps.replaceChildren(); detail.replaceChildren();
        step('trigger', 0, tr('When:') + ' ' + triggers.find(([key]) => key === config.trigger)?.[1], '', '↪');
        config.conditions.forEach((c, i) => step('condition', i, labels[c.field] || c.field, c.operator + ' ' + (c.compare_field ? labels[c.compare_field] : String(c.value)), '⇄'));
        step('branch', 0, tr('For:') + ' ' + branches.find(([key]) => key === config.branch)?.[1], '', '♧');
        config.branch_conditions.forEach((c, i) => step('branch_condition', i, labels[c.field] || c.field, c.operator + ' ' + (c.compare_field ? labels[c.compare_field] : String(c.value)), '⇄', true));
        config.actions.forEach((a, i) => step('action', i, tr('Then:') + ' ' + (a.type === 'transition' ? tr('Transition the issue') : a.type === 'edit' ? tr('Edit issue') : tr('Add comment')), a.copy_trigger ? tr('Copy from trigger issue') : a.category || a.field || '', '↪', true));
        detail.appendChild(element('h3', selected.kind === 'trigger' ? tr('When an issue event occurs') : selected.kind === 'branch' ? tr('Branch over related work') : selected.kind === 'action' ? tr('Then perform an action') : tr('Issue fields condition')));
        detail.appendChild(element('div', '', 'rule-config-fields'));
        if (selected.kind === 'trigger') choose(tr('Trigger'), triggers, config.trigger, value => { config.trigger = value; });
        else if (selected.kind === 'branch') choose(tr('Related work'), branches, config.branch, value => { config.branch = value; });
        else if (selected.kind === 'condition') renderCondition(config.conditions, selected.index);
        else if (selected.kind === 'branch_condition') renderCondition(config.branch_conditions, selected.index);
        else {
          const action = config.actions[selected.index];
          choose(tr('Action'), [['transition', tr('Transition issue')], ['edit', tr('Edit issue')], ['comment', tr('Add comment')]], action.type, value => { config.actions[selected.index] = value === 'transition' ? {type: value, copy_trigger: true} : value === 'edit' ? {type: value, field: 'priority', value: 'medium'} : {type: value, body: ''}; });
          if (action.type === 'transition') {
            choose(tr('Destination status'), [['copy', tr('Copy from trigger issue')], ...categories], action.copy_trigger ? 'copy' : action.category, value => { if (value === 'copy') { action.copy_trigger = true; delete action.category; } else { delete action.copy_trigger; action.category = value; } });
          } else if (action.type === 'edit') {
            choose(tr('Field'), fields.filter(([key]) => ['priority', 'flagged', 'title'].includes(key)), action.field, value => { action.field = value; action.value = value === 'priority' ? 'medium' : value === 'flagged' ? false : ''; });
            if (action.field === 'priority') choose(tr('Value'), priorities, action.value, value => { action.value = value; });
            else if (action.field === 'flagged') choose(tr('Value'), [['true', tr('Yes')], ['false', tr('No')]], String(action.value), value => { action.value = value === 'true'; });
            else input(tr('Value'), action.value, value => { action.value = value; });
          } else input(tr('Comment'), action.body, value => { action.body = value; }, true);
          remove(config.actions, selected.index);
        }
      }
      form.querySelector('[data-rule-add]').addEventListener('click', () => {
        try {
          const kind = form.querySelector('[data-rule-new-component]').value;
          const list = kind === 'condition' ? config.conditions : kind === 'branch_condition' ? config.branch_conditions : config.actions;
          if (list.length >= (kind === 'action' ? 10 : 20)) throw new Error(tr('The component limit has been reached.'));
          list.push(kind === 'action' ? {type: 'transition', copy_trigger: true} : {field: 'category', operator: 'eq', value: 'done'});
          selected = {kind, index: list.length - 1}; write(true);
        } catch (error) { report(feedback, error); }
      });
      raw.addEventListener('input', () => { rawEdited = true; });
      form.addEventListener('submit', event => {
        try { if (!rawEdited) write(false); JSON.parse(raw.value); }
        catch (error) { event.preventDefault(); report(feedback, error); }
      });
      render();
    } catch (error) { report(feedback, error); }
  });
})();

(function () {
  'use strict';
  const tr = window.ServiceOpsI18n?.tr || (value => value);
  const canvas = document.querySelector('[data-plan-canvas]');
  const feedback = document.querySelector('[data-plan-feedback]');
  if (!canvas) return;
  try {
    const config = JSON.parse(document.querySelector('[data-plan-proposal]').textContent);
    const review = document.querySelector('[data-plan-review]'), reset = document.querySelector('[data-plan-reset]');
    const start = Date.parse(canvas.dataset.rangeStart + 'T00:00:00Z'), finish = Date.parse(canvas.dataset.rangeEnd + 'T00:00:00Z');
    const day = 86400000, totalDays = Math.round((finish - start) / day) + 1;
    const pending = new Map(), original = new Map();
    let dragging = null, suppressUntil = 0, reviewing = false;
    const style = document.createElement('style'); style.nonce = document.querySelector('style[nonce]')?.nonce || ''; document.head.appendChild(style);
    const iso = value => new Date(value).toISOString().slice(0, 10);
    function fail(error) { console.error('Timeline proposal failed', error?.name || 'Error'); if (feedback) feedback.textContent = error?.message || tr('The date proposal could not be saved. Reload and try again.'); }
    function render() {
      try {
        const changes = new Map(pending);
        if (dragging?.candidate) changes.set(dragging.id, dragging.candidate);
        const rules = [];
        canvas.querySelectorAll('[data-plan-bar]').forEach(bar => {
          const id = bar.dataset.planBar, dates = changes.get(id);
          bar.classList.toggle('plan-bar-pending', Boolean(dates));
          if (dates) {
            const left = Math.max(0, Math.min(100, (dates.start - start) / day / totalDays * 100));
            const width = Math.max(.5, Math.min(100 - left, (dates.due - Math.max(start, dates.start) + day) / day / totalDays * 100));
            rules.push('.plan-bar-' + Number(id) + '{left:' + left + '%;width:' + width + '%}');
          }
        });
        style.textContent = rules.join('\n');
        review.hidden = pending.size === 0; reset.hidden = pending.size === 0;
        if (pending.size) review.textContent = tr('Review changes') + ' (' + pending.size + ')';
        window.dispatchEvent(new Event('resize'));
      } catch (error) { fail(error); }
    }
    canvas.addEventListener('pointerdown', event => {
      try {
        const bar = event.target.closest('[data-plan-bar][data-plan-editable=true]');
        if (!bar || event.button !== 0) return;
        const id = bar.dataset.planBar;
        const dates = pending.get(id) || {start: Date.parse(bar.dataset.planStart + 'T00:00:00Z'), due: Date.parse(bar.dataset.planDue + 'T00:00:00Z')};
        if (!Number.isFinite(dates.start) || !Number.isFinite(dates.due)) return;
        dragging = {id, bar, x: event.clientX, dates, mode: event.target.closest('[data-plan-resize]')?.dataset.planResize || 'move', pointer: event.pointerId};
        original.set(id, dates); bar.setPointerCapture(event.pointerId);
      } catch (error) { fail(error); }
    });
    canvas.addEventListener('pointermove', event => {
      try {
        if (!dragging || event.pointerId !== dragging.pointer || Math.abs(event.clientX - dragging.x) < 5) return;
        event.preventDefault();
        const width = dragging.bar.closest('[data-plan-track]').getBoundingClientRect().width;
        const delta = Math.round((event.clientX - dragging.x) / width * totalDays) * day;
        const dates = {...dragging.dates};
        if (dragging.mode !== 'due') dates.start += delta;
        if (dragging.mode !== 'start') dates.due += delta;
        if (dates.start > dates.due) { if (dragging.mode === 'start') dates.start = dates.due; else dates.due = dates.start; }
        if (iso(dates.start) < '1900-01-01' || iso(dates.due) > '2200-12-31') throw new Error(tr('Choose dates between 1900 and 2200.'));
        dragging.candidate = dates;
        if (feedback) feedback.textContent = iso(dates.start) + ' → ' + iso(dates.due) + ' · ' + tr('Proposal only. Review changes before applying.');
        render();
      } catch (error) { fail(error); }
    });
    canvas.addEventListener('pointerup', event => {
      try {
        if (!dragging || event.pointerId !== dragging.pointer) return;
        if (dragging.candidate) { pending.set(dragging.id, dragging.candidate); suppressUntil = Date.now() + 500; }
        const current = dragging; dragging = null; current.bar.releasePointerCapture(event.pointerId); render();
      } catch (error) { fail(error); }
    });
    canvas.addEventListener('pointercancel', () => { dragging = null; render(); });
    canvas.addEventListener('click', event => { if (Date.now() < suppressUntil && event.target.closest('[data-plan-bar]')) { event.preventDefault(); event.stopPropagation(); } }, true);
    reset?.addEventListener('click', () => { pending.clear(); dragging = null; render(); if (feedback) feedback.textContent = tr('Local date proposals discarded.'); });
    review?.addEventListener('click', async () => {
      try {
        review.disabled = true;
        const changes = Object.fromEntries(Array.from(pending, ([id, dates]) => [id, {start: iso(dates.start), due: iso(dates.due)}]));
        const response = await fetch(config.url, {method: 'POST', headers: {'Content-Type': 'application/json', Accept: 'application/json', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || ''}, body: JSON.stringify({name: tr('Timeline changes'), mode: 'manual', projects: config.projects, changes})});
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || tr('The date proposal could not be saved. Reload and try again.'));
        reviewing = true; location.assign(result.review_url);
      } catch (error) { review.disabled = false; fail(error); }
    });
    window.addEventListener('beforeunload', event => { if (pending.size && !reviewing) { event.preventDefault(); event.returnValue = ''; } });
  } catch (error) { console.error('Timeline proposal controls failed', error?.name || 'Error'); if (feedback) feedback.textContent = tr('Date dragging is unavailable. Use the date fields to create a proposal.'); }
})();

// Typed intake editor keeps a JSON fallback for keyboard-only and no-script use.
document.querySelectorAll('[data-intake-editor]').forEach(form => {
  const tr=window.ServiceOpsI18n?.tr || (value=>value);
  try {
    const raw=form.querySelector('[data-intake-json]'), controls=form.querySelector('[data-intake-controls]');
    const config=JSON.parse(raw.value), list=form.querySelector('[data-intake-fields]');
    const type=form.querySelector('[data-intake-type]'), priority=form.querySelector('[data-intake-priority]');
    type.value=config.item_type;priority.value=config.priority;
    function sync(){config.item_type=type.value;config.priority=priority.value;raw.value=JSON.stringify(config,null,2);}
    function render(){
      list.replaceChildren();config.fields.forEach((field,index)=>{
        const box=document.createElement('fieldset'), legend=document.createElement('legend');legend.textContent=tr('Field')+' '+(index+1);box.append(legend);
        const input=(label,value,handler,kind='text')=>{
          const wrapper=document.createElement('label'), control=document.createElement('input');wrapper.textContent=label;control.type=kind;
          if(kind==='checkbox')control.checked=value;else control.value=value;
          control.addEventListener('input',()=>{handler(kind==='checkbox'?control.checked:control.value);sync();});wrapper.append(control);box.append(wrapper);return control;
        };
        input(tr('Label'),field.label,v=>field.label=v).maxLength=120;
        input(tr('Key'),field.key,v=>field.key=v).maxLength=40;
        const label=document.createElement('label'), select=document.createElement('select');label.textContent=tr('Type');select.dataset.plain='';
        ['text','paragraph','integer','number','date','choice','multi_choice','boolean'].forEach(kind=>{const option=document.createElement('option');option.value=kind;option.textContent=kind;select.append(option);});
        select.value=field.type;select.addEventListener('change',()=>{field.type=select.value;if(!['choice','multi_choice'].includes(field.type))field.choices=[];render();sync();});label.append(select);box.append(label);
        input(tr('Required'),field.required,v=>field.required=v,'checkbox');
        if(['choice','multi_choice'].includes(field.type))input(tr('Choices (comma separated)'),field.choices.join(', '),v=>field.choices=v.split(',').map(s=>s.trim()).filter(Boolean));
        const remove=document.createElement('button');remove.type='button';remove.textContent=tr('Remove field');remove.addEventListener('click',()=>{config.fields.splice(index,1);render();sync();});box.append(remove);list.append(box);
      });
    }
    form.querySelector('[data-intake-add]').addEventListener('click',()=>{if(config.fields.length>=30)return;let n=1;while(config.fields.some(f=>f.key==='field_'+n))n++;config.fields.push({key:'field_'+n,label:tr('New field'),type:'text',required:false,choices:[]});render();sync();});
    type.addEventListener('change',sync);priority.addEventListener('change',sync);
    raw.addEventListener('change',()=>{try {const parsed=JSON.parse(raw.value);if(!Array.isArray(parsed.fields))throw new Error('Invalid fields');Object.assign(config,parsed);type.value=config.item_type;priority.value=config.priority;render();raw.setCustomValidity('');}catch(error){console.error('Invalid intake configuration',error.name);raw.setCustomValidity(tr('Enter a valid form configuration.'));}});
    render();controls.hidden=false;
  }catch(error){console.error('Intake editor could not initialize',error.name);}
});
