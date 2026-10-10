/* A theme preview changes this document only. The existing form owns persistence. */
(() => {
  'use strict';
  const workspace = document.querySelector('[data-theme-workspace]');
  if (!workspace) return;
  const choices = Array.from(workspace.querySelectorAll('input[name="theme"]'));
  const allowed = new Set((workspace.dataset.themes || '').split(','));
  const darkThemes = new Set((workspace.dataset.darkThemes || '').split(','));
  const saved = allowed.has(workspace.dataset.savedTheme) ? workspace.dataset.savedTheme : 'light';
  const status = workspace.querySelector('#theme-preview-status');
  const reset = workspace.querySelector('[data-theme-reset]');
  const darkSheet = document.getElementById('serviceops-dark-theme');
  const scheme = document.querySelector('meta[name="color-scheme"]');
  const media = window.matchMedia('(prefers-color-scheme: dark)');

  function apply(theme) {
    try {
      if (!allowed.has(theme) || !darkSheet || !status || !reset || !scheme) {
        throw new Error('Theme preview controls are unavailable');
      }
      for (const name of allowed) document.body.classList.remove(`theme-${name}`);
      document.body.classList.add(`theme-${theme}`);
      document.documentElement.classList.toggle('theme-dark', darkThemes.has(theme) || theme === 'system');
      darkSheet.media = darkThemes.has(theme) ? 'all' : theme === 'system' ? '(prefers-color-scheme: dark)' : 'not all';
      scheme.content = theme === 'system' ? 'light dark' : darkThemes.has(theme) ? 'dark' : 'light';
      const previewing = theme !== saved;
      const choice = choices.find(input => input.value === theme);
      if (choice) choice.checked = true;
      const label = choice?.closest('.theme-option')?.querySelector('[data-theme-label]')?.textContent || theme;
      status.textContent = previewing ? status.dataset.previewMessage.replace('{theme}', label) : status.dataset.savedMessage;
      reset.hidden = !previewing;
      workspace.classList.toggle('is-theme-previewing', previewing);
    } catch (error) {
      console.error('ServiceOps theme preview failed', error);
      if (status) status.textContent = window.tr?.('Theme preview is unavailable. Save preferences to apply your selection.') || 'Theme preview is unavailable. Save preferences to apply your selection.';
      if (reset) reset.hidden = false;
    }
  }

  try {
    workspace.addEventListener('change', event => {
      if (event.target.matches('input[name="theme"]')) apply(event.target.value);
    });
    reset?.addEventListener('click', () => apply(saved));
    workspace.addEventListener('reset', () => queueMicrotask(() => apply(saved)));
    // Avoid restoring an unsaved preview when the browser restores this page from its cache.
    window.addEventListener('pagehide', () => apply(saved));
    media.addEventListener('change', () => {
      const selected = choices.find(input => input.checked);
      if (selected?.value === 'system') apply('system');
    });
  } catch (error) {
    console.error('ServiceOps theme preview initialization failed', error);
    if (status) status.textContent = window.tr?.('Theme preview is unavailable. Save preferences to apply your selection.') || 'Theme preview is unavailable. Save preferences to apply your selection.';
  }
})();
