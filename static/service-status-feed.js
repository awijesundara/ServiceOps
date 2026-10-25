/* Slim one-line rolling updates; the detail page is the complete no-JS fallback. */
(function () {
  'use strict';
  document.querySelectorAll('[data-service-feed]').forEach(function (feed) {
    try {
      const items = Array.from(feed.querySelectorAll('[data-service-feed-item]'));
      items.forEach(function (item) {
        const headline = item.querySelector('.service-headline');
        if (headline) headline.title = headline.textContent.trim();
      });
      if (items.length < 2) return;
      const position = feed.querySelector('[data-service-feed-position]');
      const announcement = feed.querySelector('[data-service-feed-announcement]');
      const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
      const accountReduced = document.body.classList.contains('reduced-motion');
      let userPaused = false;
      let hovered = false;
      let focused = false;
      let index = 0;
      let timer = null;
      const interval = parseFloat(getComputedStyle(feed).getPropertyValue('--notice-interval'));
      if (!Number.isFinite(interval) || interval < 4000) throw new Error('Invalid notice interval');
      function stop() {
        if (timer !== null) window.clearTimeout(timer);
        timer = null;
      }
      function schedule() {
        stop();
        if (!userPaused && !motion.matches && !accountReduced && !hovered && !focused && !document.hidden && items.length > 1) {
          timer = window.setTimeout(function () { show(index + 1, false); }, interval);
        }
      }
      function show(next, manual) {
        index = (next + items.length) % items.length;
        items.forEach(function (item) {
          item.hidden = true;
          item.classList.remove('service-feed-enter');
        });
        const item = items[index];
        item.hidden = false;
        if (!motion.matches && !accountReduced) {
          void item.offsetWidth;
          item.classList.add('service-feed-enter');
        }
        position.textContent = String(index + 1) + ' / ' + String(items.length);
        if (manual) announcement.textContent = item.textContent.trim();
        schedule();
      }
      feed.addEventListener('keydown', function (event) {
        if (event.target.closest('.service-headline') && event.key === ' ') {
          event.preventDefault();
          userPaused = !userPaused;
          announcement.textContent = userPaused ? tr('Updates paused') : tr('Updates resumed');
          schedule();
        }
        if (event.target.closest('.service-headline') && (event.key === 'ArrowRight' || event.key === 'ArrowLeft')) {
          event.preventDefault();
          const direction = event.key === 'ArrowRight' ? 1 : -1;
          show(index + direction, true);
          items[index].querySelector('.service-headline')?.focus();
        }
      });
      feed.addEventListener('mouseenter', function () { hovered = true; stop(); });
      feed.addEventListener('mouseleave', function () { hovered = false; schedule(); });
      feed.addEventListener('focusin', function () { focused = true; stop(); });
      feed.addEventListener('focusout', function (event) {
        if (!feed.contains(event.relatedTarget)) { focused = false; schedule(); }
      });
      document.addEventListener('visibilitychange', schedule);
      motion.addEventListener('change', function () {
        schedule();
      });
      window.addEventListener('pagehide', stop);
      window.addEventListener('pageshow', schedule);
      feed.setAttribute('data-service-feed-ready', '');
      show(index, false);
      schedule();
    } catch (error) {
      console.error('Unable to initialize service status feed', error);

    }
  });
}());
