/* Interface translations for scripts.
 *
 * The page embeds the current language's catalog as JSON in
 * <script type="application/json" id="serviceops-i18n"> (see base.html); the
 * English source text is the key and the fallback. tr() returns plain text, so
 * callers assign it with textContent, never innerHTML. */
(function () {
  "use strict";

  let catalog = {};
  try {
    const node = document.getElementById("serviceops-i18n");
    const parsed = node ? JSON.parse(node.textContent || "{}") : {};
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) catalog = parsed;
  } catch (error) {
    catalog = {};
  }

  const FIELD = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;
  const own = Object.prototype.hasOwnProperty;

  function fields(text) {
    const names = new Set();
    String(text).replace(FIELD, (match, name) => {
      names.add(name);
      return match;
    });
    return names;
  }

  function sameFields(left, right) {
    const a = fields(left);
    const b = fields(right);
    if (a.size !== b.size) return false;
    for (const name of a) if (!b.has(name)) return false;
    return true;
  }

  function tr(message, params) {
    let text = own.call(catalog, message) && typeof catalog[message] === "string" ? catalog[message] : message;
    if (text !== message && !sameFields(message, text)) text = message;
    if (!params) return text;
    return text.replace(FIELD, (match, name) => (own.call(params, name) ? String(params[name]) : match));
  }

  // Marks English text that arrives from the server (or is used as a lookup
  // key) for extraction into the catalog; it is translated where shown.
  function trNoop(message) {
    return message;
  }

  window.tr = tr;
  window.trNoop = trNoop;
  window.ServiceOpsI18n = Object.freeze({
    tr: tr,
    language: document.documentElement.getAttribute("lang") || "en",
    direction: document.documentElement.getAttribute("dir") || "ltr",
  });
})();
