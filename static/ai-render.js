/* Safe rendering of model output.
 *
 * Model text is untrusted. Nothing here ever uses innerHTML: every node is created
 * with createElement/textContent, so markup or script in an answer is displayed as
 * literal text. Only a small markdown subset is understood (headings, lists, bold,
 * italic, inline code, code fences, quotes) plus [S1]-style source citations, which
 * become links to the real record only when the server supplied that source. */
(function () {
  "use strict";

  const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+?\*\*)|(\*[^*\s][^*\n]*?\*)|(\[S\d+\])/g;

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function citation(id, sources) {
    const source = sources && sources[id];
    if (!source) return node("span", "ai-cite ai-cite-pending", id);
    const link = node("a", "ai-cite", id);
    link.href = source.url;
    link.title = source.title;
    return link;
  }

  function inline(parent, text, sources) {
    let last = 0;
    text.replace(INLINE, function (match, code, bold, italic, cite, offset) {
      if (offset > last) parent.appendChild(document.createTextNode(text.slice(last, offset)));
      if (code) parent.appendChild(node("code", "", code.slice(1, -1)));
      else if (bold) parent.appendChild(node("strong", "", bold.slice(2, -2)));
      else if (italic) parent.appendChild(node("em", "", italic.slice(1, -1)));
      else if (cite) parent.appendChild(citation(cite.slice(1, -1), sources));
      last = offset + match.length;
      return match;
    });
    if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
  }

  function render(text, sources) {
    const out = document.createDocumentFragment();
    const lines = String(text || "").replace(/\r\n?/g, "\n").split("\n");
    let paragraph = [];
    let list = null;
    let fence = null;

    const flushParagraph = function () {
      if (!paragraph.length) return;
      const block = node("p");
      inline(block, paragraph.join(" "), sources);
      out.appendChild(block);
      paragraph = [];
    };
    const flushList = function () { list = null; };

    lines.forEach(function (raw) {
      if (fence !== null) {
        if (/^\s*```/.test(raw)) { out.appendChild(fence); fence = null; return; }
        fence.firstChild.textContent += (fence.firstChild.textContent ? "\n" : "") + raw;
        return;
      }
      if (/^\s*```/.test(raw)) { flushParagraph(); flushList(); fence = node("pre", "ai-code"); fence.appendChild(node("code")); return; }
      const line = raw.trimEnd();
      if (!line.trim()) { flushParagraph(); flushList(); return; }
      let match = line.match(/^(#{1,4})\s+(.*)$/);
      if (match) {
        flushParagraph(); flushList();
        const heading = node("h" + Math.min(match[1].length + 2, 5), "ai-h");
        inline(heading, match[2], sources);
        out.appendChild(heading);
        return;
      }
      if (/^\s*([-*_])\1{2,}\s*$/.test(line)) { flushParagraph(); flushList(); out.appendChild(node("hr")); return; }
      match = line.match(/^\s*(?:([-*•])|(\d+)[.)])\s+(.*)$/);
      if (match) {
        flushParagraph();
        const ordered = Boolean(match[2]);
        if (!list || list.dataset.ordered !== String(ordered)) {
          list = node(ordered ? "ol" : "ul", "ai-list");
          list.dataset.ordered = String(ordered);
          out.appendChild(list);
        }
        const item = node("li");
        inline(item, match[3], sources);
        list.appendChild(item);
        return;
      }
      match = line.match(/^>\s?(.*)$/);
      if (match) {
        flushParagraph(); flushList();
        const quote = node("blockquote", "ai-quote");
        inline(quote, match[1], sources);
        out.appendChild(quote);
        return;
      }
      flushList();
      paragraph.push(line.trim());
    });
    flushParagraph();
    if (fence !== null) out.appendChild(fence); // an unfinished code block is shown as it streams
    return out;
  }

  function plainText(text) {
    return String(text || "").replace(/\[S\d+\]/g, "").replace(/[*`#>]/g, "").replace(/\n{3,}/g, "\n\n").trim();
  }

  window.AIRender = { render: render, plainText: plainText };
})();
