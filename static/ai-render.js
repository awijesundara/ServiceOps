/* Safe rendering of model output.
 *
 * Model text is untrusted. Nothing here ever uses innerHTML: every node is created
 * with createElement/textContent, so markup or script in an answer is displayed as
 * literal text. Only a small markdown subset is understood (headings, lists, bold,
 * italic, inline code, code fences, quotes) plus [S1]-style source markers, which
 * the model places directly after the record it just referenced (e.g. "...caused
 * by INC0010560 [S1]"). Rather than showing that bracket marker as its own footnote
 * chip, `linkCitation` below removes it from the visible text and turns the word (or
 * quoted title) immediately before it into the link instead -- a source becomes a
 * plain hyperlink on the specific thing it supports, only when the server actually
 * supplied that source. */
(function () {
  "use strict";

  const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+?\*\*)|(\*[^*\s][^*\n]*?\*)|(\[S\d+\]|\bS\d+\b)/g;

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  // The token a citation attaches to: a quoted title ("Printer offline"), or the
  // last run of non-space characters (a ticket/CI number, or an ordinary word).
  const TRAILING_TOKEN = /("[^"\n]+"|\S+)(\s*)$/;

  function safeSource(source) {
    if (!source || typeof source.url !== "string" || !source.url.startsWith("/") || source.url.startsWith("//") || /[\\\u0000-\u001f]/.test(source.url)) return null;
    return source;
  }

  function linkCitation(parent, source) {
    source = safeSource(source);
    // A space between the cited claim and "[S1]" (the model's usual style, e.g.
    // "**Printer offline** [S1]") lands as its own whitespace-only text node --
    // set it aside so the real token underneath it (plain word or bold/italic/
    // code element) can still be found and linked, then put the space back after.
    let pendingSpace = null;
    let last = parent.lastChild;
    if (last && last.nodeType === Node.TEXT_NODE && !/\S/.test(last.textContent)) {
      pendingSpace = last;
      parent.removeChild(last);
      last = parent.lastChild;
    }
    if (source && source.url) {
      const label = source.number || source.title || "Reference";
      if (last && last.nodeType === Node.TEXT_NODE && last.textContent.trimEnd().endsWith(label)) {
        const index = last.textContent.lastIndexOf(label);
        last.textContent = last.textContent.slice(0, index);
      } else if (last && last.nodeType === Node.ELEMENT_NODE && last.textContent === label) {
        parent.removeChild(last);
      } else if (last && /\S/.test(last.textContent || "")) {
        parent.appendChild(document.createTextNode(" "));
      }
      const link = node("a", "ai-cite", label);
      link.href = source.url;
      link.title = source.title || label;
      parent.appendChild(link);
      if (pendingSpace) parent.appendChild(pendingSpace);
      return;
    }
    const reattachSpace = function () { if (pendingSpace) parent.appendChild(pendingSpace); };
    if (last && last.nodeType === Node.TEXT_NODE) {
      const match = last.textContent.match(TRAILING_TOKEN);
      if (match) {
        last.textContent = last.textContent.slice(0, last.textContent.length - match[0].length);
        const wrapper = node(source ? "a" : "span", source ? "ai-cite" : "ai-cite ai-cite-pending", match[1]);
        if (source) { wrapper.href = source.url; wrapper.title = source.title; }
        parent.appendChild(wrapper);
        if (match[2]) parent.appendChild(document.createTextNode(match[2]));
        reattachSpace();
        return;
      }
    }
    if (last && last.nodeType === Node.ELEMENT_NODE && last.tagName !== "A") {
      // The cited claim was itself bold/italic/code text with nothing plain
      // trailing it (e.g. "**Printer offline** [S1]") -- wrap that element instead.
      const wrapper = node(source ? "a" : "span", source ? "ai-cite" : "ai-cite ai-cite-pending");
      if (source) { wrapper.href = source.url; wrapper.title = source.title; }
      parent.replaceChild(wrapper, last);
      wrapper.appendChild(last);
      reattachSpace();
      return;
    }
    // Nothing precedes the citation to attach it to (e.g. it opens a sentence);
    // there is no word left to link, so the marker is simply dropped.
    reattachSpace();
  }

  function inline(parent, text, sources) {
    let last = 0;
    text.replace(INLINE, function (match, code, bold, italic, cite, offset) {
      if (offset > last) parent.appendChild(document.createTextNode(text.slice(last, offset)));
      if (code) parent.appendChild(node("code", "", code.slice(1, -1)));
      else if (bold) parent.appendChild(node("strong", "", bold.slice(2, -2)));
      else if (italic) parent.appendChild(node("em", "", italic.slice(1, -1)));
      else if (cite) linkCitation(parent, sources && sources[cite.replace(/[\[\]]/g, "")]);
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
    linkRecordNumbers(out, sources || {});
    return out;
  }

  function linkRecordNumbers(fragment, sources) {
    const numbered = Object.values(sources).filter(function (source) { return source.number && safeSource(source); });
    if (!numbered.length) return;
    const escaped = numbered.map(function (source) { return source.number.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); });
    const pattern = new RegExp("(?<![\\w-])(" + escaped.join("|") + ")(?![\\w-])", "g");
    const byNumber = {};
    numbered.forEach(function (source) { byNumber[source.number] = source; });
    const walker = document.createTreeWalker(fragment, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(function (textNode) {
      if (textNode.parentElement && textNode.parentElement.closest("a,code,pre")) return;
      const text = textNode.textContent;
      const replacements = document.createDocumentFragment();
      let offset = 0;
      text.replace(pattern, function (match, number, position) {
        replacements.appendChild(document.createTextNode(text.slice(offset, position)));
        const link = node("a", "ai-cite", number);
        link.href = byNumber[number].url;
        replacements.appendChild(link);
        offset = position + match.length;
        return match;
      });
      if (offset) {
        replacements.appendChild(document.createTextNode(text.slice(offset)));
        textNode.replaceWith(replacements);
      }
    });
  }

  function plainText(text, sources) {
    return String(text || "").replace(/\[S\d+\]/g, function (marker) {
      const source = sources && sources[marker.slice(1, -1)];
      if (!source) return "";
      const linked = safeSource(source);
      const label = source.number || source.title || "Reference";
      return linked ? label + " (" + new URL(linked.url, window.location.origin).href + ")" : label;
    }).replace(/[*`#>]/g, "").replace(/\n{3,}/g, "\n\n").trim();
  }

  window.AIRender = { render: render, plainText: plainText };
})();
