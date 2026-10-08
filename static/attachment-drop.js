// "Add attachments" for ticket pages (templates/_attachments_panel.html).
// Progressive enhancement: without JavaScript the panel's form posts one chosen
// file. With it, every way of adding files -- the Add attachments button,
// choosing files, dropping them anywhere on the record, or pasting from the
// clipboard -- opens one dialog that lists the queued files for review. Nothing
// uploads until Upload is pressed; files are then posted one at a time to the
// same route (same CSRF token, validation and malware scan) and the page reloads
// on the Attachments section so its normal flash messages show the result.
(() => {
  const MAX_BYTES = 20 * 1024 * 1024; // matches MAX_CONTENT_LENGTH

  function formatSize(bytes) {
    if (bytes < 1024) return tr("{size} B", { size: bytes });
    if (bytes < 1024 * 1024) return tr("{size} KB", { size: (bytes / 1024).toFixed(1) });
    return tr("{size} MB", { size: (bytes / 1024 / 1024).toFixed(1) });
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function enhance(form) {
    const panel = form.closest(".attachments-panel") || form;
    const input = form.querySelector('input[type="file"]');
    const number = form.dataset.attachmentDrop;
    if (!input) return;
    panel.classList.add("is-enhanced");
    panel.querySelector("[data-attachment-open]")?.removeAttribute("hidden");
    input.multiple = true;
    input.required = false;

    // --- the dialog -------------------------------------------------------
    const dialog = element("dialog", "attachment-dialog");
    dialog.setAttribute("aria-labelledby", "attachment-dialog-title");
    const header = element("header", "attachment-dialog-header");
    const title = element("h2", "", tr("Add attachments"));
    title.id = "attachment-dialog-title";
    const close = element("button", "attachment-dialog-close", "×");
    close.type = "button";
    close.setAttribute("aria-label", tr("Close"));
    header.append(title, close);

    const box = form.querySelector(".attachment-dropzone-box").cloneNode(true);
    const boxInput = box.querySelector('input[type="file"]');
    boxInput.removeAttribute("name");
    boxInput.multiple = true;
    boxInput.required = false;
    const queueList = element("ul", "attachment-queue");
    const status = element("p", "attachment-dialog-status");
    status.setAttribute("role", "status");
    const footer = element("footer", "attachment-dialog-footer");
    const supported = form.querySelector(".attachment-supported").cloneNode(true);
    const actions = element("div", "attachment-dialog-actions");
    const cancel = element("button", "", tr("Cancel"));
    cancel.type = "button";
    const upload = element("button", "primary", tr("Upload"));
    upload.type = "button";
    actions.append(cancel, upload);
    footer.append(supported, actions);
    dialog.append(header, box, queueList, status, footer);
    document.body.append(dialog);

    let queue = [];
    let busy = false;
    function render() {
      queueList.replaceChildren();
      queueList.hidden = !queue.length;
      queue.forEach((file, index) => {
        const item = element("li", file.size > MAX_BYTES ? "is-too-large" : "");
        const name = element("span", "attachment-queue-name", file.name);
        const size = element("small", "", file.size > MAX_BYTES
          ? tr("{size} · over the 20 MB limit, will be skipped", { size: formatSize(file.size) })
          : formatSize(file.size));
        const remove = element("button", "attachment-queue-remove", "×");
        remove.type = "button";
        remove.setAttribute("aria-label", tr("Remove {name}", { name: file.name }));
        remove.addEventListener("click", () => { queue.splice(index, 1); render(); });
        const meta = element("div", "attachment-queue-meta");
        meta.append(name, size);
        item.append(meta, remove);
        queueList.append(item);
      });
      const uploadable = queue.filter((file) => file.size <= MAX_BYTES).length;
      upload.disabled = busy || !uploadable;
      upload.textContent = uploadable > 1 ? tr("Upload {count} files", { count: uploadable }) : tr("Upload");
      title.textContent = number ? tr("Add attachments to {number}", { number }) : tr("Add attachments");
    }
    function add(files) {
      queue = queue.concat(Array.from(files));
      render();
    }
    function open(files = []) {
      if (busy) return;
      queue = [];
      status.textContent = "";
      status.classList.remove("is-error");
      add(files);
      if (!dialog.open) dialog.showModal();
      (queue.length ? upload : box).focus();
    }
    function dismiss() {
      if (busy) return;
      dialog.close();
      queue = [];
    }

    async function send() {
      const files = queue.filter((file) => file.size <= MAX_BYTES);
      if (busy || !files.length) return;
      busy = true;
      render();
      dialog.classList.add("is-uploading");
      const failures = [];
      let uploaded = 0;
      for (const [index, file] of files.entries()) {
        status.textContent = tr("Uploading {current} of {total}: {name}", { current: index + 1, total: files.length, name: file.name });
        const body = new FormData(form);
        body.set(input.name, file, file.name);
        try {
          const response = await fetch(form.action, { method: "POST", body, credentials: "same-origin" });
          if (response.ok) uploaded += 1;
          else failures.push(tr("{name} could not be uploaded.", { name: file.name }));
        } catch (error) {
          failures.push(tr("{name} could not be uploaded.", { name: file.name }));
        }
      }
      busy = false;
      dialog.classList.remove("is-uploading");
      if (uploaded) {
        // The server flashes success or a per-file validation error; show them.
        window.location.hash = "attachments";
        window.location.reload();
        return;
      }
      status.textContent = failures.join(" ");
      status.classList.add("is-error");
      render();
    }

    close.addEventListener("click", dismiss);
    cancel.addEventListener("click", dismiss);
    upload.addEventListener("click", send);
    dialog.addEventListener("cancel", (event) => { event.preventDefault(); dismiss(); }); // Escape
    boxInput.addEventListener("change", () => { add(boxInput.files); boxInput.value = ""; });

    // --- entry points -----------------------------------------------------
    panel.querySelector("[data-attachment-open]")?.addEventListener("click", () => open());
    input.addEventListener("change", () => { if (input.files.length) open(input.files); input.value = ""; });
    form.addEventListener("submit", (event) => { event.preventDefault(); open(input.files); });

    // Dropping anywhere on the record queues the files (the Attachments panel may
    // sit behind another tab, and an unhandled drop would make the browser open the
    // file and leave the ticket). The comment box keeps its own drop target.
    const banner = element("div", "attachment-drop-banner", number
      ? tr("Drop files to attach them to {number}", { number })
      : tr("Drop files to attach them"));
    banner.setAttribute("aria-hidden", "true");
    document.body.append(banner);
    const hasFiles = (event) => Array.from(event.dataTransfer?.types || []).includes("Files");
    const inComment = (event) => event.target instanceof Element && event.target.closest("form.comment-box");
    let depth = 0;
    const reset = () => { depth = 0; document.body.classList.remove("attachment-drag-active"); };
    document.addEventListener("dragenter", (event) => {
      if (!hasFiles(event)) return;
      event.preventDefault();
      depth += 1;
      if (!dialog.open) document.body.classList.add("attachment-drag-active");
      box.classList.toggle("is-dragover", box.contains(event.target));
    });
    document.addEventListener("dragover", (event) => { if (hasFiles(event)) event.preventDefault(); });
    document.addEventListener("dragleave", () => {
      depth = Math.max(0, depth - 1);
      if (!depth) { reset(); box.classList.remove("is-dragover"); }
    });
    document.addEventListener("drop", (event) => {
      if (!hasFiles(event)) return;
      event.preventDefault();
      reset();
      box.classList.remove("is-dragover");
      if (inComment(event) || !event.dataTransfer.files.length) return;
      if (dialog.open) add(event.dataTransfer.files);
      else open(event.dataTransfer.files);
    });

    // Pasting files (a screenshot, files copied in a file manager) queues them too,
    // unless the paste lands in a text field, where it keeps its normal meaning.
    document.addEventListener("paste", (event) => {
      const files = Array.from(event.clipboardData?.files || []);
      if (!files.length) return;
      const target = event.target instanceof Element ? event.target : null;
      if (!dialog.open && target?.closest("input, textarea, [contenteditable='true'], form.comment-box")) return;
      event.preventDefault();
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
      const named = files.map((file, index) => (file.name && file.name !== "image.png")
        ? file
        : new File([file], `pasted-${stamp}${index ? `-${index}` : ""}.${(file.type.split("/")[1] || "png").replace("jpeg", "jpg")}`, { type: file.type }));
      if (dialog.open) add(named);
      else open(named);
    });
  }

  // Dropping a file on the comment box fills its optional "Attach a file" input.
  function enhanceCommentForm(form) {
    const input = form.querySelector('input[type="file"]');
    if (!input) return;
    form.addEventListener("dragover", (event) => {
      if (!event.dataTransfer?.types.includes("Files")) return;
      event.preventDefault();
      form.classList.add("is-dragover");
    });
    form.addEventListener("dragleave", (event) => {
      if (!form.contains(event.relatedTarget)) form.classList.remove("is-dragover");
    });
    form.addEventListener("drop", (event) => {
      if (!event.dataTransfer?.files.length) return;
      event.preventDefault();
      form.classList.remove("is-dragover");
      const chosen = new DataTransfer();
      chosen.items.add(event.dataTransfer.files[0]);
      input.files = chosen.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("form[data-attachment-drop]").forEach(enhance);
    document.querySelectorAll("form.comment-box").forEach(enhanceCommentForm);
  });
})();
