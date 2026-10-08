// Drag-and-drop (and multi-file) attachment upload for ticket pages.
// Progressive enhancement: the plain <form data-attachment-drop> still posts one
// file without JavaScript. With it, the whole record page accepts dropped files,
// and dropped or multi-selected files are posted one at a time to the same
// upload route (same CSRF token, validation and malware scan), then the page
// reloads on the Attachments section so its normal flash messages show the result.
(() => {
  const MAX_BYTES = 20 * 1024 * 1024; // matches MAX_CONTENT_LENGTH

  function enhanceUploadForm(form) {
    const input = form.querySelector('input[type="file"]');
    const zone = form.closest(".panel") || form;
    if (!input) return;
    input.multiple = true;
    zone.classList.add("attachment-dropzone");

    const hint = document.createElement("p");
    hint.className = "attachment-drop-hint";
    hint.textContent = tr("Drag and drop files here, or choose files to upload.");
    form.before(hint);
    const status = document.createElement("p");
    status.className = "attachment-drop-status";
    status.setAttribute("role", "status");
    status.hidden = true;
    form.after(status);

    let busy = false;
    async function upload(files) {
      if (busy || !files.length) return;
      busy = true;
      zone.classList.add("is-uploading");
      const failures = [];
      let uploaded = 0;
      for (const [index, file] of files.entries()) {
        status.hidden = false;
        status.textContent = tr("Uploading {current} of {total}: {name}", { current: index + 1, total: files.length, name: file.name });
        if (file.size > MAX_BYTES) {
          failures.push(tr("{name} is larger than 20 MB.", { name: file.name }));
          continue;
        }
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
      zone.classList.remove("is-uploading");
      if (uploaded) {
        // The server flashes success or a per-file validation error; show them.
        window.location.hash = "attachments";
        window.location.reload();
        return;
      }
      status.textContent = failures.join(" ");
      status.classList.add("is-error");
    }

    form.addEventListener("submit", (event) => {
      if (input.files.length > 1) {
        event.preventDefault();
        upload(Array.from(input.files));
      }
    });

    // The whole record page is the drop target: the Attachments panel may sit
    // behind another tab, and a file dropped outside any handler would make the
    // browser open it and leave the ticket. The comment box keeps its own drop
    // (it attaches to the comment instead).
    const banner = document.createElement("div");
    banner.className = "attachment-drop-banner";
    banner.setAttribute("aria-hidden", "true");
    banner.textContent = form.dataset.attachmentDrop
      ? tr("Drop files to attach them to {number}", { number: form.dataset.attachmentDrop })
      : tr("Drop files to attach them");
    document.body.append(banner);
    const hasFiles = (event) => Array.from(event.dataTransfer?.types || []).includes("Files");
    const inComment = (event) => event.target instanceof Element && event.target.closest("form.comment-box");
    let depth = 0;
    const reset = () => { depth = 0; document.body.classList.remove("attachment-drag-active"); zone.classList.remove("is-dragover"); };
    document.addEventListener("dragenter", (event) => {
      if (!hasFiles(event)) return;
      event.preventDefault();
      depth += 1;
      document.body.classList.add("attachment-drag-active");
      zone.classList.toggle("is-dragover", zone.contains(event.target));
    });
    document.addEventListener("dragover", (event) => {
      if (hasFiles(event)) event.preventDefault();
    });
    document.addEventListener("dragleave", () => {
      depth = Math.max(0, depth - 1);
      if (!depth) reset();
    });
    document.addEventListener("drop", (event) => {
      if (!hasFiles(event)) return;
      event.preventDefault();
      reset();
      if (inComment(event) || !event.dataTransfer.files.length) return;
      upload(Array.from(event.dataTransfer.files));
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
    document.querySelectorAll("form[data-attachment-drop]").forEach(enhanceUploadForm);
    document.querySelectorAll("form.comment-box").forEach(enhanceCommentForm);
  });
})();
