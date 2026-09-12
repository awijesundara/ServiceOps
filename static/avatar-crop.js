/* Self-contained profile-picture cropper -- no external image-editing
   library, consistent with this app's no-CDN policy. Selecting a file opens
   a circular crop viewport: drag to reposition, a range input to zoom.
   "Save picture" rasterizes the visible circle onto a fixed-size canvas and
   replaces the file input's selection with that PNG via DataTransfer, so
   the existing /profile upload handler (PNG/JPEG signature check, 5MB
   limit, on-disk save) needs no changes -- it always receives an
   already-cropped square image. */
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("avatar-input");
  const modal = document.getElementById("avatar-crop-modal");
  const viewport = document.getElementById("avatar-crop-viewport");
  const cropImage = document.getElementById("avatar-crop-image");
  const zoomInput = document.getElementById("avatar-crop-zoom");
  const saveBtn = document.getElementById("avatar-crop-save");
  const cancelBtn = document.getElementById("avatar-crop-cancel");
  const previewImg = document.getElementById("profile-avatar-preview-img");
  const previewPlaceholder = document.getElementById("profile-avatar-preview-placeholder");
  if (!input || !modal || !viewport || !cropImage || !zoomInput || !saveBtn || !cancelBtn) return;

  const OUTPUT_SIZE = 480;
  const VIEWPORT_SIZE = 280;
  let naturalWidth = 0, naturalHeight = 0;
  let baseScale = 1; // scale at which the image exactly covers the viewport
  let scale = 1, offsetX = 0, offsetY = 0;
  let objectUrl = null;

  function clampOffsets() {
    const width = naturalWidth * baseScale * scale;
    const height = naturalHeight * baseScale * scale;
    const minX = Math.min(0, VIEWPORT_SIZE - width);
    const minY = Math.min(0, VIEWPORT_SIZE - height);
    offsetX = Math.max(minX, Math.min(0, offsetX));
    offsetY = Math.max(minY, Math.min(0, offsetY));
  }

  function render() {
    clampOffsets();
    const factor = baseScale * scale;
    cropImage.style.width = `${naturalWidth * factor}px`;
    cropImage.style.height = `${naturalHeight * factor}px`;
    cropImage.style.transform = `translate(${offsetX}px, ${offsetY}px)`;
  }

  function openCropper(file) {
    if (objectUrl) URL.revokeObjectURL(objectUrl);
    objectUrl = URL.createObjectURL(file);
    cropImage.onload = () => {
      naturalWidth = cropImage.naturalWidth;
      naturalHeight = cropImage.naturalHeight;
      baseScale = VIEWPORT_SIZE / Math.min(naturalWidth, naturalHeight);
      scale = 1;
      offsetX = (VIEWPORT_SIZE - naturalWidth * baseScale) / 2;
      offsetY = (VIEWPORT_SIZE - naturalHeight * baseScale) / 2;
      zoomInput.value = "1";
      render();
      if (typeof modal.showModal === "function") modal.showModal();
      else modal.setAttribute("open", "");
    };
    cropImage.src = objectUrl;
  }

  input.addEventListener("change", () => {
    const file = input.files && input.files[0];
    if (file) openCropper(file);
  });

  zoomInput.addEventListener("input", () => {
    scale = Number(zoomInput.value) || 1;
    render();
  });

  let dragging = false, dragStart = null;
  viewport.addEventListener("pointerdown", (event) => {
    dragging = true;
    dragStart = { x: event.clientX - offsetX, y: event.clientY - offsetY };
    viewport.classList.add("is-dragging");
    viewport.setPointerCapture(event.pointerId);
  });
  viewport.addEventListener("pointermove", (event) => {
    if (!dragging) return;
    offsetX = event.clientX - dragStart.x;
    offsetY = event.clientY - dragStart.y;
    render();
  });
  function endDrag() { dragging = false; viewport.classList.remove("is-dragging"); }
  viewport.addEventListener("pointerup", endDrag);
  viewport.addEventListener("pointerleave", endDrag);

  function closeCropper(clearSelection) {
    if (typeof modal.close === "function") modal.close();
    else modal.removeAttribute("open");
    if (clearSelection) input.value = "";
  }
  cancelBtn.addEventListener("click", () => closeCropper(true));
  modal.addEventListener("cancel", () => { input.value = ""; });

  saveBtn.addEventListener("click", () => {
    const canvas = document.createElement("canvas");
    canvas.width = OUTPUT_SIZE;
    canvas.height = OUTPUT_SIZE;
    const ctx = canvas.getContext("2d");
    const factor = baseScale * scale;
    // Map the visible viewport rectangle back into source-image pixel space.
    const sx = -offsetX / factor;
    const sy = -offsetY / factor;
    const sSize = VIEWPORT_SIZE / factor;
    ctx.drawImage(cropImage, sx, sy, sSize, sSize, 0, 0, OUTPUT_SIZE, OUTPUT_SIZE);
    canvas.toBlob((blob) => {
      if (!blob) return;
      const croppedFile = new File([blob], "avatar.png", { type: "image/png" });
      const transfer = new DataTransfer();
      transfer.items.add(croppedFile);
      input.files = transfer.files;
      const previewUrl = URL.createObjectURL(blob);
      if (previewImg) { previewImg.src = previewUrl; previewImg.style.display = ""; }
      if (previewPlaceholder) previewPlaceholder.style.display = "none";
      closeCropper(false);
    }, "image/png");
  });
});
