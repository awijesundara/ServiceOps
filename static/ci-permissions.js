document.querySelectorAll('[data-row-toggle]').forEach((box) => {
  box.addEventListener('change', () => {
    document.querySelectorAll(`.ci-perm-cell[data-row="${box.dataset.rowToggle}"]`).forEach((cell) => { cell.checked = box.checked; });
  });
});
document.querySelectorAll('[data-col-toggle]').forEach((box) => {
  box.addEventListener('change', () => {
    document.querySelectorAll(`.ci-perm-cell[data-col="${box.dataset.colToggle}"]`).forEach((cell) => { cell.checked = box.checked; });
  });
});
