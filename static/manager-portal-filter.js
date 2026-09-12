/* Instant client-side filter for the manager portal -- a manager overseeing
   several IT fulfillment teams had no way to jump to one person or team
   without scanning every section by eye. Filters by name/title (per row,
   via data-search-text) and by team name (hides a whole section only when
   none of its real member rows match, never the "no members" empty-state
   row, which carries no data-search-text). */
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("manager-portal-filter");
  if (!input) return;
  const sections = document.querySelectorAll(".mp-team-section");
  input.addEventListener("input", () => {
    const needle = input.value.trim().toLowerCase();
    sections.forEach((section) => {
      const teamMatches = !needle || (section.dataset.teamName || "").includes(needle);
      let anyRowVisible = false;
      section.querySelectorAll(".mp-member-row").forEach((row) => {
        const show = !needle || teamMatches || (row.dataset.searchText || "").includes(needle);
        row.hidden = !show;
        if (show) anyRowVisible = true;
      });
      section.hidden = Boolean(needle) && !teamMatches && !anyRowVisible;
    });
  });
});
