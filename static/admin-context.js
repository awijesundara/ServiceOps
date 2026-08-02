document.addEventListener("DOMContentLoaded", () => {
  const navigation = document.querySelector(".settings-nav");
  if (!navigation) return;

  const links = [...navigation.querySelectorAll('a[href^="#"]')];
  const entries = links.map((link) => ({
    link,
    section: document.getElementById(decodeURIComponent(link.hash.slice(1))),
  })).filter((entry) => entry.section);
  if (!entries.length) return;
  let lockedEntry = null;
  let unlockTimer = null;

  const select = (activeEntry, updateHash = false) => {
    entries.forEach(({ link }) => {
      const active = link === activeEntry.link;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
    if (updateHash && history.replaceState) {
      history.replaceState(null, "", `#${activeEntry.section.id}`);
    }
  };

  links.forEach((link) => link.addEventListener("click", (event) => {
    const entry = entries.find((candidate) => candidate.link === link);
    if (!entry) return;
    event.preventDefault();
    lockedEntry = entry;
    clearTimeout(unlockTimer);
    unlockTimer = setTimeout(() => { lockedEntry = null; updateFromScroll(); }, 1200);
    entry.section.scrollIntoView({
      behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      block: "start",
    });
    select(entry, true);
  }));

  let scheduled = false;
  const updateFromScroll = () => {
    scheduled = false;
    const threshold = Math.min(180, window.innerHeight * 0.3);
    if (lockedEntry) {
      select(lockedEntry, true);
      if (Math.abs(lockedEntry.section.getBoundingClientRect().top - threshold) < 24) {
        lockedEntry = null;
        clearTimeout(unlockTimer);
      }
      return;
    }
    let active = entries[0];
    let activeTop = Number.NEGATIVE_INFINITY;
    for (const entry of entries) {
      const top = entry.section.getBoundingClientRect().top;
      if (top <= threshold && top > activeTop) {
        active = entry;
        activeTop = top;
      }
    }
    select(active, true);
  };
  window.addEventListener("scroll", () => {
    if (!scheduled) {
      scheduled = true;
      requestAnimationFrame(updateFromScroll);
    }
  }, {passive: true});
  window.addEventListener("resize", updateFromScroll);
  updateFromScroll();
});
