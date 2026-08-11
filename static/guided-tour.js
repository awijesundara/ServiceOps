/* B-120 guided tour player. Fetches tours eligible for the current route/
role from the server (server decides eligibility, this only renders), then
walks the user through each step, highlighting the element matched by its
target_selector (an unanchored step with no selector renders centered).
Only ever added to pages a page opts into via data-tour="..." attributes on
target elements -- this script never reaches into arbitrary markup beyond
what a page has explicitly marked. */
document.addEventListener("DOMContentLoaded", () => {
  const route = document.body.dataset.tourRoute;
  if (!route) return;
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";

  fetch(`/api/guided-tours/active?route=${encodeURIComponent(route)}`)
    .then((response) => (response.ok ? response.json() : {tours: []}))
    .then((data) => {
      const tours = data.tours || [];
      if (tours.length) playTour(tours[0]);
    })
    .catch(() => {});

  function recordProgress(tourId, status) {
    const body = new URLSearchParams({status});
    fetch(`/api/guided-tours/${tourId}/progress`, {
      method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrfToken},
      body,
    });
  }

  function playTour(tour) {
    let index = 0;
    const overlay = document.createElement("div");
    overlay.className = "guided-tour-overlay";
    const card = document.createElement("div");
    card.className = "guided-tour-card";
    overlay.appendChild(card);
    document.body.appendChild(overlay);

    function clearHighlight() {
      document.querySelectorAll(".guided-tour-highlight").forEach((el) => {
        el.classList.remove("guided-tour-highlight");
      });
    }

    function render() {
      clearHighlight();
      const step = tour.steps[index];
      const target = step.target_selector ? document.querySelector(step.target_selector) : null;
      if (target) {
        target.classList.add("guided-tour-highlight");
        target.scrollIntoView({block: "center", behavior: "smooth"});
      }
      card.innerHTML = "";
      const eyebrow = document.createElement("p");
      eyebrow.className = "guided-tour-eyebrow";
      eyebrow.textContent = `${tour.title} · ${index + 1} of ${tour.steps.length}`;
      const title = document.createElement("h3");
      title.textContent = step.title;
      const body = document.createElement("p");
      body.textContent = step.body;
      const actions = document.createElement("div");
      actions.className = "guided-tour-actions";

      const skip = document.createElement("button");
      skip.type = "button";
      skip.className = "button";
      skip.textContent = "Skip";
      skip.addEventListener("click", () => finish("dismissed"));
      actions.appendChild(skip);

      if (index > 0) {
        const prev = document.createElement("button");
        prev.type = "button";
        prev.className = "button";
        prev.textContent = "Back";
        prev.addEventListener("click", () => {
          index -= 1;
          render();
        });
        actions.appendChild(prev);
      }

      const next = document.createElement("button");
      next.type = "button";
      next.className = "primary button";
      next.textContent = index === tour.steps.length - 1 ? "Finish" : "Next";
      next.addEventListener("click", () => {
        if (index === tour.steps.length - 1) {
          finish("completed");
        } else {
          index += 1;
          render();
        }
      });
      actions.appendChild(next);

      card.appendChild(eyebrow);
      card.appendChild(title);
      card.appendChild(body);
      card.appendChild(actions);
    }

    function finish(status) {
      clearHighlight();
      overlay.remove();
      recordProgress(tour.id, status);
    }

    render();
  }
});
