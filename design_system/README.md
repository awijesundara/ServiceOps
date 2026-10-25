# ServiceOps interface system

Edit this directory, not `static/controls.css`.

* `tokens.json` owns shared sizing, spacing, type, focus, motion and responsive modes.
* `components.css` owns shared controls, frames, layout primitives and compatibility selectors used by existing pages.
* `templates/_ui.html` provides reusable buttons, panels, fields and action cards. Use macros for new interfaces; pass authorized destinations from the caller. Field callers must connect hint/error IDs with `aria-describedby` and set `aria-invalid` when appropriate.
* Administration → Platform & security → Interface standards demonstrates real components using sample data. Account appearance preferences apply normally.

Build with `python tools/build_interface_system.py`, then `python tools/build_dark_theme.py`. Validate with both builders' `--check`, `python -m tools.check_interface_system`, and pytest. Generated files remain checked in for runtime deployment; no runtime compilation is needed.

Page styles may define structural layout for boards, charts and trees. They must not redefine shared button and section-stack geometry. `legacy-overrides.json` is an explicit inventory of existing declarations: the guard allows their removal, but fails on new or changed fixed dimensions. This is a migration boundary, not permission to expand the inventory. The initial shared button and dashboard gap overrides have been retired; the empty inventory prevents them from returning.

Palette ownership is `design_system/themes.css`, generated to `static/themes.css`; dark-theme remapping remains `tools/build_dark_theme.py`. Semantic palette variables are consumed rather than duplicated. Do not introduce a second palette or component-size source in page styles. Reduced motion and keyboard focus must remain accessible. Validate standard, compact, touch, narrow and dark layouts after changes.

Dashboard sections must compose `.ui-stack` with `.dashboard-columns`. Both use `--section-gap`; child panel margins are reset to prevent doubled gaps. A lone SLA card spans the row, and table content scrolls within its frame. Shared heading icons use `--space-2` and have accessible explanations. The populated dashboard browser test checks actual gaps with both, one or no SLA cards.

## Calendar and notice cards

`calendar.js` generates `static/calendar.js`, loaded once by the shell. Every editable native date/datetime field is enhanced, including dynamically inserted filters. Original names, values, required/min/max/step constraints, editable typing and server timezone parsing remain authoritative. Read-only/disabled fields remain unchanged. Centrally declared name pairs cover changes, freezes, delegation, log filters, sprints, work-item start/due, release dates and contract start/end; unrelated dates stay single. One dialog stages both endpoints, supports keyboard and month/year navigation, optional times, Apply/Cancel and clearing. Unexpected action failures log a sanitized error, provide accessible feedback and restore native inputs. Without JavaScript native calendars remain available. The protected reference demonstrates single dates and ranges.

`notice-cards.js` (compatibility source name) generates `static/service-status-feed.js`. The selected B layout is a compact status row above one thin rolling headline. Shared tokens define a 36px minimum strip and four-second interval. There is no visible play/pause button or reserved control space. Full headlines are linked and available through a tooltip; overflow is ellipsized without enlarging the strip. Left/Right arrows on the focused headline browse manually. Space on a focused headline toggles persistent pause; hover/focus/visibility suspension and reduced-motion defaults remain available. One notice has no rotation controls; the no-JavaScript fallback shows the first linked headline. Server-side tenant/publication/visibility filtering is unchanged. View all remains the complete authenticated detail page.
