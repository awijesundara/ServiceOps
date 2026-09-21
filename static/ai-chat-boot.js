/* Runs before first paint so an open chat does not flash closed while moving between pages. */
try { if (sessionStorage.getItem("ai-chat-open") === "1") document.documentElement.classList.add("ai-chat-open"); } catch (e) { /* storage may be blocked */ }
