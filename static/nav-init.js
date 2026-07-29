(function () {
  if (localStorage.getItem("navCollapsed") === "1") document.body.classList.add("nav-collapsed");
  var sidebarNav = document.querySelector(".sidebar nav");
  if (sidebarNav) {
    var savedScroll = sessionStorage.getItem("sidebarNavScrollTop");
    if (savedScroll) sidebarNav.scrollTop = parseInt(savedScroll, 10) || 0;
  }
})();
