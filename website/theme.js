/**
 * Light / dark theme for kohl.network.
 * Also inlined in each HTML page (boot + onclick) so CDN-stale copies of
 * this file cannot break the toggle.
 */
(function () {
  var KEY = "kohl-theme";

  function systemTheme() {
    try {
      return window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    } catch (_) {
      return "light";
    }
  }

  function readStored() {
    try {
      var s = localStorage.getItem(KEY);
      if (s === "light" || s === "dark") return s;
    } catch (_) {}
    return null;
  }

  function get() {
    var attr = document.documentElement.getAttribute("data-theme");
    if (attr === "light" || attr === "dark") return attr;
    if (document.documentElement.classList.contains("theme-dark")) return "dark";
    if (document.documentElement.classList.contains("theme-light")) return "light";
    return readStored() || systemTheme();
  }

  function set(theme) {
    if (theme !== "dark") theme = "light";
    var root = document.documentElement;
    root.setAttribute("data-theme", theme);
    root.classList.remove("theme-light", "theme-dark");
    root.classList.add("theme-" + theme);
    try {
      localStorage.setItem(KEY, theme);
    } catch (_) {}
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", theme === "dark" ? "#070707" : "#f7f3ec");
    var btn = document.getElementById("theme-toggle");
    if (btn) {
      btn.setAttribute(
        "aria-label",
        theme === "dark" ? "Switch to light theme" : "Switch to dark theme"
      );
      btn.setAttribute("title", theme === "dark" ? "Light theme" : "Dark theme");
      btn.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
    }
  }

  function toggle(ev) {
    if (ev && ev.preventDefault) ev.preventDefault();
    set(get() === "dark" ? "light" : "dark");
    return false;
  }

  window.kohlTheme = { get: get, set: set, toggle: toggle, key: KEY };
  // Back-compat aliases
  window.__kohlToggleTheme = toggle;
  window.__kohlApplyTheme = set;

  set(readStored() || systemTheme());

  function bind() {
    var btn = document.getElementById("theme-toggle");
    if (!btn || btn.getAttribute("data-theme-bound") === "1") return;
    btn.setAttribute("data-theme-bound", "1");
    btn.addEventListener("click", toggle);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
  setTimeout(bind, 0);
})();
