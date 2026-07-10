/**
 * Light / dark theme for kohl.network.
 * Preference: localStorage → prefers-color-scheme → light.
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

  function storedTheme() {
    try {
      var stored = localStorage.getItem(KEY);
      if (stored === "light" || stored === "dark") return stored;
    } catch (_) {}
    return null;
  }

  /** Active theme from DOM, then storage, then system. */
  function current() {
    var attr = document.documentElement.getAttribute("data-theme");
    if (attr === "light" || attr === "dark") return attr;
    return storedTheme() || systemTheme();
  }

  function apply(theme) {
    if (theme !== "light" && theme !== "dark") theme = "light";
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(KEY, theme);
    } catch (_) {}
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      meta.setAttribute("content", theme === "dark" ? "#070707" : "#f7f3ec");
    }
    var btn = document.getElementById("theme-toggle");
    if (btn) {
      var toLight = theme === "dark";
      btn.setAttribute(
        "aria-label",
        toLight ? "Switch to light theme" : "Switch to dark theme"
      );
      btn.setAttribute("title", toLight ? "Light theme" : "Dark theme");
      btn.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
    }
  }

  function toggle(ev) {
    if (ev) {
      ev.preventDefault();
      ev.stopPropagation();
    }
    var next = current() === "dark" ? "light" : "dark";
    apply(next);
    return false;
  }

  // Expose for inline onclick fallback (if script order is odd).
  window.__kohlToggleTheme = toggle;
  window.__kohlApplyTheme = apply;

  apply(storedTheme() || systemTheme());

  function bind() {
    var btn = document.getElementById("theme-toggle");
    if (!btn || btn.getAttribute("data-theme-bound") === "1") return;
    btn.setAttribute("data-theme-bound", "1");
    btn.addEventListener("click", toggle);
    // Keyboard
    btn.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle(e);
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
  // Late bind if the button is re-rendered (safety).
  setTimeout(bind, 0);
})();
