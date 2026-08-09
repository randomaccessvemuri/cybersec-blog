(() => {
  const root = document.documentElement;
  const header = document.querySelector(".site-header");
  const rows = document.querySelectorAll(".reveal-row");
  const toggle = document.querySelector("[data-theme-toggle]");
  const storageKey = "tmajik-theme";

  const setTheme = (theme) => {
    root.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(storageKey, theme);
    } catch (_) {}
    if (toggle) {
      const next = theme === "dark" ? "light" : "dark";
      toggle.setAttribute("aria-label", `Switch to ${next} mode`);
      toggle.setAttribute("title", `Switch to ${next} mode`);
    }
  };

  setTheme(root.getAttribute("data-theme") || "dark");

  if (toggle) {
    toggle.addEventListener("click", () => {
      const current = root.getAttribute("data-theme") === "light" ? "light" : "dark";
      setTheme(current === "dark" ? "light" : "dark");
    });
  }

  const onScroll = () => {
    if (!header) return;
    header.classList.toggle("is-scrolled", window.scrollY > 12);
  };

  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  if ("IntersectionObserver" in window && rows.length) {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-in");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -8% 0px" }
    );
    rows.forEach((row, i) => {
      row.style.transitionDelay = `${i * 70}ms`;
      io.observe(row);
    });
  } else {
    rows.forEach((row) => row.classList.add("is-in"));
  }
})();
