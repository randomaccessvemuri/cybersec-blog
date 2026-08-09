(() => {
  const header = document.querySelector(".site-header");
  const rows = document.querySelectorAll(".reveal-row");

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
