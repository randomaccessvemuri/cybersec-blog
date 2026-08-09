(() => {
  const root = document.documentElement;
  const header = document.querySelector(".site-header");
  const rows = document.querySelectorAll(".reveal-row");
  const toggle = document.querySelector("[data-theme-toggle]");
  const storageKey = "tmajik-theme";
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const isHome = document.body.classList.contains("is-home");

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

  const initAmbient = () => {
    if (!isHome || reduceMotion) return;

    const atmosphere = document.querySelector(".atmosphere");
    const orbsHost = document.querySelector("[data-orbs]");
    const gridGlow = document.querySelector("[data-grid-glow]");
    const cursorGlow = document.querySelector("[data-cursor-glow]");
    if (!atmosphere || !orbsHost) return;

    const rand = (min, max) => min + Math.random() * (max - min);
    const orbCount = window.matchMedia("(max-width: 720px)").matches ? 3 : 5;
    const orbs = [];

    for (let i = 0; i < orbCount; i += 1) {
      const el = document.createElement("span");
      el.className = "atmosphere__orb";
      const size = rand(180, 420);
      el.style.width = `${size}px`;
      el.style.height = `${size}px`;
      orbsHost.appendChild(el);
      orbs.push({
        el,
        x: rand(0, window.innerWidth),
        y: rand(0, window.innerHeight),
        vx: rand(-0.35, 0.35) || 0.2,
        vy: rand(-0.28, 0.28) || 0.15,
        size,
        wobble: rand(0, Math.PI * 2),
        wobbleSpeed: rand(0.004, 0.012),
      });
    }

    let mx = window.innerWidth * 0.5;
    let my = window.innerHeight * 0.35;
    let tx = mx;
    let ty = my;
    let pointerActive = false;
    let raf = 0;

    const setGlowPoint = (x, y) => {
      atmosphere.style.setProperty("--mx", `${x}px`);
      atmosphere.style.setProperty("--my", `${y}px`);
    };

    const onPointerMove = (event) => {
      tx = event.clientX;
      ty = event.clientY;
      if (!pointerActive) {
        pointerActive = true;
        gridGlow?.classList.add("is-on");
        cursorGlow?.classList.add("is-on");
      }
    };

    const onPointerLeave = () => {
      pointerActive = false;
      gridGlow?.classList.remove("is-on");
      cursorGlow?.classList.remove("is-on");
    };

    window.addEventListener("pointermove", onPointerMove, { passive: true });
    document.documentElement.addEventListener("mouseleave", onPointerLeave);

    const tick = () => {
      const w = window.innerWidth;
      const h = window.innerHeight;

      mx += (tx - mx) * 0.12;
      my += (ty - my) * 0.12;
      if (pointerActive) setGlowPoint(mx, my);

      orbs.forEach((orb) => {
        orb.wobble += orb.wobbleSpeed;
        orb.vx += Math.sin(orb.wobble) * 0.012;
        orb.vy += Math.cos(orb.wobble * 0.85) * 0.01;

        const speed = Math.hypot(orb.vx, orb.vy);
        const maxSpeed = 0.55;
        if (speed > maxSpeed) {
          orb.vx = (orb.vx / speed) * maxSpeed;
          orb.vy = (orb.vy / speed) * maxSpeed;
        }

        // Occasional random nudge
        if (Math.random() < 0.008) {
          orb.vx += rand(-0.25, 0.25);
          orb.vy += rand(-0.25, 0.25);
        }

        orb.x += orb.vx;
        orb.y += orb.vy;

        const pad = orb.size * 0.35;
        if (orb.x < -pad) orb.x = w + pad;
        if (orb.x > w + pad) orb.x = -pad;
        if (orb.y < -pad) orb.y = h + pad;
        if (orb.y > h + pad) orb.y = -pad;

        orb.el.style.transform = `translate3d(${orb.x - orb.size / 2}px, ${orb.y - orb.size / 2}px, 0)`;
      });

      raf = requestAnimationFrame(tick);
    };

    raf = requestAnimationFrame(tick);

    window.addEventListener(
      "resize",
      () => {
        orbs.forEach((orb) => {
          orb.x = Math.min(orb.x, window.innerWidth);
          orb.y = Math.min(orb.y, window.innerHeight);
        });
      },
      { passive: true }
    );

    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        cancelAnimationFrame(raf);
      } else {
        raf = requestAnimationFrame(tick);
      }
    });
  };

  initAmbient();
})();
