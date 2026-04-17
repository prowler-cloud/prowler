"use client";

import { useEffect, useRef } from "react";

const PARTICLE_DENSITY = 14000;
const PARTICLE_MIN_COUNT = 40;
const PARTICLE_MIN_RADIUS = 1.4;
const PARTICLE_RADIUS_RANGE = 1.8;
const PARTICLE_SPEED = 0.35;
const CONNECTION_DISTANCE = 140;
const CONNECTION_DISTANCE_SQ = CONNECTION_DISTANCE * CONNECTION_DISTANCE;
const LINE_WIDTH = 0.8;
const MOUSE_RADIUS = 160;
const MOUSE_RADIUS_SQ = MOUSE_RADIUS * MOUSE_RADIUS;
const MOUSE_FORCE = 2.2;
const PARTICLE_ALPHA = 0.75;
const CONNECTION_MAX_ALPHA = 0.35;
const ALPHA_TIER_COUNT = 3;
const MAX_DPR = 2;
const ACCENT_LIGHT = "rgb(156, 163, 175)";
const ACCENT_DARK_FALLBACK = "rgb(110, 231, 183)";
const ACCENT_VAR = "--bg-button-primary";

export const AnimatedDotsBackground = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const ac = new AbortController();
    const { signal } = ac;

    let animationId = 0;
    let resizeFrameId = 0;
    let width = 0;
    let height = 0;
    let accentColor = ACCENT_LIGHT;
    let count = 0;
    let xs = new Float32Array(0);
    let ys = new Float32Array(0);
    let vxs = new Float32Array(0);
    let vys = new Float32Array(0);
    let rs = new Float32Array(0);

    const tierBuckets: Float32Array[] = [];
    const tierLengths = new Int32Array(ALPHA_TIER_COUNT);

    const mouse = { x: -9999, y: -9999, active: false };

    const readAccent = () => {
      const isDark = document.documentElement.classList.contains("dark");
      if (!isDark) {
        accentColor = ACCENT_LIGHT;
        return;
      }
      const value = getComputedStyle(document.documentElement)
        .getPropertyValue(ACCENT_VAR)
        .trim();
      accentColor = value || ACCENT_DARK_FALLBACK;
    };

    const ensureTierCapacity = (n: number) => {
      const maxPairs = (n * (n - 1)) / 2;
      const floatsNeeded = maxPairs * 4;
      for (let t = 0; t < ALPHA_TIER_COUNT; t++) {
        if (!tierBuckets[t] || tierBuckets[t].length < floatsNeeded) {
          tierBuckets[t] = new Float32Array(floatsNeeded);
        }
      }
    };

    const initParticles = () => {
      count = Math.max(
        PARTICLE_MIN_COUNT,
        Math.floor((width * height) / PARTICLE_DENSITY),
      );
      xs = new Float32Array(count);
      ys = new Float32Array(count);
      vxs = new Float32Array(count);
      vys = new Float32Array(count);
      rs = new Float32Array(count);
      for (let i = 0; i < count; i++) {
        xs[i] = Math.random() * width;
        ys[i] = Math.random() * height;
        vxs[i] = (Math.random() - 0.5) * PARTICLE_SPEED;
        vys[i] = (Math.random() - 0.5) * PARTICLE_SPEED;
        rs[i] = Math.random() * PARTICLE_RADIUS_RANGE + PARTICLE_MIN_RADIUS;
      }
      ensureTierCapacity(count);
    };

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR);
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      initParticles();
    };

    const scheduleResize = () => {
      if (resizeFrameId) return;
      resizeFrameId = requestAnimationFrame(() => {
        resizeFrameId = 0;
        resize();
      });
    };

    const onMove = (e: MouseEvent) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
      mouse.active = true;
    };
    const onLeave = () => {
      mouse.active = false;
      mouse.x = -9999;
      mouse.y = -9999;
    };

    const drawFrame = () => {
      ctx.clearRect(0, 0, width, height);

      for (let i = 0; i < count; i++) {
        let x = xs[i] + vxs[i];
        let y = ys[i] + vys[i];

        if (x < 0) {
          x = 0;
          vxs[i] = -vxs[i];
        } else if (x > width) {
          x = width;
          vxs[i] = -vxs[i];
        }
        if (y < 0) {
          y = 0;
          vys[i] = -vys[i];
        } else if (y > height) {
          y = height;
          vys[i] = -vys[i];
        }

        if (mouse.active) {
          const dx = x - mouse.x;
          const dy = y - mouse.y;
          const dsq = dx * dx + dy * dy;
          if (dsq < MOUSE_RADIUS_SQ && dsq > 0) {
            const dist = Math.sqrt(dsq);
            const force = (MOUSE_RADIUS - dist) / MOUSE_RADIUS;
            const inv = 1 / dist;
            x += dx * inv * force * MOUSE_FORCE;
            y += dy * inv * force * MOUSE_FORCE;
          }
        }

        xs[i] = x;
        ys[i] = y;
      }

      for (let t = 0; t < ALPHA_TIER_COUNT; t++) tierLengths[t] = 0;

      for (let i = 0; i < count; i++) {
        const xi = xs[i];
        const yi = ys[i];
        for (let j = i + 1; j < count; j++) {
          const dx = xi - xs[j];
          const dy = yi - ys[j];
          const dsq = dx * dx + dy * dy;
          if (dsq >= CONNECTION_DISTANCE_SQ) continue;

          const ratio = 1 - Math.sqrt(dsq) / CONNECTION_DISTANCE;
          let tier = (ratio * ALPHA_TIER_COUNT) | 0;
          if (tier >= ALPHA_TIER_COUNT) tier = ALPHA_TIER_COUNT - 1;

          const bucket = tierBuckets[tier];
          const off = tierLengths[tier];
          bucket[off] = xi;
          bucket[off + 1] = yi;
          bucket[off + 2] = xs[j];
          bucket[off + 3] = ys[j];
          tierLengths[tier] = off + 4;
        }
      }

      ctx.lineWidth = LINE_WIDTH;
      ctx.strokeStyle = accentColor;

      for (let t = 0; t < ALPHA_TIER_COUNT; t++) {
        const len = tierLengths[t];
        if (len === 0) continue;
        ctx.globalAlpha = CONNECTION_MAX_ALPHA * ((t + 0.5) / ALPHA_TIER_COUNT);
        ctx.beginPath();
        const bucket = tierBuckets[t];
        for (let k = 0; k < len; k += 4) {
          ctx.moveTo(bucket[k], bucket[k + 1]);
          ctx.lineTo(bucket[k + 2], bucket[k + 3]);
        }
        ctx.stroke();
      }

      ctx.fillStyle = accentColor;
      ctx.globalAlpha = PARTICLE_ALPHA;
      ctx.beginPath();
      for (let i = 0; i < count; i++) {
        ctx.moveTo(xs[i] + rs[i], ys[i]);
        ctx.arc(xs[i], ys[i], rs[i], 0, Math.PI * 2);
      }
      ctx.fill();
      ctx.globalAlpha = 1;
    };

    const loop = () => {
      drawFrame();
      animationId = requestAnimationFrame(loop);
    };

    const start = () => {
      if (animationId) return;
      animationId = requestAnimationFrame(loop);
    };

    const stop = () => {
      if (!animationId) return;
      cancelAnimationFrame(animationId);
      animationId = 0;
    };

    const onVisibilityChange = () => {
      if (document.hidden) stop();
      else if (!reducedMotion.matches) start();
    };

    const onMotionChange = () => {
      if (reducedMotion.matches) {
        stop();
        drawFrame();
      } else {
        start();
      }
    };

    const themeObserver = new MutationObserver(readAccent);
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });

    readAccent();
    resize();
    if (reducedMotion.matches) drawFrame();
    else start();

    window.addEventListener("resize", scheduleResize, { signal });
    window.addEventListener("mousemove", onMove, { signal, passive: true });
    window.addEventListener("mouseleave", onLeave, { signal });
    document.addEventListener("visibilitychange", onVisibilityChange, {
      signal,
    });
    reducedMotion.addEventListener("change", onMotionChange, { signal });

    return () => {
      stop();
      if (resizeFrameId) cancelAnimationFrame(resizeFrameId);
      themeObserver.disconnect();
      ac.abort();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none absolute inset-0 h-full w-full"
    />
  );
};
