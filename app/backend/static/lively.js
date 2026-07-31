/* ======================================================================
   lively.js — 灵动交互驱动（3D 倾斜 / 磁吸 / 避开）
   依赖 lively.css。仅在支持 hover 的指针设备上启用倾斜/磁吸/避开；
   尊重 prefers-reduced-motion。

   性能优化要点：
   - 移除全局 MutationObserver 与 setInterval 轮询，改为初始化时 + 显式刷新点执行
   - pointermove 使用 requestAnimationFrame 节流，避免每事件都重算
   - getBoundingClientRect 缓存一帧，降低强制重排成本
   - 页面 unload / visibilitychange 时清理监听器与状态
   ====================================================================== */
(function () {
  'use strict';

  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReduced) return;

  var hasHover = window.matchMedia('(hover: hover) and (pointer: fine)').matches;

  var TILT_SEL =
    'article.glass-card:not(.result-card), .kpi-card, .bento-card, .cwe-card, .chart-card, ' +
    '.score-card, .stats-card, .posture-header, .remediation-table tbody tr, .results-panel > *:not(.result-card)';
  var MAG_SEL =
    'button, .filter-chip, .view-detail, nav[aria-label="主导航"] a, a[id^="cta-quick-"]';
  var DODGE_SEL =
    '.icon-box > svg, .kpi-card svg, nav[aria-label="主导航"] svg';

  function rand(min, max) { return min + Math.random() * (max - min); }

  /* ---- 给元素打标记 + 随机化浮动节奏 ---- */
  function decorate() {
    var els = document.querySelectorAll(TILT_SEL);
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.dataset.lvTilt) continue;
      el.dataset.lvTilt = '1';
      el.classList.add('lv-tilt');
      el.style.setProperty('--fd', rand(4.6, 6.8).toFixed(2) + 's');
      el.style.setProperty('--fdelay', rand(0, 3.2).toFixed(2) + 's');
    }
    els = document.querySelectorAll(MAG_SEL);
    for (i = 0; i < els.length; i++) {
      el = els[i];
      if (el.dataset.lvMag) continue;
      el.dataset.lvMag = '1';
      el.classList.add('lv-magnetic');
    }
    els = document.querySelectorAll(DODGE_SEL);
    for (i = 0; i < els.length; i++) {
      el = els[i];
      if (el.dataset.lvDodge) continue;
      el.dataset.lvDodge = '1';
      el.classList.add('lv-dodge');
    }
  }

  /* ---- 暴露全局刷新接口，页面动态渲染后主动调用 ---- */
  window.refreshLively = decorate;

  // 初始执行一次；后续由页面在需要时调用 window.refreshLively()
  decorate();

  if (!hasHover) return;

  /* ---- 缓存避开元素列表 ---- */
  var dodgeEls = [];
  function refreshDodge() { dodgeEls = Array.prototype.slice.call(document.querySelectorAll('.lv-dodge')); }
  refreshDodge();
  // 页面可主动刷新
  window.refreshLivelyDodge = refreshDodge;

  var tiltEl = null, magEl = null;
  var px = -9999, py = -9999, pTarget = null, ticking = false;
  var lastMoveTime = 0;

  function climbTo(node, cls) {
    while (node && node !== document) {
      if (node.classList && node.classList.contains(cls)) return node;
      node = node.parentNode;
    }
    return null;
  }

  function onMove(e) {
    px = e.clientX; py = e.clientY; pTarget = e.target;
    lastMoveTime = performance.now();
    if (!ticking) { ticking = true; requestAnimationFrame(tick); }
  }

  /* ---- 缓存 dodge rects，一帧内复用 ---- */
  var dodgeRects = null;
  function getDodgeRects() {
    if (!dodgeRects) {
      dodgeRects = [];
      for (var i = 0; i < dodgeEls.length; i++) {
        var r = dodgeEls[i].getBoundingClientRect();
        if (r.width) dodgeRects.push({ el: dodgeEls[i], r: r });
      }
    }
    return dodgeRects;
  }

  function tick() {
    ticking = false;
    var root = pTarget || document.body;

    /* 1) 3D 倾斜 */
    var tEl = climbTo(root, 'lv-tilt');
    if (tEl !== tiltEl) {
      if (tiltEl) {
        tiltEl.style.setProperty('--rx', '0deg');
        tiltEl.style.setProperty('--ry', '0deg');
      }
      tiltEl = tEl;
    }
    if (tiltEl) {
      var r = tiltEl.getBoundingClientRect();
      if (r.width) {
        var dx = (px - (r.left + r.width / 2)) / (r.width / 2);
        var dy = (py - (r.top + r.height / 2)) / (r.height / 2);
        dx = Math.max(-1, Math.min(1, dx));
        dy = Math.max(-1, Math.min(1, dy));
        tiltEl.style.setProperty('--ry', (dx * 7).toFixed(2) + 'deg');
        tiltEl.style.setProperty('--rx', (-dy * 7).toFixed(2) + 'deg');
      }
    }

    /* 2) 磁吸 */
    var mEl = climbTo(root, 'lv-magnetic');
    if (mEl !== magEl) {
      if (magEl) {
        magEl.style.setProperty('--mx', '0px');
        magEl.style.setProperty('--my', '0px');
      }
      magEl = mEl;
    }
    if (magEl) {
      var mr = magEl.getBoundingClientRect();
      if (mr.width) {
        magEl.style.setProperty('--mx', ((px - (mr.left + mr.width / 2)) * 0.28).toFixed(2) + 'px');
        magEl.style.setProperty('--my', ((py - (mr.top + mr.height / 2)) * 0.28).toFixed(2) + 'px');
      }
    }

    /* 3) 避开 */
    var rects = getDodgeRects();
    for (var i = 0; i < rects.length; i++) {
      var item = rects[i];
      var er = item.r;
      var ddx = (er.left + er.width / 2) - px;
      var ddy = (er.top + er.height / 2) - py;
      var dist = Math.sqrt(ddx * ddx + ddy * ddy);
      var RADIUS = 95;
      if (dist < RADIUS && dist > 0.5) {
        var force = 1 - dist / RADIUS;
        var push = force * 16;
        item.el.style.setProperty('--dx', ((ddx / dist) * push).toFixed(2) + 'px');
        item.el.style.setProperty('--dy', ((ddy / dist) * push).toFixed(2) + 'px');
        item.el.style.setProperty('--ds', (1 + force * 0.28).toFixed(3));
      } else if (item.el.style.getPropertyValue('--dx') !== '0px') {
        item.el.style.setProperty('--dx', '0px');
        item.el.style.setProperty('--dy', '0px');
        item.el.style.setProperty('--ds', '1');
      }
    }

    // 本帧结束清除 rect 缓存
    dodgeRects = null;

    // 鼠标停止 100ms 后复位（避免留下悬停偏移）
    var now = performance.now();
    setTimeout(function () {
      if (performance.now() - lastMoveTime >= 90) resetAll();
    }, 100);
  }

  function resetAll() {
    if (tiltEl) { tiltEl.style.setProperty('--rx', '0deg'); tiltEl.style.setProperty('--ry', '0deg'); tiltEl = null; }
    if (magEl) { magEl.style.setProperty('--mx', '0px'); magEl.style.setProperty('--my', '0px'); magEl = null; }
    for (var i = 0; i < dodgeEls.length; i++) {
      dodgeEls[i].style.setProperty('--dx', '0px');
      dodgeEls[i].style.setProperty('--dy', '0px');
      dodgeEls[i].style.setProperty('--ds', '1');
    }
  }

  function cleanup() {
    window.removeEventListener('pointermove', onMove);
    document.removeEventListener('pointerleave', resetAll);
    window.removeEventListener('blur', resetAll);
    resetAll();
  }

  window.addEventListener('pointermove', onMove, { passive: true });
  document.addEventListener('pointerleave', resetAll);
  window.addEventListener('blur', resetAll);
  window.addEventListener('scroll', function () {
    if (tiltEl) { tiltEl.style.setProperty('--rx', '0deg'); tiltEl.style.setProperty('--ry', '0deg'); tiltEl = null; }
  }, { passive: true });
  window.addEventListener('beforeunload', cleanup);
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) resetAll();
  });
})();
