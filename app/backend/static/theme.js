/* ======================================================================
   theme.js — 深浅主题切换
   - 默认深色（首次访问无偏好时）
   - localStorage 持久化（key: vuln-theme）
   - 跨标签页/窗口实时同步（storage 事件）
   - 尊重系统 prefers-color-scheme（仅首次访问时作默认参考）
   - 在导航栏注入切换按钮，图标随主题切换（月/日）
   - 为避免 FOUC（首屏闪烁），在 <head> 内尽早调用 initThemeEarly()
   ====================================================================== */
(function () {
  'use strict';

  var STORAGE_KEY = 'vuln-theme';
  var DARK = 'dark';
  var LIGHT = 'light';

  /* ---- 工具 ---- */
  function getStored() {
    try { return localStorage.getItem(STORAGE_KEY); } catch (e) { return null; }
  }
  function setStored(v) {
    try { localStorage.setItem(STORAGE_KEY, v); } catch (e) {}
  }
  function applyTheme(theme) {
    var root = document.documentElement;
    root.classList.remove(LIGHT, DARK);
    root.classList.add(theme);
  }
  function currentTheme() {
    return document.documentElement.classList.contains(DARK) ? DARK : LIGHT;
  }
  function resolveInitial() {
    var s = getStored();
    if (s === DARK || s === LIGHT) return s;
    // 无存储：默认深色（产品默认）。如需跟随系统，取消下行注释。
    // if (window.matchMedia('(prefers-color-scheme: light)').matches) return LIGHT;
    return DARK;
  }

  /* ---- 早期执行（防 FOUC），可在 <head> 内联调用 ---- */
  window.initThemeEarly = function () {
    applyTheme(resolveInitial());
  };

  /* ---- 按钮注入 + 交互 ---- */
  var ICON_SUN =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<circle cx="12" cy="12" r="4"/>' +
    '<path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>' +
    '</svg>';
  var ICON_MOON =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>' +
    '</svg>';

  function btnIcon(theme) {
    return theme === DARK ? ICON_SUN : ICON_MOON; // 深色时显示太阳（点击转浅）
  }
  function btnLabel(theme) {
    return theme === DARK ? '切换到浅色模式' : '切换到深色模式';
  }

  /* ---- 切换主题：优先 View Transitions API（整页 cross-fade），降级为瞬切 ---- */
  function doSwitch(next) {
    applyTheme(next);
    setStored(next);
    syncButton();
  }

  function switchTheme() {
    var next = currentTheme() === DARK ? LIGHT : DARK;
    // 标记过渡中，供 CSS 用更慢的 transition
    document.body.classList.add('theme-transitioning');
    var done = function () {
      // 过渡结束后清理标记
      setTimeout(function () { document.body.classList.remove('theme-transitioning'); }, 600);
    };

    if (document.startViewTransition) {
      // 现代浏览器：整页快照 cross-fade，玻璃/背景平滑过渡
      var transition = document.startViewTransition(function () { doSwitch(next); });
      if (transition && transition.finished) {
        transition.finished.then(done, done);
      } else {
        done();
      }
    } else {
      // 降级：直接切换，靠 CSS transition 平滑
      doSwitch(next);
      done();
    }
  }

  function buildButton() {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.id = 'theme-toggle';
    btn.setAttribute('aria-label', btnLabel(currentTheme()));
    btn.title = btnLabel(currentTheme());
    btn.className = 'theme-toggle-btn';
    btn.innerHTML = btnIcon(currentTheme());
    btn.addEventListener('click', switchTheme);
    return btn;
  }

  function syncButton() {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    var t = currentTheme();
    btn.innerHTML = btnIcon(t);
    btn.setAttribute('aria-label', btnLabel(t));
    btn.title = btnLabel(t);
  }

  function inject() {
    if (document.getElementById('theme-toggle')) { syncButton(); return; }
    // 优先插到主导航 ul 之后；找不到则回退到 body
    var nav = document.querySelector('nav.nav-glass, nav[aria-label="主导航"]');
    var container = nav ? nav.querySelector('.flex.items-center.justify-between') : null;
    if (container) {
      var btn = buildButton();
      // 放到容器末尾（导航链接之后）
      container.appendChild(btn);
    } else {
      document.body.appendChild(buildButton());
    }
  }

  /* ---- 跨标签页同步 ---- */
  window.addEventListener('storage', function (e) {
    if (e.key === STORAGE_KEY && (e.newValue === DARK || e.newValue === LIGHT)) {
      applyTheme(e.newValue);
      syncButton();
    }
  });

  /* ---- 系统主题变化：仅当用户未显式设置时跟随 ---- */
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if (!getStored()) {
        applyTheme(resolveInitial());
        syncButton();
      }
    });
  }

  /* ---- DOM 就绪后注入按钮 ---- */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }

  // 捕获动态重渲染的导航（部分页面会重写 nav）
  var mo = new MutationObserver(function () {
    if (!document.getElementById('theme-toggle')) inject();
  });
  if (document.body) mo.observe(document.body, { childList: true, subtree: true });
})();
