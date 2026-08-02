/* ======================================================================
   theme.js — Nivis 深浅主题切换（统一版）
   - 默认深色（首次访问无偏好时）
   - localStorage 持久化（key: vuln-theme）
   - 跨标签页/窗口实时同步（storage 事件）
   - 图标随主题切换（月/日），即时更新
   - 不再动态注入按钮：所有页面静态写好 <button id="theme-toggle">
   - 统一管理设置抽屉里的 [data-theme-btn] 选项
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
    return DARK;
  }

  /* ---- 早期执行（防 FOUC），可在 <head> 内联调用 ---- */
  window.initThemeEarly = function () {
    applyTheme(resolveInitial());
  };

  /* ---- 图标 ---- */
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

  /* ---- 切换主题：优先 View Transitions API，降级为瞬切 ---- */
  function doSwitch(next) {
    applyTheme(next);
    setStored(next);
    syncButton();
    syncDrawerOpts();
  }

  function switchTheme() {
    var next = currentTheme() === DARK ? LIGHT : DARK;
    document.body.classList.add('theme-transitioning');
    var done = function () {
      setTimeout(function () { document.body.classList.remove('theme-transitioning'); }, 600);
    };

    if (document.startViewTransition) {
      var transition = document.startViewTransition(function () { doSwitch(next); });
      if (transition && transition.finished) {
        transition.finished.then(done, done);
      } else {
        done();
      }
    } else {
      doSwitch(next);
      done();
    }
  }

  /* ---- 同步右上角按钮 ---- */
  function syncButton() {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    var t = currentTheme();
    btn.innerHTML = btnIcon(t);
    btn.setAttribute('aria-label', btnLabel(t));
    btn.title = btnLabel(t);
  }

  /* ---- 绑定右上角按钮（仅一次） ---- */
  function bindButton() {
    var btn = document.getElementById('theme-toggle');
    if (!btn || btn.__nivisBound) return;
    btn.__nivisBound = true;
    btn.addEventListener('click', switchTheme);
  }

  /* ---- 同步设置抽屉里的主题选项 ---- */
  function syncDrawerOpts() {
    var isDark = currentTheme() === DARK;
    document.querySelectorAll('[data-theme-btn]').forEach(function (b) {
      var v = b.getAttribute('data-theme-btn');
      var active = (v === DARK && isDark) || (v === LIGHT && !isDark);
      b.style.background = active ? 'var(--vuln-brand)' : 'transparent';
      b.style.color = active ? 'var(--vuln-brand-ink)' : 'var(--vuln-ink-2)';
    });
  }

  /* ---- 绑定设置抽屉主题选项（仅一次，带 View Transition 渐变） ---- */
  function bindDrawerOpts() {
    document.querySelectorAll('[data-theme-btn]').forEach(function (b) {
      if (b.__nivisBound) return;
      b.__nivisBound = true;
      b.addEventListener('click', function () {
        var v = b.getAttribute('data-theme-btn');
        var next = v === DARK ? DARK : LIGHT;
        if (next === currentTheme()) return; /* 相同主题不重复切换 */

        document.body.classList.add('theme-transitioning');
        var done = function () {
          setTimeout(function () { document.body.classList.remove('theme-transitioning'); }, 600);
        };

        if (document.startViewTransition) {
          var transition = document.startViewTransition(function () { doSwitch(next); });
          if (transition && transition.finished) {
            transition.finished.then(done, done);
          } else {
            done();
          }
        } else {
          doSwitch(next);
          done();
        }
      });
    });
  }

  /* ---- 初始化 ---- */
  function init() {
    bindButton();
    syncButton();
    bindDrawerOpts();
    syncDrawerOpts();
  }

  /* ---- 跨标签页同步 ---- */
  window.addEventListener('storage', function (e) {
    if (e.key === STORAGE_KEY && (e.newValue === DARK || e.newValue === LIGHT)) {
      applyTheme(e.newValue);
      syncButton();
      syncDrawerOpts();
    }
  });

  /* ---- 系统主题变化：仅当用户未显式设置时跟随 ---- */
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if (!getStored()) {
        applyTheme(resolveInitial());
        syncButton();
        syncDrawerOpts();
      }
    });
  }

  /* ---- DOM 就绪后绑定 ---- */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
