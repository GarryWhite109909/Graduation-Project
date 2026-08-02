/* ======================================================================
   lively.js — 克制版（Nivis）
   不启用 3D 倾斜 / 磁吸 / 避开 / 浮动等指针跟踪动效。
   hover 时的「不生硬」由 lively.css 的 :hover 过渡负责
   （translateY 微抬升 + 边框色渐变 + 阴影），无需 JS 介入。
   保留 refreshLively 全局接口供各页面调用，仅做空操作。
   ====================================================================== */
(function () {
  'use strict';
  window.refreshLively = function () { /* no-op */ };
  window.refreshLivelyDodge = function () { /* no-op */ };
})();
