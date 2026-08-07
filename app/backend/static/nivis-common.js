/* ======================================================================
   nivis-common.js — Nivis 全站共享逻辑（4 个页面统一引用）
   内容：
     1. 工具函数：escapeHtml / normalizeRisk / riskWeight / riskBadge / relativeTime / setText / formatNumber
     2. 统一安全评分算法：calcSecurityScore（扣分制，0-100，全站唯一 score 来源）
     3. 后端健康检查：checkHealth（两步 /api/health/live → /api/health）
     4. 设置抽屉：injectSettingsDrawer + initSettingsDrawer（注入 HTML + 绑定事件）
   使用方式：在各页面 <body> 末尾引入 <script src="./nivis-common.js"></script>
   ====================================================================== */
(function () {
  'use strict';

  var HISTORY_KEY = 'vuln_scan_history';
  var MAX_HISTORY = 7;

  /* ====== 1. 工具函数 ====== */
  window.NivisUtil = {
    HISTORY_KEY: HISTORY_KEY,
    MAX_HISTORY: MAX_HISTORY,

    escapeHtml: function (str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },

    setText: function (id, val) {
      var el = document.getElementById(id);
      if (el) el.textContent = val;
    },

    formatNumber: function (n) {
      return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    normalizeRisk: function (level) {
      if (!level) return 'info';
      var s = String(level).toLowerCase().trim();
      if (s === 'critical' || s === '严重' || s === '危急' || s.indexOf('crit') !== -1) return 'critical';
      if (s === 'high' || s === '高危' || s === '高' || s.indexOf('high') !== -1) return 'high';
      if (s === 'medium' || s === '中危' || s === '中' || s === 'moderate' || s.indexOf('med') !== -1) return 'medium';
      if (s === 'low' || s === '低危' || s === '低' || s.indexOf('low') !== -1) return 'low';
      return 'info';
    },

    riskWeight: function (lvl) {
      if (lvl === 'critical') return 10;
      if (lvl === 'high') return 7;
      if (lvl === 'medium') return 5;
      if (lvl === 'low') return 2;
      return 1;
    },

    riskBadge: function (lvl) {
      if (lvl === 'critical') return { label: '严重', color: 'var(--vuln-state-error)' };
      if (lvl === 'high') return { label: '高危', color: 'var(--vuln-state-error)' };
      if (lvl === 'medium') return { label: '中危', color: 'var(--vuln-state-warning)' };
      if (lvl === 'low') return { label: '低危', color: 'var(--vuln-state-success)' };
      return { label: '信息', color: 'var(--vuln-state-info)' };
    },

    relativeTime: function (ts) {
      if (!ts) return '';
      var d = new Date(ts);
      if (isNaN(d.getTime())) return '';
      var diff = Date.now() - d.getTime();
      if (diff < 0) diff = 0;
      var sec = Math.floor(diff / 1000);
      if (sec < 60) return sec + ' 秒前';
      var min = Math.floor(sec / 60);
      if (min < 60) return min + ' 分钟前';
      var hr = Math.floor(min / 60);
      if (hr < 24) return hr + ' 小时前';
      var day = Math.floor(hr / 24);
      if (day < 30) return day + ' 天前';
      return d.toLocaleDateString('zh-CN');
    },

    getHistory: function () {
      try {
        var raw = localStorage.getItem(HISTORY_KEY);
        if (!raw) return [];
        var arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr : [];
      } catch (e) { return []; }
    },

    saveHistory: function (entry) {
      var hist = this.getHistory();
      hist.push(entry);
      hist.sort(function (a, b) { return new Date(a.date).getTime() - new Date(b.date).getTime(); });
      if (hist.length > MAX_HISTORY) hist = hist.slice(hist.length - MAX_HISTORY);
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(hist)); } catch (e) {}
    },

    /* 统计漏洞等级分布 */
    aggregateResults: function (results) {
      var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      if (!Array.isArray(results)) return counts;
      for (var i = 0; i < results.length; i++) {
        var r = results[i];
        if (!r || r.has_vulnerability !== true) continue;
        var lvl = this.normalizeRisk(r.risk_level);
        if (lvl === 'critical') counts.critical++;
        else if (lvl === 'high') counts.high++;
        else if (lvl === 'medium') counts.medium++;
        else if (lvl === 'low') counts.low++;
        else counts.info++;
      }
      return counts;
    },

    /* 趋势图交互：鼠标移动时显示平行于 y 轴的虚线，靠近数据点时吸附。
       config: { svg, points: [{x,y,data}], left, right, top, bottom, formatTip: fn(data)->string } */
    attachTrendHover: function (config) {
      var svg = config.svg;
      if (!svg || svg.__nivisHoverBound) return;
      svg.__nivisHoverBound = true;
      var SVG_NS = 'http://www.w3.org/2000/svg';
      var points = config.points || [];
      var left = config.left, right = config.right, top = config.top, bottom = config.bottom;
      var formatTip = config.formatTip || function (d) { return ''; };

      // 创建交互层（一个 <g> 容器，pointer-events: none，不干扰已有元素）
      var layer = document.createElementNS(SVG_NS, 'g');
      layer.setAttribute('pointer-events', 'none');
      layer.style.pointerEvents = 'none';

      var guideLine = document.createElementNS(SVG_NS, 'line');
      guideLine.setAttribute('stroke', 'var(--vuln-ink-3)');
      guideLine.setAttribute('stroke-width', '1.5');
      guideLine.setAttribute('stroke-dasharray', '4 4');
      guideLine.setAttribute('opacity', '0');
      guideLine.setAttribute('y1', top);
      guideLine.setAttribute('y2', bottom);
      layer.appendChild(guideLine);

      var tipRect = document.createElementNS(SVG_NS, 'rect');
      tipRect.setAttribute('fill', 'var(--vuln-surface)');
      tipRect.setAttribute('stroke', 'var(--vuln-line)');
      tipRect.setAttribute('rx', '6');
      tipRect.setAttribute('opacity', '0');
      layer.appendChild(tipRect);

      var tipText = document.createElementNS(SVG_NS, 'text');
      tipText.setAttribute('fill', 'var(--vuln-ink)');
      tipText.setAttribute('font-size', '12');
      tipText.setAttribute('opacity', '0');
      layer.appendChild(tipText);

      svg.appendChild(layer);

      // 用 createSVGPoint + getScreenCTM 做坐标转换，Chrome/Firefox/Safari 都可靠
      function clientToSvgX(clientX) {
        var pt = svg.createSVGPoint();
        pt.x = clientX;
        pt.y = 0;
        var ctm = svg.getScreenCTM();
        if (!ctm) {
          // 回退：用 viewBox 比例计算
          var rect = svg.getBoundingClientRect();
          var vb = svg.viewBox.baseVal;
          if (!vb || vb.width === 0) return clientX - rect.left;
          return (clientX - rect.left) / rect.width * vb.width;
        }
        var svgPt = pt.matrixTransform(ctm.inverse());
        return svgPt.x;
      }

      function showTip(x, content) {
        tipText.textContent = content;
        tipText.setAttribute('opacity', '1');
        tipText.setAttribute('text-anchor', 'middle');
        // 估算文字宽度（中文约 12px/字，英文约 7px/字，取折中）
        var tw = content.length * 9 + 16;
        tipRect.setAttribute('width', tw);
        tipRect.setAttribute('height', '22');
        tipRect.setAttribute('x', x - tw / 2);
        tipRect.setAttribute('y', top - 26);
        tipRect.setAttribute('opacity', '1');
        tipText.setAttribute('x', x);
        tipText.setAttribute('y', top - 11);
      }
      function hideAll() {
        guideLine.setAttribute('opacity', '0');
        tipRect.setAttribute('opacity', '0');
        tipText.setAttribute('opacity', '0');
      }

      svg.addEventListener('mousemove', function (e) {
        var mx = clientToSvgX(e.clientX);
        if (mx < left || mx > right) { hideAll(); return; }
        // 找最近的数据点（X 方向），仅在非常接近时吸附，避免点稀疏时全屏瞬移
        var nearest = null, minDist = Infinity;
        for (var i = 0; i < points.length; i++) {
          if (points[i] == null) continue;
          var d = Math.abs(points[i].x - mx);
          if (d < minDist) { minDist = d; nearest = points[i]; }
        }
        var stepX = points.length > 1 ? (right - left) / (points.length - 1) : 0;
        // 吸附阈值上限 30 SVG 单位：点稀疏时虚线仍能跟随鼠标，点密集时按 stepX*0.4 吸附
        var snapDist = Math.min(stepX * 0.4, 30);
        var snapX;
        if (nearest && minDist < snapDist) {
          snapX = nearest.x;
        } else {
          snapX = Math.max(left, Math.min(right, mx));
        }
        guideLine.setAttribute('x1', snapX);
        guideLine.setAttribute('x2', snapX);
        guideLine.setAttribute('opacity', '0.7');
        if (nearest && minDist < snapDist) {
          showTip(snapX, formatTip(nearest.data));
        } else {
          tipRect.setAttribute('opacity', '0');
          tipText.setAttribute('opacity', '0');
        }
      });
      svg.addEventListener('mouseleave', hideAll);
    }
  };

  /* ====== 2. 统一安全评分算法（扣分制，0-100） ====== */
  /* 全站唯一 score 计算入口：scan.html 和 posture.html 共用。
     语义：100 = 无漏洞（满分安全），每发现一个漏洞按等级扣分。
     取代 scan.html 旧有的风险密度算法（sum/total × 10）。 */
  window.calcSecurityScore = function (counts) {
    var score = 100;
    score -= (counts.critical + counts.high) * 8;
    score -= counts.medium * 4;
    score -= counts.low * 2;
    score -= counts.info * 0.5;
    return Math.max(0, Math.min(100, Math.round(score)));
  };

  /* ====== 3. 后端健康检查（两步：/api/health/live → /api/health） ====== */
  /* 用法：NivisHealth.check(function(level, label){ ... })
     level: ok / warn / err / loading
     返回 AbortController 供页面切换时中止。 */
  window.NivisHealth = {
    _ctrl: null,

    check: function (onUpdate) {
      var self = this;
      var set = function (level, text) {
        var el = document.getElementById('health-indicator');
        if (!el) return;
        el.innerHTML = '<span class="health-dot is-' + level + '"></span><span class="health-text">' + window.NivisUtil.escapeHtml(text) + '</span>';
        if (onUpdate) onUpdate(level, text);
      };
      var isJson = function (r) {
        var ct = r.headers.get('content-type') || '';
        return r.ok && ct.indexOf('application/json') !== -1;
      };

      if (self._ctrl) { try { self._ctrl.abort(); } catch (e) {} }
      self._ctrl = new AbortController();
      var signal = self._ctrl.signal;
      set('loading', '检测中');

      fetch('/api/health/live', { signal: signal })
        .then(function (rl) { return isJson(rl) ? rl.json() : null; })
        .then(function (live) {
          if (!live || !live.status) throw new Error('响应无效');
          set('loading', '后端已连接 · 检测引擎…');
          return fetch('/api/health', { signal: signal })
            .then(function (rh) { return isJson(rh) ? rh.json() : null; })
            .then(function (h) {
              if (!h) { set('warn', '后端已连接 · 引擎检测失败'); return; }
              if (h.ollama_connected || h.vllm_connected) {
                var m = h.model || (h.vllm_connected ? 'vLLM' : 'unknown');
                set('ok', '后端已连接 · 引擎就绪 · ' + m);
              } else {
                set('warn', '后端已连接 · 引擎未就绪');
              }
            });
        })
        .catch(function (e) {
          if (e && e.name === 'AbortError') return;
          set('err', '后端未连接 · 请启动后端脚本');
        });

      return self._ctrl;
    },

    abort: function () {
      if (this._ctrl) { try { this._ctrl.abort(); } catch (e) {} this._ctrl = null; }
    }
  };

  /* ====== 4. 设置抽屉（注入 HTML + 绑定事件） ====== */
  /* 各页面只需在 <body> 中保留 <button id="settings-open">，
     nivis-common.js 会自动注入抽屉 HTML 并绑定所有事件。 */

  var DRAWER_HTML = '\
    <div id="settings-overlay" class="fixed inset-0 z-[60] hidden" style="background: rgba(0,0,0,0.4); backdrop-filter: blur(2px);">\
      <aside id="settings-drawer" class="absolute right-0 top-0 bottom-0 w-full sm:w-[400px] flex flex-col" style="background: var(--vuln-surface); border-left: 1px solid var(--vuln-line); transform: translateX(100%); transition: transform 300ms cubic-bezier(0.4,0,0.2,1);">\
        <div class="flex items-center justify-between px-6 py-4 border-b" style="border-color: var(--vuln-line);">\
          <h2 class="text-base font-semibold" style="color: var(--vuln-ink)">设置</h2>\
          <button id="settings-close" class="inline-flex items-center justify-center w-8 h-8 rounded-md hover:bg-[var(--vuln-surface-2)] text-muted-foreground hover:text-foreground transition-colors" aria-label="关闭">\
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>\
          </button>\
        </div>\
        <div class="flex-1 overflow-y-auto px-6 py-5 space-y-8">\
          <section>\
            <h3 class="text-xs font-semibold uppercase tracking-wider mb-3" style="color: var(--vuln-ink-3)">外观</h3>\
            <div class="space-y-2">\
              <div class="flex items-center justify-between p-3 rounded-lg" style="background: var(--vuln-surface-2);">\
                <div>\
                  <div class="text-sm font-medium" style="color: var(--vuln-ink)">主题模式</div>\
                  <div class="text-xs mt-0.5" style="color: var(--vuln-ink-3)">选择界面配色</div>\
                </div>\
                <div class="flex gap-1 p-1 rounded-md" style="background: var(--vuln-bg); border: 1px solid var(--vuln-line);">\
                  <button data-theme-btn="light" class="theme-opt px-3 py-1 text-xs rounded transition-colors">浅色</button>\
                  <button data-theme-btn="dark" class="theme-opt px-3 py-1 text-xs rounded transition-colors">深色</button>\
                </div>\
              </div>\
            </div>\
          </section>\
          <section>\
            <h3 class="text-xs font-semibold uppercase tracking-wider mb-3" style="color: var(--vuln-ink-3)">连接</h3>\
            <div class="space-y-2">\
              <div class="flex items-center justify-between p-3 rounded-lg" style="background: var(--vuln-surface-2);">\
                <div>\
                  <div class="text-sm font-medium" style="color: var(--vuln-ink)">后端地址与模型</div>\
                  <div class="text-xs mt-0.5" style="color: var(--vuln-ink-3)">由启动器自动检测与配置，前端不可更改</div>\
                </div>\
                <a href="https://ollama.com/download" target="_blank" rel="noopener" class="text-xs px-3 py-1 rounded-md transition-colors" style="background: var(--vuln-surface-3); color: var(--vuln-ink-2); text-decoration: none;">Ollama</a>\
              </div>\
            </div>\
          </section>\
          <section>\
            <h3 class="text-xs font-semibold uppercase tracking-wider mb-3" style="color: var(--vuln-ink-3)">关于 Nivis</h3>\
            <div class="flex items-center gap-3 mb-4 p-3 rounded-lg" style="background: color-mix(in srgb, var(--vuln-brand) 6%, transparent); border: 1px solid color-mix(in srgb, var(--vuln-brand) 15%, var(--vuln-line));">\
              <span class="nivis-logo" aria-hidden="true">\
                <img src="./logo/图标logo.png" class="logo-light" alt="" width="36" height="36">\
                <img src="./logo/图标logo深色版.png" class="logo-dark" alt="" width="36" height="36">\
              </span>\
              <div>\
                <div class="text-base font-semibold" style="color: var(--vuln-ink)">Nivis</div>\
                <div class="text-xs" style="color: var(--vuln-ink-3)">版本 2.0.0</div>\
              </div>\
            </div>\
            <p class="text-sm leading-relaxed mb-4" style="color: var(--vuln-ink-2)">\
              Nivis 是一款本地部署的 AI 代码漏洞静态分析平台。基于 <span class="font-mono text-xs px-1 py-0.5 rounded" style="background: var(--vuln-surface-2); color: var(--vuln-brand)">Qwen3-8B</span> 多轮微调的安全分析模型，结合静态规则引擎，识别 SQL 注入、XSS、命令注入、路径穿越、反序列化等常见安全漏洞。所有分析在本地完成，代码不上传云端。\
            </p>\
            <div class="space-y-2">\
              <div class="text-xs font-semibold mb-2" style="color: var(--vuln-ink)">使用指南</div>\
              <ol class="space-y-2 text-sm" style="color: var(--vuln-ink-2)">\
                <li class="flex gap-2.5"><span class="flex-shrink-0 w-5 h-5 inline-flex items-center justify-center rounded-full text-[10px] font-bold" style="background: color-mix(in srgb, var(--vuln-brand) 12%, transparent); color: var(--vuln-brand)">1</span>在「扫描工作台」选择输入方式：粘贴代码片段、上传文件或接入仓库</li>\
                <li class="flex gap-2.5"><span class="flex-shrink-0 w-5 h-5 inline-flex items-center justify-center rounded-full text-[10px] font-bold" style="background: color-mix(in srgb, var(--vuln-brand) 12%, transparent); color: var(--vuln-brand)">2</span>点击「开始扫描」，等待 AI 分析完成</li>\
                <li class="flex gap-2.5"><span class="flex-shrink-0 w-5 h-5 inline-flex items-center justify-center rounded-full text-[10px] font-bold" style="background: color-mix(in srgb, var(--vuln-brand) 12%, transparent); color: var(--vuln-brand)">3</span>查看漏洞详情、风险等级与修复建议</li>\
                <li class="flex gap-2.5"><span class="flex-shrink-0 w-5 h-5 inline-flex items-center justify-center rounded-full text-[10px] font-bold" style="background: color-mix(in srgb, var(--vuln-brand) 12%, transparent); color: var(--vuln-brand)">4</span>在「仪表盘」追踪扫描活动趋势，在「安全态势」查看整体评分</li>\
              </ol>\
            </div>\
          </section>\
        </div>\
        <div class="px-6 py-3 border-t text-xs text-center" style="border-color: var(--vuln-line); color: var(--vuln-ink-3)">\
          2.0.0 · 本地优先 · 数据不出境\
        </div>\
      </aside>\
    </div>';

  window.NivisSettings = {
    _bound: false,

    /* 注入抽屉 HTML（若页面已有则跳过） */
    inject: function () {
      if (document.getElementById('settings-overlay')) return;
      var div = document.createElement('div');
      div.innerHTML = DRAWER_HTML;
      var overlay = div.firstElementChild;
      if (overlay) document.body.appendChild(overlay);
    },

    /* 绑定 open/close/escape/save 事件（仅一次） */
    init: function () {
      if (this._bound) return;
      this._bound = true;
      var self = this;
      var overlay, drawer, btnOpen, btnClose;
      var opened = false;
      var closeTimer = null;   /* 保存 close 的隐藏延时句柄，open 时清掉，避免"关→快开"被残留定时器隐藏 */

      function ensureRefs() {
        overlay = document.getElementById('settings-overlay');
        drawer = document.getElementById('settings-drawer');
        btnOpen = document.getElementById('settings-open');
        btnClose = document.getElementById('settings-close');
      }

      function open() {
        ensureRefs();
        if (!overlay || opened) return;
        opened = true;
        if (closeTimer) { clearTimeout(closeTimer); closeTimer = null; }  /* 取消尚未执行的隐藏 */
        overlay.classList.remove('hidden');
        // 主题选项的高亮由 theme.js 的 syncDrawerOpts() 负责，这里不重复同步
        if (window.syncDrawerOpts) window.syncDrawerOpts();
        requestAnimationFrame(function () { if (drawer) drawer.style.transform = 'translateX(0)'; });
        document.body.style.overflow = 'hidden';
      }

      function close() {
        ensureRefs();
        if (!overlay || !opened) return;
        opened = false;
        if (drawer) drawer.style.transform = 'translateX(100%)';
        document.body.style.overflow = '';
        if (closeTimer) clearTimeout(closeTimer);
        closeTimer = setTimeout(function () {
          overlay.classList.add('hidden');
          closeTimer = null;
        }, 300);
      }

      /* 延迟绑定：等 DOM 中存在按钮后再绑 */
      function tryBind() {
        ensureRefs();
        if (btnOpen && !btnOpen.__nivisSettingsBound) {
          btnOpen.__nivisSettingsBound = true;
          btnOpen.addEventListener('click', open);
        }
        if (btnClose && !btnClose.__nivisSettingsBound) {
          btnClose.__nivisSettingsBound = true;
          btnClose.addEventListener('click', close);
        }
        if (overlay && !overlay.__nivisSettingsBound) {
          overlay.__nivisSettingsBound = true;
          overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
        }
      }

      /* 保存按钮逻辑已移除：后端地址与模型由启动器配置，前端 localStorage 中的值不会被任何代码读取 */

      document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });

      /* 立即尝试绑定，同时监听 DOM 变化 */
      tryBind();
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', tryBind);
      }

      /* 暴露 open/close 供外部调用 */
      self.open = open;
      self.close = close;
    }
  };

  /* 自动注入 + 初始化 */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      window.NivisSettings.inject();
      window.NivisSettings.init();
    });
  } else {
    window.NivisSettings.inject();
    window.NivisSettings.init();
  }
})();
