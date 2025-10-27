/* ========================================================================
   DASHBOARD
   - Presets: Today / Last 7 Days / Last 30 Days / By Month (+ "All Months")
   - Default preset everywhere: TODAY
   - KPI filter is GLOBAL -> broadcasts to all breakdown cards
   - Breakdown filters are LOCAL-ONLY -> do NOT broadcast; don't affect KPI/others
   - Compat: KPI also emits legacy 'dashboardFilterChange' (guarded with source:'kpi')
   ======================================================================== */


/* =============== tiny style helper: rounded/pill selects =============== */
(function injectPillCSS(){
  if (!document.getElementById('pillCSS')) {
    const css = `
      .form-control.form-control-sm.pill{
        border-radius: 16px !important;
        padding: 0 .6rem !important;
      }
      .header-controls .form-control.form-control-sm{ height: 34px; }
    `;
    const s = document.createElement('style');
    s.id = 'pillCSS';
    s.textContent = css;
    document.head.appendChild(s);
  }
})();


/* ===================== Helpers (shared) ===================== */
(function(){
  window._dashHelpers = {
    peso(n){
      const v = Number(n) || 0;
      return v < 0 ? `-₱${Math.abs(v).toLocaleString()}` : `₱${v.toLocaleString()}`;
    },
    
    // Month/year options + "All Months"
    ensureMonthYearOptions($monthSel, $yearSel){
      if ($monthSel.length && $monthSel.children().length === 0) {
        $monthSel.append(`<option value="all">All Months</option>`);
        const months = [
          'January','February','March','April','May','June',
          'July','August','September','October','November','December'
        ];
        months.forEach((name, idx) => $monthSel.append(`<option value="${idx}">${name}</option>`));
      }
      if ($yearSel.length && $yearSel.children().length === 0) {
        const nowY = new Date().getFullYear();
        for (let yy = nowY; yy >= nowY - 7; yy--) $yearSel.append(`<option value="${yy}">${yy}</option>`);
      }
      const now = new Date();
      if ($monthSel.length && $monthSel.prop('selectedIndex') === -1) $monthSel.val('all');
      if ($yearSel.length && $yearSel.prop('selectedIndex') === -1) $yearSel.val(String(now.getFullYear()));
    },
    // Unified preset options (default TODAY)
    applyUnifiedPresetOptions($sel, selectedValue){
      const html = [
        `<option value="today">Today</option>`,
        `<option value="7d">Last 7 Days</option>`,
        `<option value="30d">Last 30 Days</option>`,
        `<option value="monthpick">By Month</option>`
      ].join('');
      $sel.html(html);
      const toSet = (selectedValue && ['today','7d','30d','monthpick'].includes(selectedValue))
        ? selectedValue : 'today';
      $sel.val(toSet);
    },

    ensureMonthYearForCard(presetSelector, idPrefix){
      const $preset = $(presetSelector);
      const $container = $preset.closest('.header-controls');
      if (!$container.length) return { $m: $(), $y: $() };

      let $m = $container.find(`#${idPrefix}Month`);
      let $y = $container.find(`#${idPrefix}Year`);

      if ($m.length === 0) {
        $m = $(`<select id="${idPrefix}Month" class="form-control form-control-sm mr-2 pill" style="display:none; min-width:130px;"></select>`);
        $container.append($m);
      }
      if ($y.length === 0) {
        $y = $(`<select id="${idPrefix}Year" class="form-control form-control-sm pill" style="display:none; min-width:110px;"></select>`);
        $container.append($y);
      }
      window._dashHelpers.ensureMonthYearOptions($m, $y);
      return { $m, $y };
    },

    toggleMonthYearUI(presetVal, $m, $y){
      if (presetVal === 'monthpick') { $m.show(); $y.show(); }
      else { $m.hide(); $y.hide(); }
    },

    // ---- API helpers (return Promises, handle "All Months") ----
    getSalesData(preset, month, year){
      if (preset === 'monthpick' && String(month) === 'all') {
        const calls = [];
        for (let m = 0; m < 12; m++) calls.push($.getJSON('/admin/sales-breakdown', { preset: 'monthpick', month: m, year }));
        return Promise.all(calls).then(arr => {
          const norm = s => String(s||'').trim().toLowerCase().replace(/\s+/g,' ');
          const prodMap = new Map(); // key: name|unit
          const svcMap  = new Map(); // key: name|fee
          let productsSubtotal = 0, servicesSubtotal = 0;

          arr.forEach(d => {
            (d.products||[]).forEach(r => {
              const key = `${norm(r.name)}|${Number(r.unitPrice||0)}`;
              if (!prodMap.has(key)) prodMap.set(key, { name: r.name, qty: 0, unitPrice: Number(r.unitPrice||0), total: 0 });
              const row = prodMap.get(key);
              row.qty += Number(r.qty||0);
              row.total += Number(r.total||0);
            });
            (d.services||[]).forEach(r => {
              const key = `${norm(r.name)}|${Number(r.fee||0)}`;
              if (!svcMap.has(key)) svcMap.set(key, { name: r.name, count: 0, fee: Number(r.fee||0), total: 0 });
              const row = svcMap.get(key);
              row.count += Number(r.count||0);
              row.total += Number(r.total||0);
            });
            productsSubtotal += Number(d.productsSubtotal||0);
            servicesSubtotal += Number(d.servicesSubtotal||0);
          });

          const products = [...prodMap.values()].sort((a,b)=>b.total-a.total);
          const services = [...svcMap.values()].sort((a,b)=>b.total-a.total);
          return {
            products, services,
            productsSubtotal, servicesSubtotal,
            grandTotal: productsSubtotal + servicesSubtotal
          };
        });
      }
      const params = (preset === 'monthpick') ? { preset, month, year } : { preset };
      return $.getJSON('/admin/sales-breakdown', params);
    },

    getCopData(preset, month, year){
      if (preset === 'monthpick' && String(month) === 'all') {
        const calls = [];
        for (let m = 0; m < 12; m++) calls.push($.getJSON('/admin/cop-breakdown', { preset: 'monthpick', month: m, year }));
        return Promise.all(calls).then(arr => {
          const norm = s => String(s||'').trim().toLowerCase().replace(/\s+/g,' ');
          const prodMap = new Map(); // key: name|purchase
          const expMap  = new Map(); // key: name|purchase
          let productsSubtotal = 0, expiredSubtotal = 0;

          arr.forEach(d => {
            (d.products||[]).forEach(r => {
              const key = `${norm(r.name)}|${Number(r.purchase||0)}`;
              if (!prodMap.has(key)) prodMap.set(key, { name: r.name, qty: 0, purchase: Number(r.purchase||0), total: 0 });
              const row = prodMap.get(key);
              row.qty += Number(r.qty||0);
              row.total += Number(r.total||0);
            });
            (d.expired||[]).forEach(r => {
              const key = `${norm(r.name)}|${Number(r.purchase||0)}`;
              if (!expMap.has(key)) expMap.set(key, { name: r.name, qty: 0, purchase: Number(r.purchase||0), total: 0 });
              const row = expMap.get(key);
              row.qty += Number(r.qty||0);
              row.total += Number(r.total||0);
            });
            productsSubtotal += Number(d.productsSubtotal||0);
            expiredSubtotal  += Number(d.expiredSubtotal||0);
          });

          const products = [...prodMap.values()].sort((a,b)=>b.total-a.total);
          const expired  = [...expMap.values()].sort((a,b)=>b.total-a.total);
          return {
            products, expired,
            productsSubtotal, expiredSubtotal,
            grandTotal: productsSubtotal + expiredSubtotal
          };
        });
      }
      const params = (preset === 'monthpick') ? { preset, month, year } : { preset };
      return $.getJSON('/admin/cop-breakdown', params);
    },

    getCosData(preset, month, year){
      if (preset === 'monthpick' && String(month) === 'all') {
        const calls = [];
        for (let m = 0; m < 12; m++) calls.push($.getJSON('/admin/cos-breakdown', { preset: 'monthpick', month: m, year }));
        return Promise.all(calls).then(arr => {
          const norm = s => String(s||'').trim().toLowerCase().replace(/\s+/g,' ');
          const svcMap = new Map(); // key: name|purchase
          let servicesTotal = 0;

          arr.forEach(d => {
            (d.services||[]).forEach(r => {
              const key = `${norm(r.name)}|${Number(r.purchase||0)}`;
              if (!svcMap.has(key)) svcMap.set(key, { name: r.name, purchase: Number(r.purchase||0), total: 0 });
              const row = svcMap.get(key);
              row.total += Number(r.total||0);
            });
            servicesTotal += Number(d.servicesTotal||0);
          });

          const services = [...svcMap.values()].sort((a,b)=>b.total-a.total);
          return { services, servicesTotal };
        });
      }
      const params = (preset === 'monthpick') ? { preset, month, year } : { preset };
      return $.getJSON('/admin/cos-breakdown', params);
    },

    getOpexData(preset, month, year){
      if (preset === 'monthpick' && String(month) === 'all') {
        return $.getJSON('/admin/opex-breakdown', { preset: 'year', year });
      }
      const mapped = (preset === 'monthpick') ? 'month' : preset;
      const params = (mapped === 'month') ? { preset: 'month', month, year } : { preset: mapped };
      return $.getJSON('/admin/opex-breakdown', params);
    },
     // ==== Chart width helper: makes chart horizontally scroll when many categories ====
    ensureChartScrollable(el, categoriesCount, perBarPx = 80, minWidthPx = 700){
      if (!el) return null;

      // Make sure the chart is inside a scroll wrapper (.chart-x-scroll)
      const parent = el.parentElement;
      if (!parent || !parent.classList.contains('chart-x-scroll')) {
        // If template wrapping was missed, wrap dynamically
        const wrap = document.createElement('div');
        wrap.className = 'chart-x-scroll';
        wrap.style.overflowX = 'auto';
        wrap.style.width = '100%';
        if (el.parentNode) {
          el.parentNode.insertBefore(wrap, el);
          wrap.appendChild(el);
        }
      }

      const wrapper = el.parentElement;
      const wrapperWidth = wrapper ? (wrapper.clientWidth || 800) : 800;

      // Desired width = perBar * count, clamped to at least wrapper width & minWidth
      const desired = Math.max(wrapperWidth, minWidthPx, Math.round((categoriesCount || 0) * perBarPx));

      // Apply width on the chart container so wrapper can scroll
      el.style.width = desired + 'px';

      return desired;
    },
    bindChartResize(el, getCategoryCount, applyWidth, perBarPx = 90, minWidthPx = 720){
  if (!el) return;

  const doResize = () => {
    const count = Math.max(0, Number(typeof getCategoryCount === 'function' ? getCategoryCount() : 0));
    const newW = window._dashHelpers.ensureChartScrollable(el, count, perBarPx, minWidthPx);
    if (typeof applyWidth === 'function') applyWidth(newW);
  };

  // cleanup old observer if any (avoids duplicates)
  if (el._chartResizeCleanup) try { el._chartResizeCleanup(); } catch {}

  const target = el.parentElement || el;
  const ro = new ResizeObserver(() => doResize());
  if (target) ro.observe(target);

  const onWin = () => doResize();
  window.addEventListener('resize', onWin);

  // first run
  setTimeout(doResize, 0);

  el._chartResizeCleanup = () => {
    try { ro.disconnect(); } catch {}
    window.removeEventListener('resize', onWin);
  };
}

    
  };
})();



/* ===================== Sales Breakdown (LOCAL-ONLY) ===================== */
/* ===================== Sales Breakdown (LOCAL-ONLY) ===================== */
(function(){
  const GLOBAL_EVT = 'kpiFilterChange';
  const LEGACY_EVT = 'dashboardFilterChange';

  const $preset = $('#salesTrendPreset');
  const $m = $('#trendMonth');
  const $y = $('#trendYear');

  // DEFAULT TODAY
  (function initSalesPreset(){
    window._dashHelpers.applyUnifiedPresetOptions($preset);
    $preset.addClass('pill'); $m.addClass('pill'); $y.addClass('pill');
  })();

  function toggleMonthPickUI(){
    window._dashHelpers.toggleMonthYearUI($preset.val(), $m, $y);
  }

 function setScrollableIfNeeded($tbody){
  const rows = $tbody.find('tr').length;
  if (rows >= 5) $tbody.addClass('scrollable-body');
  else $tbody.removeClass('scrollable-body');
}

  // ------- Chart -------
  let salesChart = null;
  function renderSalesChart(data){
    const el = document.querySelector('#salesTrendChart');
    if (!el) return;

    const prods = (data.products || []).map(r => ({ name: r.name, p: r.total || 0, s: 0 }));
    const svcs  = (data.services || []).map(r => ({ name: r.name, p: 0, s: r.total || 0 }));
    const byName = new Map();

    [...prods, ...svcs].forEach(x => {
      const key = String(x.name || '').trim();
      if (!byName.has(key)) byName.set(key, { name: key, p: 0, s: 0 });
      const row = byName.get(key);
      row.p += x.p; row.s += x.s;
    });

    const top = [...byName.values()]
      .map(r => ({ ...r, total: r.p + r.s }))
      .sort((a,b) => b.total - a.total)
      .slice(0, 10);

    const categories = top.map(r => r.name);
   const prodData = top.map(r => (r.p > 0 ? r.p : null));
const svcData  = top.map(r => (r.s > 0 ? r.s : null));
const series = [
  { name: 'Products', data: prodData },
  { name: 'Services', data: svcData }
];

// Make chart horizontally scroll when many columns
const width = window._dashHelpers.ensureChartScrollable(el, categories.length, 90, 720);

    const showLabels = categories.length <= 10;

const opts = {
  chart: { type: 'bar', height: 320, width, toolbar: { show: false },   zoom: { enabled: false },
    redrawOnParentResize: true   },
  series,
  xaxis: {
    categories,
    tickPlacement: 'on',                // label centered under bar
    labels: {
      rotate: 0,                        // no slant
      trim: true,
      hideOverlappingLabels: true,
      style: { fontSize: '12px' }
    }
  },
  yaxis: { labels: { formatter: v => Number(v||0).toLocaleString() } },
  colors: ['#008FFB', '#FEB019'],
  plotOptions: { bar: { horizontal: false, columnWidth: '45%', dataLabels: { position: 'top' } } },
dataLabels: {
  enabled: categories.length <= 10,
  offsetY: -20,
  style: { colors: ['#222'], fontWeight: 700, fontSize: '12px' },
  background: { enabled: true, borderRadius: 4, opacity: 0.9, padding: 3 },
  formatter: (val) => (val == null || val === 0 ? '' : `₱${Number(val).toLocaleString()}`)
},
tooltip: {
  y: { formatter: (val) => (val == null || val === 0 ? '' : `₱${Number(val).toLocaleString()}`) }
},

  legend: { position: 'top', horizontalAlign: 'right' },
  tooltip: { y: { formatter: v => `₱${Number(v||0).toLocaleString()}` } },
  noData: { text: 'No sales data' }
};

    if (!salesChart) {
      salesChart = new ApexCharts(el, opts);
      salesChart.render();
    } else {
     salesChart.updateOptions({
  chart: { width },
  xaxis: {
    categories,
    tickPlacement: 'on',
    labels: { rotate: 0, trim: true, hideOverlappingLabels: true, style: { fontSize: '12px' } }
  },
  plotOptions: { bar: { horizontal: false, columnWidth: '45%', dataLabels: { position: 'top' } } },
  legend: { position: 'top', horizontalAlign: 'right' },
  colors: ['#008FFB', '#FEB019'],
  dataLabels: { enabled: categories.length <= 10, offsetY: -20, style: { colors: ['#222'], fontWeight: 700, fontSize: '12px' }, background: { enabled: true, borderRadius: 4, opacity: 0.9, padding: 3 }, formatter: v => `₱${Number(v||0).toLocaleString()}` }
});
salesChart.updateSeries(series, true);

    }
        // ⬇️ ADD THIS LINE (sales)
    window._dashHelpers.bindChartResize(
      el,
      () => (salesChart?.w?.globals?.labels?.length ?? categories.length),
      (newW) => { if (salesChart) salesChart.updateOptions({ chart: { width: newW } }, false, true); }
    );
  }

  function fillSalesBreakdownTable(data){
    const peso = window._dashHelpers.peso;
    const $prodBody = $('#salesProductsBody');
    const $svcBody  = $('#salesServicesBody');

    $prodBody.empty();
    if ((data.products || []).length === 0) {
      $prodBody.append(`<tr class="empty-row"><td colspan="4" class="text-center text-muted">No product sales to display.</td></tr>`);
    } else {
      data.products.forEach(r => {
        $prodBody.append(
          `<tr>
            <td class="text-left">${r.name}</td>
            <td class="text-right">${Number(r.qty || 0).toLocaleString()}</td>
            <td class="text-right">${peso(r.unitPrice)}</td>
            <td class="text-right">${peso(r.total)}</td>
          </tr>`
        );
      });
    }
    $('#salesProductsSubtotal').text(peso(data.productsSubtotal || 0));
    setScrollableIfNeeded($prodBody);

    $svcBody.empty();
    if ((data.services || []).length === 0) {
      $svcBody.append(`<tr class="empty-row"><td colspan="4" class="text-center text-muted">No service sales to display.</td></tr>`);
    } else {
      data.services.forEach(r => {
        $svcBody.append(
          `<tr>
            <td class="text-left">${r.name}</td>
            <td class="text-right">${Number(r.count || 0).toLocaleString()}</td>
            <td class="text-right">${peso(r.fee)}</td>
            <td class="text-right">${peso(r.total)}</td>
          </tr>`
        );
      });
    }
$('#salesServicesSubtotal').text(peso(data.servicesSubtotal || 0));
$('#salesGrandTotal').text(peso((data.productsSubtotal || 0) + (data.servicesSubtotal || 0)));

// make both bodies scroll when 5+ rows
setScrollableIfNeeded($prodBody);
setScrollableIfNeeded($svcBody);

renderSalesChart(data);

  }

  // ---- helpers: validate month/year coming from KPI ----
  function hasValidMY(month, year){
    const mOk = (String(month) === 'all') || (Number.isFinite(Number(month)) && Number(month) >= 0 && Number(month) <= 11);
    const yOk = Number.isFinite(Number(year)) && String(year).length >= 4;
    return mOk && yOk;
  }

  // Loader with safe override handling
  function loadSalesBreakdown(override){
    let preset = $preset.val() || 'today';

    const useOverride = override && hasValidMY(override.month, override.year);
    if (useOverride) {
      preset = 'monthpick';
      $preset.val('monthpick');
    }

    const rawM = useOverride ? override.month : $m.val();
    const rawY = useOverride ? override.year  : $y.val();

    const mm = (preset === 'monthpick')
      ? (String(rawM) === 'all' ? 'all' : Number(rawM))
      : undefined;
    const yy = (preset === 'monthpick') ? Number(rawY) : undefined;

    if (preset === 'monthpick') { $m.val(String(rawM)).show(); $y.val(String(rawY)).show(); }
    toggleMonthPickUI();

    window._dashHelpers.getSalesData(preset, mm, yy)
      .then(fillSalesBreakdownTable)
      .catch(() => {
        fillSalesBreakdownTable({ products: [], productsSubtotal: 0, services: [], servicesSubtotal: 0, grandTotal: 0 });
      });
  }

  // LOCAL-ONLY UI handlers (no broadcasting)
  $(document).on('change', '#salesTrendPreset', function(){
    toggleMonthPickUI();
    loadSalesBreakdown();
  });
  $(document).on('change', '#trendMonth,#trendYear', function(){
    if ($preset.val() === 'monthpick') loadSalesBreakdown();
  });

  // KPI global changes (guard on source === 'kpi')
  function onKpiChange(_ev, f){
    if (!f || f.source !== 'kpi') return;

    if (f.preset && f.preset !== 'monthpick') {
      // Today / 7d / 30d → follow preset, ignore month/year
      $preset.val(f.preset);
      toggleMonthPickUI();
      loadSalesBreakdown();
      return;
    }

    // Monthpick: only override if month+year valid
    if (hasValidMY(f.month, f.year)) {
      $preset.val('monthpick');
      $m.val(String(f.month)).show();
      $y.val(String(f.year)).show();
      toggleMonthPickUI();
      loadSalesBreakdown({ month: (f.month === 'all' ? 'all' : Number(f.month)), year: Number(f.year) });
    } else {
      // Fallback to local state if KPI didn't send valid month/year
      $preset.val('monthpick');
      toggleMonthPickUI();
      loadSalesBreakdown();
    }
  }
  $(document).on(GLOBAL_EVT, onKpiChange);
  $(window).on(GLOBAL_EVT, onKpiChange);
  $(document).on(LEGACY_EVT, onKpiChange);
  $(window).on(LEGACY_EVT, onKpiChange);

  $(function(){
    if (!document.getElementById('salesOverview')) return;
    window._dashHelpers.ensureMonthYearOptions($m, $y);
    toggleMonthPickUI();
    $preset.addClass('pill'); $m.addClass('pill'); $y.addClass('pill');
    loadSalesBreakdown();
  });

  // Expose a reliable loader for KPI block
  window._dash = window._dash || {};
  window._dash.forceSales = function(month, year){
    if (!hasValidMY(month, year)) return;
    $preset.val('monthpick');
    $m.val(String(month)).show();
    $y.val(String(year)).show();
    toggleMonthPickUI();
    loadSalesBreakdown({ month: (month === 'all' ? 'all' : Number(month)), year: Number(year) });
  };
})();

/* ===================== COP Breakdown (LOCAL-ONLY) ===================== */
(function(){
  const GLOBAL_EVT = 'kpiFilterChange';
  const LEGACY_EVT = 'dashboardFilterChange';
  const $preset = $('#copPreset');

  window._dashHelpers.applyUnifiedPresetOptions($preset);
  $preset.addClass('pill');

  const { $m: $cm, $y: $cy } = window._dashHelpers.ensureMonthYearForCard('#copPreset', 'cop');
  window._dashHelpers.ensureMonthYearOptions($cm, $cy);
  $cm.addClass('pill'); $cy.addClass('pill');
// --- Scroll helper (≥ 5 rows makes tbody scroll) ---
function setScrollableIfNeeded($tbody){
  const rows = $tbody.find('tr').length;
  if (rows >= 5) $tbody.addClass('scrollable-body');
  else $tbody.removeClass('scrollable-body');
}

  function toggleUI(){ window._dashHelpers.toggleMonthYearUI($preset.val(), $cm, $cy); }

  let copChart = null;
  function renderCopChart(data){
    const el = document.querySelector('#copBreakdownChart');
    if (!el) return;

    const prodRows = (data.products || []).map(r => ({ name: r.name, sold: r.total || 0, exp: 0 }));
    const expRows  = (data.expired  || []).map(r => ({ name: r.name, sold: 0,        exp: r.total || 0 }));

    const byName = new Map();
    [...prodRows, ...expRows].forEach(x => {
      const key = String(x.name || '').trim();
      if (!byName.has(key)) byName.set(key, { name: key, sold: 0, exp: 0 });
      const row = byName.get(key);
      row.sold += x.sold; row.exp += x.exp;
    });

    const top = [...byName.values()]
      .map(r => ({ ...r, total: r.sold + r.exp }))
      .sort((a,b) => b.total - a.total)
      .slice(0, 10);

    const categories = top.map(r => r.name);
  const soldData = top.map(r => (r.sold > 0 ? r.sold : null));
const expData  = top.map(r => (r.exp  > 0 ? r.exp  : null));
const series = [
  { name: 'Products (Sold)', data: soldData },
  { name: 'Expired',         data: expData  }
];

// Make chart horizontally scroll when many columns
const width = window._dashHelpers.ensureChartScrollable(el, categories.length, 90, 720);

    const showLabels = categories.length <= 10;
const opts = {
  chart: { type: 'bar', height: 320, width, toolbar: { show: false },   zoom: { enabled: false },
    redrawOnParentResize: true   },
  series,
  xaxis: {
    categories,
    tickPlacement: 'on',
    labels: { rotate: 0, trim: true, hideOverlappingLabels: true, style: { fontSize: '12px' } }
  },
  yaxis: { labels: { formatter: v => Number(v||0).toLocaleString() } },
  colors: ['#008FFB', '#FEB019'],
  plotOptions: { bar: { horizontal: false, columnWidth: '45%', dataLabels: { position: 'top' } } },
dataLabels: {
  enabled: categories.length <= 10,
  offsetY: -20,
  style: { colors: ['#222'], fontWeight: 700, fontSize: '12px' },
  background: { enabled: true, borderRadius: 4, opacity: 0.9, padding: 3 },
  formatter: (val) => (val == null || val === 0 ? '' : `₱${Number(val).toLocaleString()}`)
},
tooltip: {
  y: { formatter: (val) => (val == null || val === 0 ? '' : `₱${Number(val).toLocaleString()}`) }
},

  legend: { position: 'top', horizontalAlign: 'right' },
  tooltip: { y: { formatter: v => `₱${Number(v||0).toLocaleString()}` } },
  noData: { text: 'No cost data' }
};


    if (!copChart) {
      copChart = new ApexCharts(el, opts);
      copChart.render();
    } else {
  copChart.updateOptions({
  chart: { width },
  xaxis: {
    categories,
    tickPlacement: 'on',
    labels: { rotate: 0, trim: true, hideOverlappingLabels: true, style: { fontSize: '12px' } }
  },
  plotOptions: { bar: { horizontal: false, columnWidth: '45%', dataLabels: { position: 'top' } } },
  legend: { position: 'top', horizontalAlign: 'right' },
  colors: ['#008FFB', '#FEB019'],
  dataLabels: { enabled: categories.length <= 10, offsetY: -20, style: { colors: ['#222'], fontWeight: 700, fontSize: '12px' }, background: { enabled: true, borderRadius: 4, opacity: 0.9, padding: 3 }, formatter: v => `₱${Number(v||0).toLocaleString()}` }
});
copChart.updateSeries(series, true);

    }
       // ⬇️ ADD THIS LINE (cop)
    window._dashHelpers.bindChartResize(
      el,
      () => (copChart?.w?.globals?.labels?.length ?? categories.length),
      (newW) => { if (copChart) copChart.updateOptions({ chart: { width: newW } }, false, true); }
    );
  }

  function fillCopBreakdownTable(data){
    const peso = window._dashHelpers.peso;
    const $prodBody = $('#copProductsBody');
    const $expBody  = $('#copExpiredBody');

    $prodBody.empty();
    if ((data.products || []).length === 0) {
      $prodBody.append(`<tr class="empty-row"><td colspan="4" class="text-center text-muted">No product costs to display.</td></tr>`);
    } else {
      data.products.forEach(r => {
        $prodBody.append(
          `<tr>
            <td class="text-left">${r.name}</td>
            <td class="text-right">${Number(r.qty || 0).toLocaleString()}</td>
            <td class="text-right">${peso(r.purchase)}</td>
            <td class="text-right">${peso(r.total)}</td>
          </tr>`
        );
      });
    }
    $('#copProductsSubtotal').text(peso(data.productsSubtotal || 0));

    $expBody.empty();
    if ((data.expired || []).length === 0) {
      $expBody.append(`<tr class="empty-row"><td colspan="4" class="text-center text-muted">No expired products in this period.</td></tr>`);
    } else {
      data.expired.forEach(r => {
        $expBody.append(
          `<tr>
            <td class="text-left">${r.name}</td>
            <td class="text-right">${Number(r.qty || 0).toLocaleString()}</td>
            <td class="text-right">${peso(r.purchase)}</td>
            <td class="text-right">${peso(r.total)}</td>
          </tr>`
        );
      });
    }
  $('#copExpiredSubtotal').text(peso(data.expiredSubtotal || 0));
$('#copGrandTotal').text(peso((data.productsSubtotal || 0) + (data.expiredSubtotal || 0)));

// make bodies scroll when 5+ rows
setScrollableIfNeeded($prodBody);
setScrollableIfNeeded($expBody);

renderCopChart(data);

  }

  function hasValidMY(month, year){
    const mOk = (String(month) === 'all') || (Number.isFinite(Number(month)) && Number(month) >= 0 && Number(month) <= 11);
    const yOk = Number.isFinite(Number(year)) && String(year).length >= 4;
    return mOk && yOk;
  }

  function loadCopBreakdown(override){
    let preset = $preset.val() || 'today';
    const useOverride = override && hasValidMY(override.month, override.year);
    if (useOverride) { preset = 'monthpick'; $preset.val('monthpick'); }

    const rawM = useOverride ? override.month : $cm.val();
    const rawY = useOverride ? override.year  : $cy.val();

    const mm = (preset === 'monthpick') ? (String(rawM) === 'all' ? 'all' : Number(rawM)) : undefined;
    const yy = (preset === 'monthpick') ? Number(rawY) : undefined;

    if (preset === 'monthpick') { $cm.val(String(rawM)).show(); $cy.val(String(rawY)).show(); }
    toggleUI();

    window._dashHelpers.getCopData(preset, mm, yy)
      .then(fillCopBreakdownTable)
      .catch(() => {
        fillCopBreakdownTable({ products: [], productsSubtotal: 0, expired: [], expiredSubtotal: 0 });
      });
  }

  // LOCAL-ONLY handlers
  $(document).on('change', '#copPreset', function(){
    toggleUI();
    loadCopBreakdown();
  });
  $(document).on('change', '#copMonth,#copYear', function(){
    if ($preset.val() === 'monthpick') loadCopBreakdown();
  });

  // KPI listener
  function onKpiChange(_ev, f){
    if (!f || f.source !== 'kpi') return;

    if (f.preset && f.preset !== 'monthpick') {
      $preset.val(f.preset);
      toggleUI();
      loadCopBreakdown();
      return;
    }

    if (hasValidMY(f.month, f.year)) {
      $preset.val('monthpick');
      $cm.val(String(f.month)).show();
      $cy.val(String(f.year)).show();
      toggleUI();
      loadCopBreakdown({ month: (f.month === 'all' ? 'all' : Number(f.month)), year: Number(f.year) });
    } else {
      $preset.val('monthpick');
      toggleUI();
      loadCopBreakdown();
    }
  }
  $(document).on(GLOBAL_EVT, onKpiChange);
  $(window).on(GLOBAL_EVT, onKpiChange);
  $(document).on(LEGACY_EVT, onKpiChange);
  $(window).on(LEGACY_EVT, onKpiChange);

  $(function(){
    if (!document.getElementById('salesOverview')) return;
    toggleUI();
    loadCopBreakdown();
  });

  window._dash = window._dash || {};
  window._dash.forceCop = function(month, year){
    if (!hasValidMY(month, year)) return;
    $preset.val('monthpick');
    $('#copMonth').val(String(month)).show();
    $('#copYear').val(String(year)).show();
    toggleUI();
    loadCopBreakdown({ month: (month === 'all' ? 'all' : Number(month)), year: Number(year) });
  };
})();

/* ===================== COS Breakdown (LOCAL-ONLY) ===================== */
(function(){
  const GLOBAL_EVT = 'kpiFilterChange';
  const LEGACY_EVT = 'dashboardFilterChange';
  const $preset = $('#cosPreset');

  window._dashHelpers.applyUnifiedPresetOptions($preset);
  $preset.addClass('pill');

  const { $m: $sm, $y: $sy } = window._dashHelpers.ensureMonthYearForCard('#cosPreset', 'cos');
  window._dashHelpers.ensureMonthYearOptions($sm, $sy);
  $sm.addClass('pill'); $sy.addClass('pill');
// --- Scroll helper (≥ 5 rows makes tbody scroll) ---
function setScrollableIfNeeded($tbody){
  const rows = $tbody.find('tr').length;
  if (rows >= 5) $tbody.addClass('scrollable-body');
  else $tbody.removeClass('scrollable-body');
}

  function toggleUI(){ window._dashHelpers.toggleMonthYearUI($preset.val(), $sm, $sy); }

  let cosChart = null;
  function renderCosChart(data){
    const el = document.querySelector('#cosBreakdownChart');
    if (!el) return;

    const rows = (data.services || [])
      .map(r => ({ name: r.name, amt: Number(r.total || 0) }))
      .sort((a,b) => b.amt - a.amt)
      .slice(0, 10);

    const categories = rows.map(r => r.name);
    const series = [{ name: 'Cost', data: rows.map(r => r.amt) }];
    // Make chart horizontally scroll when many columns
const width = window._dashHelpers.ensureChartScrollable(el, categories.length, 90, 720);

    const showLabels = categories.length <= 10;

  const opts = {
  chart: { type: 'bar', height: 320, width, toolbar: { show: false },   zoom: { enabled: false },
    redrawOnParentResize: true   },
  series,
  xaxis: {
    categories,
    tickPlacement: 'on',
    labels: { rotate: 0, trim: true, hideOverlappingLabels: true, style: { fontSize: '12px' } }
  },
  yaxis: { labels: { formatter: v => Number(v||0).toLocaleString() } },
  colors: ['#008FFB'],
  plotOptions: { bar: { horizontal: false, columnWidth: '45%', dataLabels: { position: 'top' } } },
  dataLabels: {
    enabled: categories.length <= 10,
    offsetY: -20,
    style: { colors: ['#222'], fontWeight: 700, fontSize: '12px' },
    background: { enabled: true, borderRadius: 4, opacity: 0.9, padding: 3 },
    formatter: v => `₱${Number(v||0).toLocaleString()}`
  },
  legend: { show: false },
  tooltip: { y: { formatter: v => `₱${Number(v||0).toLocaleString()}` } },
  noData: { text: 'No service cost data' }
};


    if (!cosChart) {
      cosChart = new ApexCharts(el, opts);
      cosChart.render();
    } else {
cosChart.updateOptions({
  chart: { width },
  xaxis: {
    categories,
    tickPlacement: 'on',
    labels: { rotate: 0, trim: true, hideOverlappingLabels: true, style: { fontSize: '12px' } }
  },
  plotOptions: { bar: { horizontal: false, columnWidth: '45%', dataLabels: { position: 'top' } } },
  colors: ['#008FFB'],
  dataLabels: { enabled: categories.length <= 10, offsetY: -20, style: { colors: ['#222'], fontWeight: 700, fontSize: '12px' }, background: { enabled: true, borderRadius: 4, opacity: 0.9, padding: 3 }, formatter: v => `₱${Number(v||0).toLocaleString()}` }
});
cosChart.updateSeries(series, true);

    }
      // ⬇️ ADD THIS LINE (cos)
    window._dashHelpers.bindChartResize(
      el,
      () => (cosChart?.w?.globals?.labels?.length ?? categories.length),
      (newW) => { if (cosChart) cosChart.updateOptions({ chart: { width: newW } }, false, true); }
    );
  }

  function fillCosBreakdownTable(data){
    const peso = window._dashHelpers.peso;
    const $body = $('#cosServicesBody');
    $body.empty();

    const rows = data.services || [];
    if (!rows.length) {
      $body.append(`<tr class="empty-row"><td colspan="3" class="text-center text-muted">No service costs to display.</td></tr>`);
    } else {
      rows.forEach(r => {
        $body.append(
          `<tr>
            <td class="text-left">${r.name}</td>
            <td class="text-right">${peso(r.purchase)}</td>
            <td class="text-right">${peso(r.total)}</td>
          </tr>`
        );
      });
    }
$('#cosServicesTotal').text(peso(data.servicesTotal || 0));

// make body scroll when 5+ rows
setScrollableIfNeeded($body);

renderCosChart(data);

  }

  function hasValidMY(month, year){
    const mOk = (String(month) === 'all') || (Number.isFinite(Number(month)) && Number(month) >= 0 && Number(month) <= 11);
    const yOk = Number.isFinite(Number(year)) && String(year).length >= 4;
    return mOk && yOk;
  }

  function loadCosBreakdown(override){
    let preset = $preset.val() || 'today';
    const useOverride = override && hasValidMY(override.month, override.year);
    if (useOverride) { preset = 'monthpick'; $preset.val('monthpick'); }

    const rawM = useOverride ? override.month : $sm.val();
    const rawY = useOverride ? override.year  : $sy.val();

    const mm = (preset === 'monthpick') ? (String(rawM) === 'all' ? 'all' : Number(rawM)) : undefined;
    const yy = (preset === 'monthpick') ? Number(rawY) : undefined;

    if (preset === 'monthpick') { $sm.val(String(rawM)).show(); $sy.val(String(rawY)).show(); }
    toggleUI();

    window._dashHelpers.getCosData(preset, mm, yy)
      .then(fillCosBreakdownTable)
      .catch(() => fillCosBreakdownTable({ services: [], servicesTotal: 0 }));
  }

  // LOCAL-ONLY
  $(document).on('change', '#cosPreset', function(){
    toggleUI();
    loadCosBreakdown();
  });
  $(document).on('change', '#cosMonth,#cosYear', function(){
    if ($preset.val() === 'monthpick') loadCosBreakdown();
  });

  // KPI listener
  function onKpiChange(_ev, f){
    if (!f || f.source !== 'kpi') return;

    if (f.preset && f.preset !== 'monthpick') {
      $preset.val(f.preset);
      toggleUI();
      loadCosBreakdown();
      return;
    }

    if (hasValidMY(f.month, f.year)) {
      $preset.val('monthpick');
      $sm.val(String(f.month)).show();
      $sy.val(String(f.year)).show();
      toggleUI();
      loadCosBreakdown({ month: (f.month === 'all' ? 'all' : Number(f.month)), year: Number(f.year) });
    } else {
      $preset.val('monthpick');
      toggleUI();
      loadCosBreakdown();
    }
  }
  $(document).on(GLOBAL_EVT, onKpiChange);
  $(window).on(GLOBAL_EVT, onKpiChange);
  $(document).on(LEGACY_EVT, onKpiChange);
  $(window).on(LEGACY_EVT, onKpiChange);

  $(function(){
    if (!document.getElementById('salesOverview')) return;
    toggleUI();
    loadCosBreakdown();
  });

  window._dash = window._dash || {};
  window._dash.forceCos = function(month, year){
    if (!hasValidMY(month, year)) return;
    $preset.val('monthpick');
    $('#cosMonth').val(String(month)).show();
    $('#cosYear').val(String(year)).show();
    toggleUI();
    loadCosBreakdown({ month: (month === 'all' ? 'all' : Number(month)), year: Number(year) });
  };
})();

/* ===================== OPEX Breakdown (LOCAL-ONLY) ===================== */
(function () {
  const GLOBAL_EVT = 'kpiFilterChange';
  const LEGACY_EVT = 'dashboardFilterChange';
  const $preset = $('#opexPreset');

  window._dashHelpers.applyUnifiedPresetOptions($preset);
  $preset.addClass('pill');

  const { $m: $om, $y: $oy } = window._dashHelpers.ensureMonthYearForCard('#opexPreset', 'opex');
  window._dashHelpers.ensureMonthYearOptions($om, $oy);
  $om.addClass('pill'); $oy.addClass('pill');
// --- Scroll helper (≥ 5 rows makes tbody scroll) ---
function setScrollableIfNeeded($tbody){
  const rows = $tbody.find('tr').length;
  if (rows >= 5) $tbody.addClass('scrollable-body');
  else $tbody.removeClass('scrollable-body');
}

  function toggleUI(){ window._dashHelpers.toggleMonthYearUI($preset.val(), $om, $oy); }

  let opexChart = null;
  function renderOpexChart(data){
    const el = document.querySelector('#opexBreakdownChart');
    if (!el) return;

    const rows = (data.opex || [])
      .map(r => ({ name: r.type, amt: Number(r.amount || 0) }))
      .sort((a,b) => b.amt - a.amt)
      .slice(0, 10);

    const categories = rows.map(r => r.name);
    const series = [{ name: 'Amount', data: rows.map(r => r.amt) }];
    // Make chart horizontally scroll when many columns
const width = window._dashHelpers.ensureChartScrollable(el, categories.length, 90, 720);

    const showLabels = categories.length <= 10;

 const opts = {
  chart: { type: 'bar', height: 320, width, toolbar: { show: false },   zoom: { enabled: false },
    redrawOnParentResize: true   },
  series,
  xaxis: {
    categories,
    tickPlacement: 'on',
    labels: { rotate: 0, trim: true, hideOverlappingLabels: true, style: { fontSize: '12px' } }
  },
  yaxis: { labels: { formatter: v => Number(v||0).toLocaleString() } },
  colors: ['#008FFB'],
  plotOptions: { bar: { horizontal: false, columnWidth: '45%', dataLabels: { position: 'top' } } },
  dataLabels: {
    enabled: categories.length <= 10,
    offsetY: -20,
    style: { colors: ['#222'], fontWeight: 700, fontSize: '12px' },
    background: { enabled: true, borderRadius: 4, opacity: 0.9, padding: 3 },
    formatter: v => `₱${Number(v||0).toLocaleString()}`
  },
  legend: { show: false },
  tooltip: { y: { formatter: v => `₱${Number(v||0).toLocaleString()}` } },
  noData: { text: 'No OPEX data' }
};


    if (!opexChart) {
      opexChart = new ApexCharts(el, opts);
      opexChart.render();
    } else {
opexChart.updateOptions({
  chart: { width },
  xaxis: {
    categories,
    tickPlacement: 'on',
    labels: { rotate: 0, trim: true, hideOverlappingLabels: true, style: { fontSize: '12px' } }
  },
  plotOptions: { bar: { horizontal: false, columnWidth: '45%', dataLabels: { position: 'top' } } },
  colors: ['#008FFB'],
  dataLabels: { enabled: categories.length <= 10, offsetY: -20, style: { colors: ['#222'], fontWeight: 700, fontSize: '12px' }, background: { enabled: true, borderRadius: 4, opacity: 0.9, padding: 3 }, formatter: v => `₱${Number(v||0).toLocaleString()}` }
});
opexChart.updateSeries(series, true);

    }
    
    // ⬇️ ADD THIS LINE (opex)
    window._dashHelpers.bindChartResize(
      el,
      () => (opexChart?.w?.globals?.labels?.length ?? categories.length),
      (newW) => { if (opexChart) opexChart.updateOptions({ chart: { width: newW } }, false, true); }
    );
  }

  function fillOpexTable(data) {
    const peso = window._dashHelpers.peso;
    const $body = $('#opexBody');
    $body.empty();

    const rows = data.opex || [];
    if (!rows.length) {
      $body.append(
        `<tr class="empty-row">
           <td colspan="2" class="text-center text-muted">No operating expenses to display.</td>
         </tr>`
      );
    } else {
      rows.forEach(r => {
        $body.append(
          `<tr>
             <td class="text-left">${r.type}</td>
             <td class="text-right">${peso(r.amount)}</td>
           </tr>`
        );
      });
    }
$('#opexTotal').text(peso(data.total || 0));

// make body scroll when 5+ rows
setScrollableIfNeeded($body);

renderOpexChart(data);

  }

  function hasValidMY(month, year){
    const mOk = (String(month) === 'all') || (Number.isFinite(Number(month)) && Number(month) >= 0 && Number(month) <= 11);
    const yOk = Number.isFinite(Number(year)) && String(year).length >= 4;
    return mOk && yOk;
  }

  function loadOpexBreakdown(override) {
    let preset = $preset.val() || 'today';
    const useOverride = override && hasValidMY(override.month, override.year);
    if (useOverride) { preset = 'monthpick'; $preset.val('monthpick'); }

    const rawM = useOverride ? override.month : $om.val();
    const rawY = useOverride ? override.year  : $oy.val();

    // Note: getOpexData maps 'monthpick' to 'month' and handles 'all' by year
    const mm = (preset === 'monthpick') ? (String(rawM) === 'all' ? 'all' : Number(rawM)) : undefined;
    const yy = (preset === 'monthpick') ? Number(rawY) : undefined;

    if (preset === 'monthpick') { $om.val(String(rawM)).show(); $oy.val(String(rawY)).show(); }
    toggleUI();

    window._dashHelpers.getOpexData(preset, mm, yy)
      .then(fillOpexTable)
      .catch(() => fillOpexTable({ opex: [], total: 0 }));
  }

  // LOCAL-ONLY
  $(document).on('change', '#opexPreset', function(){ 
    toggleUI();
    loadOpexBreakdown();
  });
  $(document).on('change', '#opexMonth,#opexYear', function(){
    if ($preset.val() === 'monthpick') loadOpexBreakdown();
  });

  // KPI listener
  function onKpiChange(_ev, f){
    if (!f || f.source !== 'kpi') return;

    if (f.preset && f.preset !== 'monthpick') {
      $preset.val(f.preset);
      toggleUI();
      loadOpexBreakdown();
      return;
    }

    if (hasValidMY(f.month, f.year)) {
      $preset.val('monthpick');
      $om.val(String(f.month)).show();
      $oy.val(String(f.year)).show();
      toggleUI();
      loadOpexBreakdown({ month: (f.month === 'all' ? 'all' : Number(f.month)), year: Number(f.year) });
    } else {
      $preset.val('monthpick');
      toggleUI();
      loadOpexBreakdown();
    }
  }
  $(document).on(GLOBAL_EVT, onKpiChange);
  $(window).on(GLOBAL_EVT, onKpiChange);
  $(document).on(LEGACY_EVT, onKpiChange);
  $(window).on(LEGACY_EVT, onKpiChange);

  $(function () {
    if (!document.getElementById('salesOverview')) return;
    toggleUI();
    loadOpexBreakdown();
  });

  window._dash = window._dash || {};
  window._dash.forceOpex = function(month, year){
    if (!hasValidMY(month, year)) return;
    $preset.val('monthpick');
    $('#opexMonth').val(String(month)).show();
    $('#opexYear').val(String(year)).show();
    toggleUI();
    loadOpexBreakdown({ month: (month === 'all' ? 'all' : Number(month)), year: Number(year) });
  };
})();


/* ===================== Predictive Cards (Service/Product) — SIMPLE, SALES WORDING ===================== */
(function(){
  const GLOBAL_EVT = 'kpiFilterChange';
  const LEGACY_EVT = 'dashboardFilterChange';
  const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];

  // helpers
  function esc(s){ return String(s||'').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
  function pct(x){
    if (x==null || isNaN(Number(x))) return null;
    const v = Number(x);
    return (v<=1 && v>=0) ? Math.round(v*100) : Math.round(v);
  }
  function stripStars(t){ return String(t||'').replace(/\*\*/g,''); } // remove "**"
  function toSales(t){ return String(t||'').replace(/revenue/gi,'sales'); }
  function boldPercents(t){ return String(t||'').replace(/(\d+(?:\.\d+)?)%/g, '<b>$1%</b>'); }
  function boldName(t, name){
    if (!name) return t;
    const re = new RegExp(`\\b(${name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})\\b`, 'gi');
    return String(t||'').replace(re, '<b>$1</b>');
  }

  // sentence builder (month/year plain; only bold name + %)
  function line(kind, monthName, year, name, sharePct, deltaPts, lo, hi){
    const who = kind === 'service' ? 'service' : 'product';
    const parts = [];

    parts.push(`${esc(monthName)} ${year}:`);

    if (name && sharePct!=null){
      parts.push(` <b>${esc(name)}</b> did <b>${sharePct}%</b> of ${who} sales.`);
    } else if (sharePct!=null){
      parts.push(` Top ${who} did <b>${sharePct}%</b> of sales.`);
    } else if (name){
      parts.push(` <b>${esc(name)}</b> led ${who} sales.`);
    } else {
      parts.push(` ${who[0].toUpperCase()+who.slice(1)} update.`);
    }

    if (deltaPts!=null){
      const d = Math.round(deltaPts);
      if (d !== 0) parts.push(` Change from last month: ${d>0 ? 'up' : 'down'} ${Math.abs(d)} points.`);
      else parts.push(` Change from last month: no change.`);
    }

    if (lo!=null && hi!=null){
      parts.push(` Next month: around <b>${Math.round(lo)}–${Math.round(hi)}%</b> (if nothing big changes).`);
    }
    return parts.join('');
  }

  function renderCard($card, title, html){
    const $body = $card.find('.card-body');
    const icon = $card.is('#predictiveServiceCard') ? 'fa-robot' : 'fa-lightbulb';
    $body.html(`
      <div>
        <h6 class="mb-1">${title}</h6>
        <small>${html}</small>
      </div>
      <i class="fas ${icon}"></i>
    `);
  }

function kpiMonthYear(){
  const $gm = $('#kpiMonth'), $gy = $('#kpiYear');
  const m = $gm.val(), y = $gy.val();
  if (m != null && y != null && m !== 'all'){
    const mm = parseInt(m, 10), yy = parseInt(y, 10);
    if (!Number.isNaN(mm) && !Number.isNaN(yy)) return { m: mm, y: yy };
  }
  // Fallback = last full month
  const now = new Date();
  let M = now.getMonth() - 1, Y = now.getFullYear();
  if (M < 0){ M = 11; Y -= 1; }
  return { m: M, y: Y };
}

  function addMonths(m,y,offset){
    let M=m+offset, Y=y;
    while(M<0){M+=12;Y--;} while(M>11){M-=12;Y++;}
    return {m:M,y:Y};
  }

  function totalSales(d){ return Number(d?.productsSubtotal||0)+Number(d?.servicesSubtotal||0); }
  function topShare(rows, grand){
    if (!rows || !rows.length || !grand) return null;
    const sorted = [...rows].sort((a,b)=>Number(b.total||0)-Number(a.total||0));
    const t = sorted[0];
    return { name: t.name, sharePct: (Number(t.total||0)/Number(grand))*100 };
  }
  function shareFor(rows, grand, name){
    if (!rows || !rows.length || !grand || !name) return null;
    const r = rows.find(x => String(x.name).trim().toLowerCase()===String(name).trim().toLowerCase());
    return r ? (Number(r.total||0)/Number(grand))*100 : null;
  }
  function simpleBand(values){
    const nums = values.filter(v => typeof v==='number' && !Number.isNaN(v));
    const avg = nums.length ? nums.reduce((a,b)=>a+b,0)/nums.length : null;
    const diffs = [];
    for(let i=1;i<nums.length;i++) diffs.push(Math.abs(nums[i]-nums[i-1]));
    const wiggle = Math.max(2, ...(diffs.length?diffs:[2])); // ≥ ±2 pts
    return avg==null ? {lo:null,hi:null} : { lo: Math.max(0, avg - wiggle), hi: Math.min(100, avg + wiggle) };
  }

  async function computeClientSide(base){
    const {m,y} = base;
    const prev1 = addMonths(m,y,-1);
    const prev2 = addMonths(m,y,-2);

    const d0 = await window._dashHelpers.getSalesData('monthpick', m, y);
    const d1 = await window._dashHelpers.getSalesData('monthpick', prev1.m, prev1.y).catch(()=>null);
    const d2 = await window._dashHelpers.getSalesData('monthpick', prev2.m, prev2.y).catch(()=>null);

    const g0 = totalSales(d0), g1 = d1?totalSales(d1):0, g2 = d2?totalSales(d2):0;

    // product
    const tp = topShare(d0?.products, g0);
    const p1 = tp ? shareFor(d1?.products, g1, tp.name) : null;
    const p2 = tp ? shareFor(d2?.products, g2, tp.name) : null;
    const pBand = tp ? simpleBand([tp.sharePct, p1, p2]) : {lo:null,hi:null};
    const pDelta = (tp && p1!=null) ? (tp.sharePct - p1) : null;

    // service
    const ts = topShare(d0?.services, g0);
    const s1 = ts ? shareFor(d1?.services, g1, ts.name) : null;
    const s2 = ts ? shareFor(d2?.services, g2, ts.name) : null;
    const sBand = ts ? simpleBand([ts.sharePct, s1, s2]) : {lo:null,hi:null};
    const sDelta = (ts && s1!=null) ? (ts.sharePct - s1) : null;

    const monthName = MONTHS[m];

    const prodHTML = tp
      ? line('product', monthName, y, tp.name, pct(tp.sharePct), pDelta, pct(pBand.lo), pct(pBand.hi))
      : 'Not enough product data yet.';
    const svcHTML = ts
      ? line('service', monthName, y, ts.name, pct(ts.sharePct), sDelta, pct(sBand.lo), pct(sBand.hi))
      : 'Not enough service data yet.';

    return { prodHTML, svcHTML };
  }

  function formatServerText(monthName, year, obj, kind){
    if (!obj) return `Not enough ${kind} data yet.`;
    // if server gives plain text, clean + convert to sales + bold % + bold known name
    if (obj.text){
      let t = stripStars(obj.text);
      t = toSales(t);
      t = boldPercents(t);
      if (obj.name) t = boldName(t, obj.name);
      return `${monthName} ${year}: ${t}`;
    }
    // if server gives fields, build line
    if (obj.name || obj.share){
      return line(
        kind,
        monthName, year,
        obj.name,
        pct(obj.share),
        obj.deltaPp,
        pct(obj.forecastLow),
        pct(obj.forecastHigh)
      );
    }
    return `Not enough ${kind} data yet.`;
  }

  async function loadPredictives(){
    const base = kpiMonthYear();
    const params = `?month=${encodeURIComponent(base.m)}&year=${encodeURIComponent(base.y)}`;
    const monthName = MONTHS[base.m];
    try {
      const d = await $.getJSON(`/admin/predictive-insights${params}`);
      const mName = d?.baseMonthName || monthName;
      const year = d?.baseYear || base.y;

      const svcHTML = formatServerText(mName, year, d?.service, 'service');
      const prodHTML = formatServerText(mName, year, d?.product, 'product');

      if (svcHTML || prodHTML){
        renderCard($('#predictiveServiceCard'), 'Service Insight', svcHTML || 'Not enough service data yet.');
        renderCard($('#predictiveProductCard'), 'Product Insight', prodHTML || 'Not enough product data yet.');
        return;
      }

      const calc = await computeClientSide(base);
      renderCard($('#predictiveServiceCard'), 'Service Insight', calc.svcHTML);
      renderCard($('#predictiveProductCard'), 'Product Insight', calc.prodHTML);
    } catch {
      const calc = await computeClientSide(base);
      renderCard($('#predictiveServiceCard'), 'Service Insight', calc.svcHTML);
      renderCard($('#predictiveProductCard'), 'Product Insight', calc.prodHTML);
    }
  }

  // init + listen to KPI
  $(function(){
    if (!document.getElementById('salesOverview')) return;
    loadPredictives();
  });
  $(document).on(GLOBAL_EVT, loadPredictives);
  $(window).on(GLOBAL_EVT, loadPredictives);
  $(document).on(LEGACY_EVT, loadPredictives);
  $(window).on(LEGACY_EVT, loadPredictives);
})();
/* ===================== KPI + GLOBAL MONTH FILTER (BROADCASTS + HARD SYNC, NUMERIC) ===================== */
(function () {
  const GLOBAL_EVT = 'kpiFilterChange';
  const LEGACY_EVT = 'dashboardFilterChange';

  const $gm = $('#kpiMonth');
  const $gy = $('#kpiYear');

  if (!document.getElementById('salesOverview') || !$gm.length || !$gy.length) return;

  // Populate Month(+All) + Year
  window._dashHelpers.ensureMonthYearOptions($gm, $gy);
  $gm.addClass('pill'); $gy.addClass('pill');

  const peso = window._dashHelpers.peso;

  function setKpiValues(vals){
    $('#kpiSales').text(peso(vals.sales || 0));
    $('#kpiProdCost').text(peso(vals.cop || 0));
    $('#kpiServCost').text(peso(vals.cos || 0));
    $('#kpiOpex').text(peso(vals.opex || 0));
    $('#kpiOpIncome').text(
      peso((vals.sales || 0) - (vals.cop || 0) - (vals.cos || 0) - (vals.opex || 0))
    );
  }

  function fetchAll(preset, month, year){
    const P  = preset || 'today';
    const mm = (P === 'monthpick') ? month : undefined;
    const yy = (P === 'monthpick') ? year  : undefined;

    return Promise.all([
      window._dashHelpers.getSalesData(P, mm, yy).catch(() => ({ productsSubtotal: 0, servicesSubtotal: 0 })),
      window._dashHelpers.getCopData(P, mm, yy).catch(() => ({ productsSubtotal: 0, expiredSubtotal: 0 })),
      window._dashHelpers.getCosData(P, mm, yy).catch(() => ({ servicesTotal: 0 })),
      window._dashHelpers.getOpexData(P, mm, yy).catch(() => ({ total: 0 }))
    ]).then(([sales, cop, cos, opex]) => {
      const kpiSales = Number(sales.productsSubtotal || 0) + Number(sales.servicesSubtotal || 0);
      const kpiCop   = Number(cop.productsSubtotal || 0) + Number(cop.expiredSubtotal || 0);
      const kpiCos   = Number(cos.servicesTotal || 0);
      const kpiOpex  = Number(opex.total || 0);
      return { sales: kpiSales, cop: kpiCop, cos: kpiCos, opex: kpiOpex };
    });
  }

  // Force each breakdown card to EXACT month/year + fire its loader
  function hardSyncBreakdowns(mNum, yNum){
    const sync = (presetSel, monthSel, yearSel) => {
      const $p = $(presetSel);
      if (!$p.length) return;

      // Ensure their month/year selects exist & have options (their IIFEs add them)
      if (monthSel && $(monthSel).length && $(monthSel).children().length === 0) {
        window._dashHelpers.ensureMonthYearOptions($(monthSel), $(yearSel));
      }
      if (yearSel && $(yearSel).length && $(yearSel).children().length === 0) {
        window._dashHelpers.ensureMonthYearOptions($(monthSel), $(yearSel));
      }

      // Set preset + numeric month/year, reveal if hidden
      $p.val('monthpick');
      if (monthSel && $(monthSel).length){
        $(monthSel).val(String(mNum)).show();
      }
      if (yearSel && $(yearSel).length){
        $(yearSel).val(String(yNum)).show();
      }

      // Trigger their handlers to reload
      $p.trigger('change');            // toggles UI + calls load...
      if (monthSel && $(monthSel).length) $(monthSel).trigger('change');
      if (yearSel  && $(yearSel).length)  $(yearSel).trigger('change');

      // Safety: re-trigger after a tick in case UI created lazily
      setTimeout(() => {
        $p.trigger('change');
        if (monthSel && $(monthSel).length) $(monthSel).trigger('change');
        if (yearSel  && $(yearSel).length)  $(yearSel).trigger('change');
      }, 0);
    };

    // Sales Breakdown
    sync('#salesTrendPreset', '#trendMonth', '#trendYear');
    // Cost of Product Sold Breakdown
    sync('#copPreset', '#copMonth', '#copYear');
    // Cost of Service Breakdown
    sync('#cosPreset', '#cosMonth', '#cosYear');
    // Operating Expenses Breakdown
    sync('#opexPreset', '#opexMonth', '#opexYear');
  }

  function broadcastMonthState(mNum, yNum){
    const payload = { source: 'kpi', preset: 'monthpick', month: mNum, year: yNum };
    $(document).trigger('kpiFilterChange', [payload]);
    $(window).trigger('kpiFilterChange', [payload]);
    $(document).trigger('dashboardFilterChange', [payload]);   // legacy compatibility
    $(window).trigger('dashboardFilterChange', [payload]);
  }

  function updateFromGlobalMonth(){
    const rawM = $gm.val();           // "0".."11" or "all"
    const rawY = $gy.val();           // "2025", etc.
    const mNum = (rawM === 'all') ? 'all' : parseInt(rawM, 10);
    const yNum = parseInt(rawY, 10);

    // 1) Recompute KPIs for the chosen period
    fetchAll('monthpick', mNum, yNum).then(setKpiValues);

    // 2) Broadcast (for anyone listening)
    broadcastMonthState(mNum, yNum);

    // 3) Bullet-proof reload: directly call each breakdown’s force-* API
    if (window._dash){
      if (typeof _dash.forceSales === 'function') _dash.forceSales(mNum, yNum);
      if (typeof _dash.forceCop   === 'function') _dash.forceCop(mNum, yNum);
      if (typeof _dash.forceCos   === 'function') _dash.forceCos(mNum, yNum);
      if (typeof _dash.forceOpex  === 'function') _dash.forceOpex(mNum, yNum);
    }

    // 4) (Optional, keep) also sync the dropdown UIs visually
    hardSyncBreakdowns(mNum, yNum);
  }

  // Initial KPIs = Today
  fetchAll('today').then(setKpiValues);

  // Wire up global month change
  $gm.on('change', updateFromGlobalMonth);
  $gy.on('change', updateFromGlobalMonth);
})();

/* ===================== Download Report (Excel) — polished & correct ===================== */
(function(){
  const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];

  // ---------- helpers ----------
  const clamp = (n, min, max) => Math.max(min, Math.min(max, n));
  const safeN = v => Number.isFinite(Number(v)) ? Number(v) : 0;
  const isNil = v => v === null || v === undefined;
  const pesoFmt = `"₱"#,##0.00`;
  const norm = s => String(s||'').trim().toLowerCase().replace(/\s+/g,' ');
  const textLen = v => String(v ?? '').length;

  function titleFromKPI(){
    const m = $('#kpiMonth').val(), y = Number($('#kpiYear').val());
    if (m === 'all') return { month:'all', year:y, title:`All Months ${y}` };
    const mm = Number(m);
    return { month:mm, year:y, title:`${MONTHS[mm]} ${y}` };
  }

  function toggleBusy(b){
    const $b = $('#btnDownloadReport'), $s = $('#dlSpin'), $i = $('#dlIcon');
    if (!$b.length) return;
    $b.prop('disabled', !!b);
    $s && $s.toggleClass('d-none', !b);
    $i && $i.toggleClass('d-none', !!b);
  }

  function ensureExcelJS(){
    return new Promise((res, rej)=>{
      if (window.ExcelJS?.Workbook) return res();
      const s = document.createElement('script');
      s.src = 'https://cdn.jsdelivr.net/npm/exceljs@4.4.0/dist/exceljs.min.js';
      s.onload = () => res();
      s.onerror = () => rej(new Error('ExcelJS failed to load'));
      document.head.appendChild(s);
    });
  }

  async function pullData(month, year){
    const [sales, cop, cos, opex] = await Promise.all([
      window._dashHelpers.getSalesData('monthpick', month, year),
      window._dashHelpers.getCopData('monthpick', month, year),
      window._dashHelpers.getCosData('monthpick', month, year),
      window._dashHelpers.getOpexData('monthpick', month, year),
    ]);
    return { sales, cop, cos, opex };
  }

  function kpiFromData({ sales, cop, cos, opex }){
    const salesTotal = safeN(sales?.productsSubtotal) + safeN(sales?.servicesSubtotal);
    const copSold    = safeN(cop?.productsSubtotal);
    const copExpired = safeN(cop?.expiredSubtotal);
    const copTotal   = copSold + copExpired;
    const cosTotal   = safeN(cos?.servicesTotal);
    const opexTotal  = safeN(opex?.total);
    const opIncome   = salesTotal - (copTotal + cosTotal + opexTotal);
    return { salesTotal, copTotal, cosTotal, opexTotal, opIncome };
  }

  // ---------- Sheet/Layout helpers (wide title band; never-cut clinic name) ----------
  function createSheet(wb, name){
    const ws = wb.addWorksheet(name, { properties: { defaultRowHeight: 18 }});
    ws.pageSetup = {
      margins:{ left:0.25, right:0.25, top:0.5, bottom:0.5, header:0.2, footer:0.2 },
      fitToPage:true, fitToWidth:1, fitToHeight:0,
      orientation:'landscape',
      horizontalCentered:true
    };

    // Wider canvas so the merged title spans nicely even on short tables
    ws.columns = [
      { width: 42 }, // A
      { width: 18 }, // B
      { width: 20 }, // C
      { width: 20 }, // D
      { width: 22 }, // E
      { width: 16 }, // F extra for title band
      { width: 16 }, // G extra for title band
      { width: 16 }, // H extra for title band
    ];
    return ws;
  }

  function putHeader(ws, subtitle){
    // Ensure at least 8 columns exist for a wide title band
    const needCols = 8;
    const currCols = (ws.columns?.length || 0);
    if (currCols < needCols){
      for (let i = currCols; i < needCols; i++){
        ws.columns.push({ width: 14 });
      }
    }

    const lastCol = ws.columns.length;
    const lastLetter = ws.getColumn(lastCol).letter || 'H';

    ws.mergeCells(`A1:${lastLetter}1`);
    ws.mergeCells(`A2:${lastLetter}2`);

    const t1 = ws.getCell('A1');
    t1.value = 'Casa Animalia Veterinary Clinic ';
    t1.font = { bold:true, size:16, color:{argb:'FF0D47A1'} };
    t1.alignment = { horizontal:'center', vertical:'middle', wrapText:true, shrinkToFit:true };
    t1.fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FFF5F8FF'} };

    const t2 = ws.getCell('A2');
    t2.value = `Sales Report — ${subtitle}`;
    t2.font = { bold:true, size:12, color:{argb:'FF4A5568'} };
    t2.alignment = { horizontal:'center', vertical:'middle', wrapText:true, shrinkToFit:true };

    ws.getRow(1).height = 30;
    ws.getRow(2).height = 22;

    // Subtle divider under subtitle
    ws.getCell('A2').border = { bottom:{ style:'thin', color:{argb:'FFB3C1E6'} } };

    ws.addRow([]);
    ws.views = [{ state:'frozen', ySplit: 3 }]; // freeze titles
  }

  function addSectionTitle(ws, text){
    const lastCol = ws.columns.length;
    const lastLetter = ws.getColumn(lastCol).letter || 'H';
    const r = ws.addRow([text]);
    r.font = { bold:true, size:12, color:{ argb:'FF1C2C45' } };
    r.alignment = { vertical:'middle' };
    ws.mergeCells(`A${r.number}:${lastLetter}${r.number}`);
    ws.getCell(`A${r.number}`).fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FFEFF4FF'} };
    ws.getCell(`A${r.number}`).border = { bottom:{style:'thin', color:{argb:'FFB3C1E6'} } };
    ws.addRow([]);
  }

  // autosize after data is present (keeps long names readable)
  function autosize(ws, headers, rows){
    const colCount = headers.length;
    const maxChars = new Array(colCount).fill(0);
    headers.forEach((h,i)=>{ maxChars[i] = Math.max(maxChars[i], textLen(h.label)); });
    rows.forEach(arr => {
      arr.forEach((v,i)=>{ maxChars[i] = Math.max(maxChars[i], textLen(v)); });
    });
    ws.columns.forEach((col, i) => {
      const ch = clamp(Math.ceil(maxChars[i] * 1.2), 12, 50);
      col.width = Math.max(col.width || 0, ch);
    });
  }

  /**
   * Beautiful banded grid (no Excel "Table" needed).
   * headers: [{label, numFmt?}], rows: array of arrays, totals: { label, cols:[...] }
   */
  function writeGrid(ws, headers, rows, totals){
    // Header
    const head = ws.addRow(headers.map(h => h.label));
    head.height = 18;
    head.eachCell(c => {
      c.font = { bold:true, color:{argb:'FFFFFFFF'} };
      c.alignment = { horizontal:'center', vertical:'middle', wrapText:true };
      c.fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FF1E88E5'} };
      c.border = { top:{style:'medium'}, left:{style:'thin'}, bottom:{style:'thin'}, right:{style:'thin'} };
    });

    const firstDataRow = head.number + 1;

    // Data + zebra stripes
    const stripe = { type:'pattern', pattern:'solid', fgColor:{argb:'FFF8FAFF'} };
    rows.forEach((arr, idx) => {
      const r = ws.addRow(arr.map(v => (isNil(v) ? null : v)));
      r.height = 18;
      r.eachCell((c, ci) => {
        const fmt = headers[ci-1]?.numFmt;
        if (fmt && c.value != null) c.numFmt = fmt;
        c.alignment = (ci===1) ? { horizontal:'left', vertical:'middle', wrapText:true } : { horizontal:'right', vertical:'middle' };
        c.border = { left:{style:'thin'}, right:{style:'thin'} };
        if (idx % 2 === 1) c.fill = stripe;
      });
    });

    const lastDataRow = ws.lastRow.number;

    // Totals (double top line, colored background)
    if (totals && rows.length > 0){
      const tr = ws.addRow(new Array(headers.length).fill(null));
      tr.height = 19;
      tr.getCell(1).value = totals.label || 'Total';
      tr.getCell(1).font = { bold:true };

      (totals.cols || []).forEach(ci => {
        const colLetter = ws.getColumn(ci).letter;
        tr.getCell(ci).value = { formula: `SUM(${colLetter}${firstDataRow}:${colLetter}${lastDataRow})` };
        const fmt = headers[ci-1]?.numFmt;
        if (fmt) tr.getCell(ci).numFmt = fmt;
        tr.getCell(ci).font = { bold:true };
        tr.getCell(ci).alignment = { horizontal:'right' };
      });

      tr.eachCell(c => {
        c.fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FFE3F2FD'} };
        c.border = { top:{style:'double'}, bottom:{style:'thin'}, left:{style:'thin'}, right:{style:'thin'} };
      });
    }

    ws.addRow([]);
    autosize(ws, headers, rows);
  }

  async function buildAndDownload({ month, year, title }){
    toggleBusy(true);
    try{
      await ensureExcelJS();
      const data = await pullData(month, year);
      const KPI = kpiFromData(data);

      // Map base purchase by product for markup computation
      const baseByName = new Map();
      for (const r of (data.cop?.products || [])){
        if (r?.name) baseByName.set(norm(r.name), safeN(r.purchase));
      }

      const wb = new ExcelJS.Workbook();
      wb.created = new Date();

      // ===== Summary =====
      const wsSum = createSheet(wb, 'Summary');
      putHeader(wsSum, title);
      addSectionTitle(wsSum, 'KPI Summary');
      writeGrid(
        wsSum,
        [{label:'KPI'}, {label:'Amount', numFmt:pesoFmt}],
        [
          ['Sales', KPI.salesTotal],
          ['Cost of Products Sold (incl. Expired)', KPI.copTotal],
          ['Cost of Services', KPI.cosTotal],
          ['Operating Expenses', KPI.opexTotal],
          ['Operating Income', KPI.opIncome],
        ],
        null
      );

      // ===== Sales – Products =====
      const wsProd = createSheet(wb, 'Sales – Products');
      putHeader(wsProd, title);
      addSectionTitle(wsProd, 'Products');
      const prodRows = (data.sales?.products || []).map(r => {
        const name = r.name || '';
        const qty  = isNil(r.qty)       ? null : safeN(r.qty);
        const unit = isNil(r.unitPrice) ? null : safeN(r.unitPrice);
        const base = baseByName.get(norm(name)); // may be undefined
        const markup = (isNil(base) || isNil(unit)) ? null : (unit - base);
        const total = isNil(r.total) ? null : safeN(r.total);
        return [ name, qty, unit, markup, total ];
      });
      writeGrid(
        wsProd,
        [
          {label:'Product Name'},
          {label:'Qty'},
          {label:'Unit Price',       numFmt:pesoFmt},
          {label:'Markup (per unit)',numFmt:pesoFmt},
          {label:'Total Amount',     numFmt:pesoFmt}
        ],
        prodRows,
        { label:'Total Product Sales', cols:[5] }
      );

      // ===== Sales – Services =====
      const wsSvc = createSheet(wb, 'Sales – Services');
      putHeader(wsSvc, title);
      addSectionTitle(wsSvc, 'Services');
      const svcRows = (data.sales?.services || []).map(r => ([
        r.name || '',
        isNil(r.count) ? null : safeN(r.count),
        isNil(r.fee)   ? null : safeN(r.fee),
        isNil(r.total) ? null : safeN(r.total)
      ]));
      writeGrid(
        wsSvc,
        [
          {label:'Service Type'},
          {label:'Service Count'},
          {label:'Service Fee',  numFmt:pesoFmt},
          {label:'Total Amount', numFmt:pesoFmt}
        ],
        svcRows,
        { label:'Total Service Sales', cols:[2,4] }
      );

      // ===== COPS – Sold =====
      const wsCops = createSheet(wb, 'COPS – Sold');
      putHeader(wsCops, title);
      addSectionTitle(wsCops, 'Cost of Products Sold — Sold Items');
      const copSoldRows = (data.cop?.products || []).map(r => ([
        r.name || '',
        isNil(r.qty)      ? null : safeN(r.qty),
        isNil(r.purchase) ? null : safeN(r.purchase),
        isNil(r.total)    ? null : safeN(r.total)
      ]));
      writeGrid(
        wsCops,
        [
          {label:'Product Name'},
          {label:'Qty'},
          {label:'Purchase Price', numFmt:pesoFmt},
          {label:'Total Amount',   numFmt:pesoFmt}
        ],
        copSoldRows,
        { label:'Total Cost of Products Sold', cols:[2,4] }
      );

      // ===== COPS – Expired (optional) =====
      const copExpRows = (data.cop?.expired || []).map(r => ([
        r.name || '',
        isNil(r.qty)      ? null : safeN(r.qty),
        isNil(r.purchase) ? null : safeN(r.purchase),
        isNil(r.total)    ? null : safeN(r.total)
      ]));
      if (copExpRows.length){
        const wsExp = createSheet(wb, 'COPS – Expired');
        putHeader(wsExp, title);
        addSectionTitle(wsExp, 'Expired Products (Cost)');
        writeGrid(
          wsExp,
          [
            {label:'Product Name'},
            {label:'Qty'},
            {label:'Purchase Price', numFmt:pesoFmt},
            {label:'Total Amount',   numFmt:pesoFmt}
          ],
          copExpRows,
          { label:'Total Expired Cost', cols:[2,4] }
        );
      }

      // ===== COS =====
      const wsCos = createSheet(wb, 'COS');
      putHeader(wsCos, title);
      addSectionTitle(wsCos, 'Cost of Services Sold');
      const svcCountMap = new Map((data.sales?.services || []).map(r => [norm(r.name), safeN(r.count)]));
      const cosRows = (data.cos?.services || []).map(r => ([
        r.name || '',
        svcCountMap.get(norm(r.name||'')) ?? null,
        isNil(r.purchase) ? null : safeN(r.purchase),
        isNil(r.total)    ? null : safeN(r.total)
      ]));
      writeGrid(
        wsCos,
        [
          {label:'Service Name'},
          {label:'Service Count'},
          {label:'Purchase Price', numFmt:pesoFmt},
          {label:'Total Amount',   numFmt:pesoFmt}
        ],
        cosRows,
        { label:'Total Cost of Services', cols:[2,4] }
      );

      // ===== OPEX =====
      const wsOpex = createSheet(wb, 'OPEX');
      putHeader(wsOpex, title);
      addSectionTitle(wsOpex, 'Operating Expenses');
      const opexRows = (data.opex?.opex || []).map(r => ([
        r.type || '',
        isNil(r.amount) ? null : safeN(r.amount)
      ]));
      writeGrid(
        wsOpex,
        [
          {label:'Type of Expenses'},
          {label:'Amount', numFmt:pesoFmt}
        ],
        opexRows,
        { label:'Total Operating Expenses', cols:[2] }
      );

      // ----- Save workbook -----
      const mmPart = month === 'all' ? 'ALL' : String(month+1).padStart(2,'0');
      const fname = `CasaAnimalia_Report_${year}-${mmPart}.xlsx`;
      const buf = await wb.xlsx.writeBuffer();
      const blob = new Blob([buf], { type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = fname; document.body.appendChild(a); a.click();
      setTimeout(()=>{ URL.revokeObjectURL(url); a.remove(); }, 0);
    } catch(e){
      console.error(e);
      alert('Sorry, the Excel export failed.');
    } finally {
      toggleBusy(false);
    }
  }

  // Wire up the button
  $(document).on('click', '#btnDownloadReport', function(){
    const sel = titleFromKPI();
    buildAndDownload(sel);
  });
})();
