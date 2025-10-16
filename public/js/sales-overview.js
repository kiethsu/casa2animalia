// /js/sales-overview.js
(function (window, $) {
  'use strict';

  // Public API
  const SalesOverview = { init, destroy, pause, resume };
  window.SalesOverview = SalesOverview;

  // ---- internal state ----
  const ns = '.salesOverview';
  const REFRESH_MS = 30000; // gentler than 20s
  let autoId = null;
  let paused = false;

  // selection state so auto-refresh honors user's choice (preset/monthpick/yoy)
  const lastSel = {
    mode: 'preset',                // 'preset' | 'monthpick' | 'yoy'
    preset: 'today',
    month: null,                   // 0..11 (when mode === 'monthpick')
    year: null,                    // YYYY   (when mode === 'monthpick')
    yoy: null                      // YYYY   (when mode === 'yoy')
  };

  // in-flight guards per section (so we can cancel/avoid stacking)
  let xhrKpi = null, xhrTrend = null, xhrCat = null, xhrProd = null, xhrServ = null;

  let pending = [];
  let salesTrendChart = null;
  let catSparklineChart = null;

  // ---------- tiny utils ----------
  const peso = (n) => {
    const v = Number(n) || 0;
    return (v < 0 ? `-₱${Math.abs(v).toLocaleString()}` : `₱${v.toLocaleString()}`);
  };

  const debounce = (fn, ms = 250) => { let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn.apply(null,args), ms); }; };

  // Track jqXHR and remove when finished (prevents memory growth)
  const track = (jq) => {
    pending.push(jq);
    jq.always(() => {
      const i = pending.indexOf(jq);
      if (i > -1) pending.splice(i, 1);
    });
    return jq;
  };

  const isSalesTabActive = () =>
    $('#salesOverview').hasClass('active') &&
    $('#salesOverview').is(':visible') &&
    document.visibilityState === 'visible';

  const isSlowNet = () => {
    const n = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!n) return false;
    return !!(n.saveData || /(^|-)2g$/.test(n.effectiveType || '') || (n.downlink && n.downlink < 1));
  };

  const addInterval = () => {
    clearInterval(autoId);
    autoId = setInterval(() => {
      if (paused || !isSalesTabActive() || isSlowNet()) return;
      refreshAll('auto');
    }, REFRESH_MS);
  };

  const clearIntervalSafe = () => { clearInterval(autoId); autoId = null; };

  function abortIfAny(...xhrs) {
    xhrs.forEach(x => { try { x && x.abort(); } catch (_) {} });
  }

  function destroyCharts() {
    try { salesTrendChart && salesTrendChart.destroy(); } catch(e){}
    try { catSparklineChart && catSparklineChart.destroy(); } catch(e){}
    salesTrendChart = null;
    catSparklineChart = null;
    $('#salesTrendChart, #catSparkline').empty();
  }

  function bindOnce() {
    // Remove any old handlers first (namespaced)
    $(document)
      .off('change' + ns, '#salesTrendPreset')
      .off('change' + ns, '#trendMonth, #trendYear')
      .off('change' + ns, '#salesTrendYOY')
      .off('change' + ns, '#categorySelect, #categoryRangeSelect')
      .off('change' + ns, '#prodCategorySelect, #prodRangeSelect')
      .off('input'  + ns, '#prodSearchInput')
      .off('change' + ns, '#servRangeSelect')
      .off('shown.bs.tab' + ns, 'a[data-toggle="tab"]');

    // Tabs: pause background refresh when not on Sales Overview
    $(document).on('shown.bs.tab' + ns, 'a[data-toggle="tab"]', function (e) {
      const target = $(e.target).attr('href');
      paused = (target !== '#salesOverview');
      if (!paused) refreshAll('tab-shown');
    });

    // Page visibility
    document.removeEventListener('visibilitychange', onVis);
    document.addEventListener('visibilitychange', onVis);

    // PRESET changed
    $(document).on('change' + ns, '#salesTrendPreset', function () {
      const v = $(this).val();

      // Clear YoY if user picks a preset/month
      $('#salesTrendYOY').val('');

      if (v === 'monthpick') {
        // Show month + year pickers (default to current if empty)
        $('#trendMonth, #trendYear').show();

        const now = new Date();
        if ($('#trendMonth').val() === null || $('#trendMonth').val() === '') {
          $('#trendMonth').val(String(now.getMonth()));
        }
        if ($('#trendYear').val() === null || $('#trendYear').val() === '') {
          $('#trendYear').val(String(now.getFullYear()));
        }

        lastSel.mode  = 'monthpick';
        lastSel.month = parseInt($('#trendMonth').val(), 10);
        lastSel.year  = parseInt($('#trendYear').val(), 10);
        loadMonthlyYoY(lastSel.month, lastSel.year);
        return;
      }

      // Hide month+year pickers when not in monthpick
      $('#trendMonth, #trendYear').hide();

      // Normal presets
      lastSel.mode = 'preset';
      lastSel.preset = v || '7d';
      loadSales(lastSel.preset, null, null, 'prev');
    });

    // MONTH / YEAR changed
    $(document).on('change' + ns, '#trendMonth, #trendYear', function () {
      const m = parseInt($('#trendMonth').val(), 10);
      const y = parseInt($('#trendYear').val(), 10);
      if (Number.isInteger(m) && Number.isInteger(y)) {
        lastSel.mode = 'monthpick';
        lastSel.month = m;
        lastSel.year  = y;
        loadMonthlyYoY(m, y);
      }
    });

    // YoY changed (whole year)
    $(document).on('change' + ns, '#salesTrendYOY', function () {
      // When YoY is selected, clear preset and hide month/year pickers
      $('#salesTrendPreset').val('');
      $('#trendMonth, #trendYear').hide();

      const selectedYear = parseInt($(this).val(), 10);
      lastSel.mode = selectedYear ? 'yoy' : 'preset';
      lastSel.yoy = selectedYear || null;
      if (selectedYear) loadSales('year', null, null, 'yoy', selectedYear);
    });

    $(document).on('change' + ns, '#categorySelect, #categoryRangeSelect', refreshCategoryKPIs);
    $(document).on('change' + ns, '#prodCategorySelect, #prodRangeSelect', refreshProductList);
    $(document).on('input'  + ns, '#prodSearchInput', debounce(refreshProductList, 250));
    $(document).on('change' + ns, '#servRangeSelect', refreshServiceList);
  }

  function onVis() {
    paused = document.visibilityState !== 'visible';
    if (!paused) refreshAll('visible');
  }

  // ------------- public -------------
  function init() {
    // Run only if dashboard DOM is present
    if (!document.getElementById('salesOverview')) return;

    // reset timers/requests/charts if reinited
    clearIntervalSafe();
    abortIfAny(xhrKpi, xhrTrend, xhrCat, xhrProd, xhrServ);
    pending = [];
    destroyCharts();
    paused = false;

    // Build YoY dropdown with a placeholder (OFF by default)
    const $yoy = $('#salesTrendYOY').empty();
    $yoy.append('<option value="">YoY (off)</option>');
    const currentYear = new Date().getFullYear();
    for (let y = currentYear; y > currentYear - 5; y--) {
      $yoy.append(`<option value="${y}">${y}-${y - 1}</option>`);
    }
    $yoy.val(''); // OFF initially

    // Populate Month + Year pickers
    const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    const $m = $('#trendMonth').empty();
    monthNames.forEach((name, idx) => $m.append(`<option value="${idx}">${name}</option>`));

    const $y = $('#trendYear').empty();
    for (let yv = currentYear; yv >= currentYear - 7; yv--) {
      $y.append(`<option value="${yv}">${yv}</option>`);
    }
    // hide by default; shown only when preset=monthpick
    $('#trendMonth, #trendYear').hide();

    bindOnce();

    // Default selection (today) reflected in both DOM and state
    lastSel.mode = 'preset';
    lastSel.preset = 'today';
    $('#salesTrendPreset').val('today').trigger('change');

    loadYearKPIs();
    populateCategoryDropdown().then(() => {
      $.getJSON('/admin/get-top-category?range=day')
        .done(resp => {
          const topCat = resp.topCategory;
          if (topCat) {
            $('#categorySelect').val(topCat);
            $('#prodCategorySelect').val(topCat);
            $('#categoryRangeSelect').val('day');
            $('#prodRangeSelect').val('day');
          }
        })
        .always(() => {
          refreshCategoryKPIs();
          refreshProductList();
        });
    });

    $('#servRangeSelect').val('day');
    refreshServiceList();

    addInterval(); // start visibility-aware, tab-aware loop
  }

  function destroy() {
    clearIntervalSafe();
    abortIfAny(xhrKpi, xhrTrend, xhrCat, xhrProd, xhrServ);
    destroyCharts();
    $(document).off(ns);
    document.removeEventListener('visibilitychange', onVis);
  }

  function pause(){ paused = true; }
  function resume(){ paused = false; refreshAll('resume'); }

  function refreshAll(reason){
    if (!isSalesTabActive()) return;

    loadYearKPIs();

    // honor the user's last selection
    if (lastSel.mode === 'preset' && lastSel.preset) {
      loadSales(lastSel.preset, null, null, 'prev');
    } else if (lastSel.mode === 'monthpick' && Number.isInteger(lastSel.month) && Number.isInteger(lastSel.year)) {
      loadMonthlyYoY(lastSel.month, lastSel.year);
    } else if (lastSel.mode === 'yoy' && lastSel.yoy) {
      loadSales('year', null, null, 'yoy', parseInt(lastSel.yoy, 10));
    }

    refreshCategoryKPIs();
    refreshProductList();
    refreshServiceList();
  }

  // ------------- logic -------------
function loadYearKPIs() {
  const today = new Date();
  const currentYear = today.getFullYear();
  const curStart = `${currentYear}-01-01`;
  const curEnd = today.toISOString().slice(0, 10);
  const prevYear = currentYear - 1;
  const prevStart = `${prevYear}-01-01`;
  const prevEnd = `${prevYear}-12-31`;

  abortIfAny(xhrKpi);
  xhrKpi = track($.getJSON(`/admin/get-dashboard-stats?range=custom&start=${curStart}&end=${curEnd}&compare=none`))
    .done(curData => {
      const curRev  = curData.sales?.totalRevenue || 0;
      const curTxns = curData.sales?.totalTransactions || 0;

      $('#kpiRevenue').text(peso(curRev));
      $('#kpiTxns').text(curTxns);

      const jq = track($.getJSON(`/admin/get-dashboard-stats?range=custom&start=${prevStart}&end=${prevEnd}&compare=none`))
        .done(prevData => {
          const prevRev  = prevData.sales?.totalRevenue || 0;
          const prevTxns = prevData.sales?.totalTransactions || 0;

          // Fill past-year KPIs
          $('#kpiAov').text(peso(prevRev));
          $('#kpiTxnsPrev').text(prevTxns);

          // Compute growth vs previous year (revenue)
          let revPctChange = 0;
          if (prevRev > 0) revPctChange = ((curRev - prevRev) / prevRev) * 100;
          const revPctRounded = parseFloat(revPctChange.toFixed(1));
          const convText = (revPctRounded >= 0 ? '+' : '') + `${revPctRounded}%`;

          $('#kpiConv').text(convText)
            .toggleClass('up', revPctRounded > 0)
            .toggleClass('down', revPctRounded < 0)
            .toggleClass('neutral', revPctRounded === 0);

          const $growthIcon = $('#growthIcon')
            .removeClass('up down neutral fa-arrow-up fa-arrow-down');
          if (revPctRounded > 0) $growthIcon.addClass('up fa-arrow-up');
          else if (revPctRounded < 0) $growthIcon.addClass('down fa-arrow-down');
          else $growthIcon.addClass('neutral fa-arrow-down');
        })
        .fail(() => {
          $('#kpiAov').text('₱0');
          $('#kpiTxnsPrev').text('0');
          $('#kpiConv').text('0%').removeClass('up down').addClass('neutral');
          $('#growthIcon').removeClass('up down').addClass('neutral fa-arrow-down');
        });

      xhrKpi = jq;
    })
    .fail(() => {
      $('#kpiRevenue').text('₱0');
      $('#kpiTxns').text(0);
      $('#kpiAov').text('₱0');
      $('#kpiTxnsPrev').text('0');
      $('#kpiConv').text('0%').removeClass('up down').addClass('neutral');
      $('#growthIcon').removeClass('up down').addClass('neutral fa-arrow-down');
    });
}

  // NEW: Month + Year selection (compare to same month last year)
  function loadMonthlyYoY(monthIdx, year) {
    abortIfAny(xhrTrend);

    const monthNamesShort = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

    // Build [YYYY-MM-01 .. YYYY-MM-last]
    const curStart = new Date(year, monthIdx, 1);
    const curEnd   = new Date(year, monthIdx + 1, 0);
    const prevYear = year - 1;
    const prevStart= new Date(prevYear, monthIdx, 1);
    const prevEnd  = new Date(prevYear, monthIdx + 1, 0);

    function iso(d){ const s = new Date(d); s.setHours(0,0,0,0); return s.toISOString().slice(0,10); }

    const qs1 = `/admin/get-dashboard-stats?range=custom&start=${iso(curStart)}&end=${iso(curEnd)}&compare=none`;
    const qs2 = `/admin/get-dashboard-stats?range=custom&start=${iso(prevStart)}&end=${iso(prevEnd)}&compare=none`;

    const q1 = track($.getJSON(qs1));
    const q2 = track($.getJSON(qs2));
    xhrTrend = q1;

    $.when(q1, q2).done((curWrap, prevWrap) => {
      const cur = (curWrap && curWrap[0]) || {};
      const prv = (prevWrap && prevWrap[0]) || {};

      const curSales   = Number(cur.sales?.totalRevenue)     || 0;
      const prevSales  = Number(prv.sales?.totalRevenue)     || 0;
      const curTxns    = Number(cur.sales?.totalTransactions)|| 0;
      const prevTxns   = Number(prv.sales?.totalTransactions)|| 0;
      const curProfit  = Number(cur.sales?.profit)           || 0;
      const prevProfit = Number(prv.sales?.profit)           || 0;

      let pctGrowth = 0;
      if (prevSales > 0) pctGrowth = ((curSales - prevSales) / prevSales) * 100;
      const pctRounded = Number(pctGrowth.toFixed(1));

      const curLabel  = `${monthNamesShort[monthIdx]} ${year}`;
      const prevLabel = `${monthNamesShort[monthIdx]} ${prevYear}`;

      destroyCharts();

      // Chart
      salesTrendChart = new ApexCharts(document.querySelector('#salesTrendChart'), {
        chart: { type: 'bar', height: 320, toolbar: { show: false } },
        series: [
          { name: 'Sales (₱)',    data: [curSales,  prevSales] },
          { name: 'Transactions', data: [curTxns,   prevTxns]  },
          { name: 'Profit (₱)',   data: [curProfit, prevProfit] }
        ],
        xaxis: { categories: [curLabel, prevLabel], labels: { style: { fontSize: '13px' } } },
        yaxis: { labels: { formatter: v => Number(Number(v).toFixed(0)).toLocaleString() } },
        colors: ['#008FFB', '#FEB019', '#28A745'],
        plotOptions: { bar: { columnWidth: '45%', dataLabels: { position: 'top' } } },
        dataLabels: {
          enabled: true,
          offsetY: -28,
          style: { colors: ['#222'], fontWeight: 700, fontSize: '15px' },
          background: { enabled: true, foreColor: '#fff', borderRadius: 4, opacity: 0.95, padding: 3 },
          formatter: (val, opts) => {
            if (opts.seriesIndex === 0 && opts.dataPointIndex === 0) {
              const sign = pctRounded >= 0 ? '+' : '';
              return `${peso(val)}\n${sign}${pctRounded}%`;
            }
            return opts.seriesIndex === 1
              ? `${Number(val).toLocaleString()}`
              : `${peso(val)}`;
          }
        },
        legend: { show: true, position: 'top', horizontalAlign: 'right' },
        tooltip: { y: (v, o) => (o.seriesIndex === 1 ? `${Number(v).toLocaleString()}` : `${peso(v)}`) }
      });
      salesTrendChart.render();

      // KPI table
      $('#salesTrendKPITable').show();
      $('#stCurLabel').text(curLabel);
      $('#stPrevLabel').text(prevLabel);
      $('#stCurSales').text(peso(curSales));
      $('#stCurTxns').text(curTxns);
      $('#stCurProfit').text(peso(curProfit));
      $('#stPrevSales').text(peso(prevSales));
      $('#stPrevTxns').text(prevTxns);
      $('#stPrevProfit').text(peso(prevProfit));
    }).fail(() => {
      renderTrendZero();
    });

    function renderTrendZero() {
      $('#salesTrendKPITable').show();
      $('#stCurLabel').text('Current');
      $('#stPrevLabel').text('Previous');
      $('#stCurSales, #stPrevSales, #stCurProfit, #stPrevProfit').text('₱0');
      $('#stCurTxns, #stPrevTxns').text('0');

      destroyCharts();
      salesTrendChart = new ApexCharts(document.querySelector('#salesTrendChart'), {
        chart: { type: 'bar', height: 320, toolbar: { show: false } },
        series: [
          { name: 'Sales (₱)',    data: [0, 0] },
          { name: 'Transactions', data: [0, 0] },
          { name: 'Profit (₱)',   data: [0, 0] }
        ],
        xaxis: { categories: ['Current', 'Previous'] },
        legend: { show: false },
        dataLabels: { enabled: false }
      });
      salesTrendChart.render();
    }
  }

  // Existing generic loader (presets + YoY year)
  function loadSales(range, start, end, compare, year) {
    abortIfAny(xhrTrend);

    function renderTrendZero() {
      $('#salesTrendKPITable').show();
      $('#stCurLabel').text('Current');
      $('#stPrevLabel').text('Previous');
      $('#stCurSales, #stPrevSales, #stCurProfit, #stPrevProfit').text('₱0');
      $('#stCurTxns, #stPrevTxns').text('0');

      destroyCharts();
      salesTrendChart = new ApexCharts(document.querySelector('#salesTrendChart'), {
        chart: { type: 'bar', height: 320, toolbar: { show: false } },
        series: [
          { name: 'Sales (₱)',    data: [0, 0] },
          { name: 'Transactions', data: [0, 0] },
          { name: 'Profit (₱)',   data: [0, 0] }
        ],
        xaxis: { categories: ['Current', 'Previous'] },
        legend: { show: false },
        dataLabels: { enabled: false }
      });
      salesTrendChart.render();
    }

    // YoY (whole-year) path unchanged
    if (compare === 'yoy' && typeof year === 'number') {
      const curYear  = year;
      const prevYear = year - 1;
      const curStart = `${curYear}-01-01`;
      const curEnd   = `${curYear}-12-31`;
      const prevStart= `${prevYear}-01-01`;
      const prevEnd  = `${prevYear}-12-31`;

      const q1 = track($.getJSON(`/admin/get-dashboard-stats?range=custom&start=${curStart}&end=${curEnd}&compare=none`));
      const q2 = track($.getJSON(`/admin/get-dashboard-stats?range=custom&start=${prevStart}&end=${prevEnd}&compare=none`));

      xhrTrend = q1;
      $.when(q1, q2).done((curDataWrap, prevDataWrap) => {
        const curData = curDataWrap[0] || {};
        const prevData= prevDataWrap[0] || {};
        const curSales   = curData.sales?.totalRevenue || 0;
        const prevSales  = prevData.sales?.totalRevenue || 0;
        const curTxns    = curData.sales?.totalTransactions || 0;
        const prevTxns   = prevData.sales?.totalTransactions || 0;
        const curProfit  = curData.sales?.profit || 0;
        const prevProfit = prevData.sales?.profit || 0;

        let pctGrowth = 0;
        if (prevSales > 0) pctGrowth = ((curSales - prevSales) / prevSales) * 100;
        const pctRounded = Number(pctGrowth.toFixed(1));

        destroyCharts();
        $('#salesTrendKPITable').show();
        $('#stCurLabel').text(`${curYear}`);
        $('#stPrevLabel').text(`${prevYear}`);
        $('#stCurSales').text(peso(curSales));
        $('#stCurTxns').text(curTxns);
        $('#stCurProfit').text(peso(curProfit));
        $('#stPrevSales').text(peso(prevSales));
        $('#stPrevTxns').text(prevTxns);
        $('#stPrevProfit').text(peso(prevProfit));

        salesTrendChart = new ApexCharts(document.querySelector('#salesTrendChart'), {
          chart: { type: 'bar', height: 320, toolbar: { show: false } },
          series: [
            { name: 'Sales (₱)',      data: [curSales,  prevSales] },
            { name: 'Transactions',   data: [curTxns,   prevTxns]  },
            { name: 'Profit (₱)',     data: [curProfit, prevProfit] }
          ],
          xaxis: { categories: [`${curYear}`, `${prevYear}`], labels: { style: { fontSize: '13px' } } },
          yaxis: { labels: { formatter: v => Number(Number(v).toFixed(0)).toLocaleString() } },
          colors: ['#008FFB', '#FEB019', '#28A745'],
          plotOptions: { bar: { columnWidth: '45%', dataLabels: { position: 'top' } } },
          dataLabels: {
            enabled: true,
            offsetY: -28,
            style: { colors: ['#222'], fontWeight: 700, fontSize: '15px' },
            background: { enabled: true, foreColor: '#fff', borderRadius: 4, opacity: 0.95, padding: 3 },
            formatter: (val, opts) => {
              if (opts.seriesIndex === 0 && opts.dataPointIndex === 0) {
                const sign = pctRounded >= 0 ? '+' : '';
                return `${peso(val)}\n${sign}${pctRounded}%`;
              }
              return opts.seriesIndex === 1
                ? `${Number(val).toLocaleString()}`
                : `${peso(val)}`;
            }
          },
          legend: { show: true, position: 'top', horizontalAlign: 'right' },
          tooltip: { y: (v, o) => (o.seriesIndex === 1 ? `${Number(v).toLocaleString()}` : `${peso(v)}`) }
        });
        salesTrendChart.render();
      }).fail(renderTrendZero);

      return;
    }

    // Other ranges + prev compare (or none) – unchanged
    let qs = `?range=${encodeURIComponent(range)}&compare=${encodeURIComponent(compare || 'prev')}`;
    if (range === 'custom' && start && end) qs += `&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`;

    xhrTrend = track($.getJSON(`/admin/get-dashboard-stats${qs}`))
      .done(renderTrendFromApi)
      .fail(renderTrendZero);

    function renderTrendFromApi(data){
      const s = data.sales || {};
      destroyCharts();

      let curLabel = 'Current', prevLabel = 'Previous';
      const now = moment().endOf('day');
      if (compare === 'prev') {
        if (range === '7d') {
          const curFrom = now.clone().subtract(6, 'days').startOf('day');
          const prevTo = curFrom.clone().subtract(1, 'day').endOf('day');
          const prevFrom = prevTo.clone().subtract(6, 'days').startOf('day');
          curLabel = `${curFrom.format('MMM D')} – ${now.format('MMM D')}`;
          prevLabel = `${prevFrom.format('MMM D')} – ${prevTo.format('MMM D')}`;
        } else if (range === '30d') {
          const curFrom = now.clone().subtract(29, 'days').startOf('day');
          const prevTo = curFrom.clone().subtract(1, 'day').endOf('day');
          const prevFrom = prevTo.clone().subtract(29, 'days').startOf('day');
          curLabel = `${curFrom.format('MMM D')} – ${now.format('MMM D')}`;
          prevLabel = `${prevFrom.format('MMM D')} – ${prevTo.format('MMM D')}`;
        } else if (range === 'month') {
          const curFrom = moment().startOf('month');
          const prevFrom = curFrom.clone().subtract(1, 'month').startOf('month');
          const prevTo = now.clone().subtract(1, 'month');
          curLabel = `${curFrom.format('MMM D')} – ${now.format('MMM D')}`;
          prevLabel = `${prevFrom.format('MMM D')} – ${prevTo.format('MMM D')}`;
        } else if (range === 'year') {
          const curFrom = moment().startOf('year');
          const prevFrom = curFrom.clone().subtract(1, 'year').startOf('year');
          const prevTo = now.clone().subtract(1, 'year');
          curLabel = `${curFrom.format('MMM D')} – ${now.format('MMM D')}`;
          prevLabel = `${prevFrom.format('MMM D')} – ${prevTo.format('MMM D')}`;
        } else if (range === 'custom' && start && end) {
          const curFrom = moment(start, 'YYYY-MM-DD').startOf('day');
          const curTo = moment(end, 'YYYY-MM-DD').endOf('day');
          const dayCount = curTo.diff(curFrom, 'days') + 1;
          const prevTo = curFrom.clone().subtract(1, 'day').endOf('day');
          const prevFrom = prevTo.clone().subtract(dayCount - 1, 'days').startOf('day');
          curLabel = `${curFrom.format('MMM D')} – ${curTo.format('MMM D')}`;
          prevLabel = `${prevFrom.format('MMM D')} – ${prevTo.format('MMM D')}`;
        }
      }

      const currentRev     = Number(s.totalRevenue) || 0;
      const previousRev    = Number(s.comparison?.prevRevenue) || 0;
      const currentTxns    = Number(s.totalTransactions) || 0;
      const previousTxns   = Number(s.comparison?.prevTransactions) || 0;
      const currentProfit  = Number(s.profit) || 0;
      const previousProfit = Number(s.comparison?.prevProfit) || 0;

      let pctGrowth = 0;
      if (previousRev > 0) pctGrowth = ((currentRev - previousRev) / previousRev) * 100;
      const pctRounded = Number(pctGrowth.toFixed(1));

      salesTrendChart = new ApexCharts(document.querySelector('#salesTrendChart'), {
        chart: { type: 'bar', height: 320, toolbar: { show: false } },
        series: [
          { name: 'Sales (₱)',    data: [currentRev,     previousRev] },
          { name: 'Transactions', data: [currentTxns,    previousTxns] },
          { name: 'Profit (₱)',   data: [currentProfit,  previousProfit] }
        ],
        xaxis: { categories: [curLabel, prevLabel], labels: { style: { fontSize: '13px' } } },
        yaxis: { labels: { formatter: val => Number(Number(val).toFixed(0)).toLocaleString() } },
        colors: ['#008FFB', '#FEB019', '#28A745'],
        plotOptions: { bar: { columnWidth: '45%', dataLabels: { position: 'top' } } },
        dataLabels: {
          enabled: true,
          offsetY: -28,
          style: { colors: ['#222'], fontWeight: 700, fontSize: '15px' },
          background: { enabled: true, foreColor: '#fff', borderRadius: 4, opacity: 0.95, padding: 3 },
          formatter: (val, opts) => {
            if (opts.seriesIndex === 0 && opts.dataPointIndex === 0) {
              const sign = pctRounded >= 0 ? '+' : '';
              return `${peso(val)}\n${sign}${pctRounded}%`;
            }
            return opts.seriesIndex === 1
              ? `${Number(val).toLocaleString()}`
              : `${peso(val)}`;
          }
        },
        legend: { show: true, position: 'top', horizontalAlign: 'right' },
        tooltip: { y: (v, o) => (o.seriesIndex === 1 ? `${Number(v).toLocaleString()}` : `${peso(v)}`) }
      });
      salesTrendChart.render();

      // KPI table
      $('#salesTrendKPITable').show();
      $('#stCurLabel').text(curLabel);
      $('#stPrevLabel').text(prevLabel);
      $('#stCurSales').text(peso(currentRev));
      $('#stCurTxns').text(currentTxns);
      $('#stCurProfit').text(peso(currentProfit));
      $('#stPrevSales').text(peso(previousRev));
      $('#stPrevTxns').text(previousTxns);
      $('#stPrevProfit').text(peso(previousProfit));
    }
  }

  function refreshCategoryKPIs() {
    const category = $('#categorySelect').val();
    const range = $('#categoryRangeSelect').val() || 'day';

    if (!category) {
      $('#catSales, #catProfit, #catLoss').text('₱0');
      $('#catRate').text('0%');
      $('#catComparisonText').text('');
      $('#catGrowth').removeClass('up down').addClass('neutral')
        .html('<span>0%</span><span class="arrow">&#8594;</span><small class="ml-2 text-muted">vs. previous period</small>');
      try { catSparklineChart && catSparklineChart.destroy(); } catch(e){}
      $('#catSparkline').html('');
      return;
    }

    abortIfAny(xhrCat);
    xhrCat = track($.getJSON(`/admin/get-sales-by-category?category=${encodeURIComponent(category)}&range=${encodeURIComponent(range)}`))
      .done(data => {
        const rev    = Number(data.totalRevenue)         || 0;
        const loss   = Number(data.totalExpiredFullLoss) || 0;
        const profit = Number(data.profit)               || 0;

        $('#catSales').text(peso(rev));
        $('#catProfit').text(peso(profit));
        $('#catLoss').text(peso(loss));

        const lastRev = Number(data.lastPeriodRevenue) || 0;
        let pctGrowth = 0;
        if (lastRev > 0) pctGrowth = ((rev - lastRev) / lastRev) * 100;
        const pctRounded = parseFloat(pctGrowth.toFixed(1));

        $('#catRate').text((pctRounded >= 0 ? '+' : '') + `${pctRounded}%`);
        const $gl = $('#catGrowth').removeClass('up down neutral');
        if (pctRounded > 0) {
          $gl.addClass('up').html(`<span>+${pctRounded}%</span><span class="arrow">&#8599;</span><small class="ml-2 text-muted">vs. previous period</small>`);
        } else if (pctRounded < 0) {
          $gl.addClass('down').html(`<span>${pctRounded}%</span><span class="arrow">&#8600;</span><small class="ml-2 text-muted">vs. previous period</small>`);
        } else {
          $gl.addClass('neutral').html(`<span>0%</span><span class="arrow">&#8594;</span><small class="ml-2 text-muted">vs. previous period</small>`);
        }

        try { catSparklineChart && catSparklineChart.destroy(); } catch(e){}
        $('#catSparkline').html('');
        catSparklineChart = new ApexCharts(document.querySelector('#catSparkline'), {
          chart: { type: 'line', height: 20, width: 50, sparkline: { enabled: true } },
          series: [{ data: [lastRev, rev] } ],
          stroke: { curve: 'smooth', width: 2 },
          colors: [pctRounded > 0 ? '#28a745' : '#e74c3c'],
          tooltip: { enabled: false }
        });
        catSparklineChart.render();

        const map = {
          day:   ['today', 'yesterday'],
          week:  ['the last 7 days', 'the previous 7 days'],
          month: ['this month', 'last month'],
          year:  ['this year', 'last year']
        };
        const [curTxt, prevTxt] = map[range] || ['current period', 'previous period'];
        const comparisonText = pctRounded > 0
          ? `Your ${curTxt} sales are higher than ${prevTxt}.`
          : pctRounded < 0
            ? `Your ${curTxt} sales are lower than ${prevTxt}.`
            : `Your ${curTxt} sales are the same as ${prevTxt}.`;
        $('#catComparisonText').text(comparisonText);
      })
      .fail(() => {
        $('#catSales, #catProfit, #catLoss').text('₱0');
        $('#catRate').text('0%');
        $('#catComparisonText').text('');
        $('#catGrowth').removeClass('up down').addClass('neutral')
          .html('<span>0%</span><span class="arrow">&#8594;</span><small class="ml-2 text-muted">vs. previous period</small>');
        try { catSparklineChart && catSparklineChart.destroy(); } catch(e){}
        $('#catSparkline').html('');
      });
  }

  function refreshProductList() {
    const category = $('#prodCategorySelect').val() || '';
    const range = $('#prodRangeSelect').val() || 'day';
    const searchTerm = ($('#prodSearchInput').val() || '').toLowerCase();

    const $tbody = $('#salesByProdTable tbody').empty();
    $('#prodNoData').hide();

    abortIfAny(xhrProd);
    xhrProd = track($.getJSON(`/admin/get-sales-by-product?category=${encodeURIComponent(category)}&range=${encodeURIComponent(range)}`))
      .done(data => {
        let items = data.products || [];
        if (searchTerm) items = items.filter(i => (i.productName || '').toLowerCase().includes(searchTerm));
        if (!items.length) { $('#prodNoData').show(); return; }

        items.forEach(item => {
          const units = Number(item.unitsSold) || 0;
          const rev   = Number(item.revenue)   || 0;
          $tbody.append(`
            <tr>
              <td>${item.productName}</td>
              <td class="text-right">${units.toLocaleString()}</td>
              <td class="text-right">${peso(rev)}</td>
            </tr>
          `);
        });
      })
      .fail(() => $('#prodNoData').text('Error loading products.').show());
  }

  function refreshServiceList() {
    const range = $('#servRangeSelect').val() || 'day';
    const $tbody = $('#salesByServTable tbody').empty();
    $('#servNoData').hide();

    abortIfAny(xhrServ);
    xhrServ = track($.getJSON(`/admin/get-sales-by-service?range=${encodeURIComponent(range)}`))
      .done(data => {
        const items = data.services || [];
        if (!items.length) { $('#servNoData').show(); return; }
        items.forEach(item => {
          const count = Number(item.unitsSold) || 0;
          const rev   = Number(item.revenue)   || 0;
          $tbody.append(`
            <tr>
              <td>${item.serviceName}</td>
              <td class="text-right">${count.toLocaleString()}</td>
              <td class="text-right">${peso(rev)}</td>
            </tr>
          `);
        });
      })
      .fail(() => $('#servNoData').text('Error loading data.').show());
  }

  function populateCategoryDropdown() {
    const $catSel       = $('#categorySelect');
    const $prodCatSel   = $('#prodCategorySelect');
    const $expiredCatSel= $('#expiredCategorySelect');

    const prevCat       = $catSel.val();
    const prevProdCat   = $prodCatSel.val();
    const prevExpiredCat= $expiredCatSel.val();

    $catSel.empty().append('<option value="" disabled selected>Select Category</option>');
    $prodCatSel.empty().append('<option value="">All Categories</option>');
    if ($expiredCatSel.length) $expiredCatSel.empty().append('<option value="">All Categories</option>');

    return track($.getJSON('/admin/get-categories'))
      .done((categories = []) => {
        const list = categories
          .filter(c => typeof c === 'string' && c.trim().length)
          .map(c => c.trim())
          .sort((a, b) => a.localeCompare(b));

        list.forEach(cat => {
          const t = cat.charAt(0).toUpperCase() + cat.slice(1);
          $catSel.append(`<option value="${cat}">${t}</option>`);
          $prodCatSel.append(`<option value="${cat}">${t}</option>`);
          if ($expiredCatSel.length) $expiredCatSel.append(`<option value="${cat}">${t}</option>`);
        });

        if (prevCat && list.includes(prevCat)) $catSel.val(prevCat);
        if (prevProdCat === '' || list.includes(prevProdCat)) $prodCatSel.val(prevProdCat);
        if ($expiredCatSel.length && (prevExpiredCat === '' || list.includes(prevExpiredCat))) {
          $expiredCatSel.val(prevExpiredCat);
        }
      })
      .fail(() => console.warn('Failed to load categories.'));
  }

})(window, jQuery);
