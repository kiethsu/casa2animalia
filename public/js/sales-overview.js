// /js/sales-overview.js
(function (window, $) {
  'use strict';

  // Public API
  const SalesOverview = { init, destroy };
  window.SalesOverview = SalesOverview;

  // ---- internal state (cleared on destroy) ----
  const ns = '.salesOverview';
  const REFRESH_MS = 20000; // auto refresh every 20s

  let timers = [];
  let pending = [];
  let salesTrendChart = null;
  let catSparklineChart = null;

  // ------------- tiny utils -------------
  const addTimer = (id) => { timers.push(id); };
  const clearTimers = () => { timers.forEach(clearInterval); timers = []; };
  const track = (jqxhr) => { pending.push(jqxhr); return jqxhr; };
  const abortAll = () => { pending.forEach(x => { try { x.abort(); } catch(e){} }); pending = []; };
  const peso = (n) => {
    const v = Number(n) || 0;
    return (v < 0 ? `-₱${Math.abs(v).toLocaleString()}` : `₱${v.toLocaleString()}`);
  };
  const debounce = (fn, ms=250) => {
    let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn.apply(null,args), ms); };
  };

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
      .off('apply.daterangepicker' + ns + ' cancel.daterangepicker' + ns, '#salesTrendCustom')
      .off('change' + ns, '#salesTrendYOY')
      .off('change' + ns, '#categorySelect, #categoryRangeSelect')
      .off('change' + ns, '#prodCategorySelect, #prodRangeSelect')
      .off('input'  + ns, '#prodSearchInput')
      .off('change' + ns, '#servRangeSelect');

    // Re-bind
    $(document).on('change' + ns, '#salesTrendPreset', function () {
      const v = $(this).val();
      if (v === 'today') {
        $('#salesTrendCustom').hide().val('');
        loadSales('today', null, null, 'prev');
      } else if (v === 'custom') {
        $('#salesTrendCustom').show().val('');
      } else {
        $('#salesTrendCustom').hide().val('');
        loadSales(v, null, null, 'prev');
      }
    });

    $(document).on('apply.daterangepicker' + ns, '#salesTrendCustom', (e, picker) => {
      const start = picker.startDate.format('YYYY-MM-DD');
      const end = picker.endDate.format('YYYY-MM-DD');
      $(e.target).val(`${start} to ${end}`);
      loadSales('custom', start, end, 'prev');
    });
    $(document).on('cancel.daterangepicker' + ns, '#salesTrendCustom', () => {
      $('#salesTrendCustom').val('');
      const preset = $('#salesTrendPreset').val();
      loadSales(preset || '7d', null, null, 'prev');
    });

    $(document).on('change' + ns, '#salesTrendYOY', function () {
      $('#salesTrendPreset').val('');
      $('#salesTrendCustom').hide().val('');
      const selectedYear = parseInt($(this).val(), 10);
      loadSales('year', null, null, 'yoy', selectedYear);
    });

    $(document).on('change' + ns, '#categorySelect, #categoryRangeSelect', refreshCategoryKPIs);
    $(document).on('change' + ns, '#prodCategorySelect, #prodRangeSelect', refreshProductList);
    $(document).on('input'  + ns, '#prodSearchInput', debounce(refreshProductList, 250));
    $(document).on('change' + ns, '#servRangeSelect', refreshServiceList);
  }

  // ------------- public -------------
  function init() {
    // Guard: run only if dashboard DOM is present
    if (!document.getElementById('salesOverview')) return;

    // Build YOY dropdown fresh
    const $yoy = $('#salesTrendYOY').empty();
    const currentYear = new Date().getFullYear();
    for (let y = currentYear; y > currentYear - 5; y--) {
      $yoy.append(`<option value="${y}">${y}-${y - 1}</option>`);
    }

    // Init daterangepicker every time (it attaches to the input node newly injected)
    const $custom = $('#salesTrendCustom');
    if ($custom.data('daterangepicker')) {
      try { $custom.data('daterangepicker').remove(); } catch(e){}
    }
    $custom.daterangepicker({
      autoUpdateInput: false,
      opens: 'right',
      locale: { format: 'YYYY-MM-DD', cancelLabel: 'Clear' },
      alwaysShowCalendars: true,
      linkedCalendars: false,
      showDropdowns: true
    });

    bindOnce();

    // First load (makes things appear immediately)
    $('#salesTrendPreset').val('7d').trigger('change');
    loadYearKPIs();
    populateCategoryDropdown().then(() => {
      track($.getJSON('/admin/get-top-category?range=week'))
        .done(resp => {
          const topCat = resp.topCategory;
          if (topCat) {
            $('#categorySelect').val(topCat);
            $('#prodCategorySelect').val(topCat);
            $('#categoryRangeSelect').val('week');
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

    // Auto refresh loop for “realtime” feel
    addTimer(setInterval(() => {
      if (!document.getElementById('salesOverview')) return; // still visible?
      loadYearKPIs(); // KPI row
      const preset = $('#salesTrendPreset').val();
      const yoyVal = $('#salesTrendYOY').val();
      if (preset && preset !== 'custom') {
        loadSales(preset, null, null, 'prev');
      } else if (yoyVal) {
        loadSales('year', null, null, 'yoy', parseInt(yoyVal, 10));
      }
      refreshCategoryKPIs();
      refreshProductList();
      refreshServiceList();
    }, REFRESH_MS));
  }

  function destroy() {
    // Stop any refreshing + kill requests + charts + handlers
    clearTimers();
    abortAll();
    destroyCharts();
    $(document).off(ns); // removes all namespaced handlers
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

    track($.getJSON(`/admin/get-dashboard-stats?range=custom&start=${curStart}&end=${curEnd}&compare=none`))
      .done(curData => {
        const curRev  = curData.sales?.totalRevenue || 0;
        const curTxns = curData.sales?.totalTransactions || 0;
        $('#kpiRevenue').text(peso(curRev));
        $('#kpiTxns').text(curTxns);

        track($.getJSON(`/admin/get-dashboard-stats?range=custom&start=${prevStart}&end=${prevEnd}&compare=none`))
          .done(prevData => {
            const prevRev = prevData.sales?.totalRevenue || 0;
            // keep original IDs: kpiAov shows last year's revenue in your UI
            $('#kpiAov').text(peso(prevRev));

            let revPctChange = 0;
            if (prevRev > 0) revPctChange = ((curRev - prevRev) / prevRev) * 100;
            const revPctRounded = parseFloat(revPctChange.toFixed(1));
            const convText = (revPctRounded >= 0 ? '+' : '') + `${revPctRounded}%`;
            $('#kpiConv').text(convText)
              .toggleClass('up', revPctRounded > 0)
              .toggleClass('down', revPctRounded < 0)
              .toggleClass('neutral', revPctRounded === 0);

            const $growthIcon = $('#growthIcon').removeClass('up down neutral fa-arrow-up fa-arrow-down');
            if (revPctRounded > 0) $growthIcon.addClass('up fa-arrow-up');
            else if (revPctRounded < 0) $growthIcon.addClass('down fa-arrow-down');
            else $growthIcon.addClass('neutral fa-arrow-down');
          })
          .fail(() => {
            $('#kpiAov').text('₱0');
            $('#kpiConv').text('0%').removeClass('up down').addClass('neutral');
            $('#growthIcon').removeClass('up down').addClass('neutral fa-arrow-down');
          });
      })
      .fail(() => {
        $('#kpiRevenue').text('₱0');
        $('#kpiTxns').text(0);
        $('#kpiAov').text('₱0');
        $('#kpiConv').text('0%').removeClass('up down').addClass('neutral');
        $('#growthIcon').removeClass('up down').addClass('neutral fa-arrow-down');
      });
  }

  function loadSales(range, start, end, compare, year) {
    // YOY: fetch two custom windows (no compare) and render side-by-side
    if (compare === 'yoy' && typeof year === 'number') {
      const curYear  = year;
      const prevYear = year - 1;
      const curStart = `${curYear}-01-01`;
      const curEnd   = `${curYear}-12-31`;
      const prevStart= `${prevYear}-01-01`;
      const prevEnd  = `${prevYear}-12-31`;

      track($.getJSON(`/admin/get-dashboard-stats?range=custom&start=${curStart}&end=${curEnd}&compare=none`))
        .done(curData => {
          track($.getJSON(`/admin/get-dashboard-stats?range=custom&start=${prevStart}&end=${prevEnd}&compare=none`))
            .done(prevData => {
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
            })
            .fail(renderTrendZero);
        })
        .fail(renderTrendZero);
      return;
    }

    // TODAY vs PREV
    if (range === 'today' && compare === 'prev') {
      track($.getJSON(`/admin/get-dashboard-stats?range=today&compare=prev`))
        .done(renderTrendFromApi)
        .fail(renderTrendZero);
      return;
    }

    // Other ranges + prev compare (or none)
    let qs = `?range=${encodeURIComponent(range)}&compare=${encodeURIComponent(compare || 'prev')}`;
    if (range === 'custom') qs += `&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`;
    track($.getJSON(`/admin/get-dashboard-stats${qs}`))
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

  function refreshCategoryKPIs() {
    const category = $('#categorySelect').val();
    const range = $('#categoryRangeSelect').val() || 'week';

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

    track($.getJSON(`/admin/get-sales-by-category?category=${encodeURIComponent(category)}&range=${encodeURIComponent(range)}`))
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
          series: [{ data: [lastRev, rev] }],
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

    track($.getJSON(`/admin/get-sales-by-product?category=${encodeURIComponent(category)}&range=${encodeURIComponent(range)}`))
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

    track($.getJSON(`/admin/get-sales-by-service?range=${encodeURIComponent(range)}`))
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
