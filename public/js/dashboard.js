let salesTrendChart = null;
let stockByCategoryChartInstance = null;
let valueByCategoryChartInstance = null;
let appointmentTrendChart = null;

// ─── Helper for percent arrows ─────────────────────────────────────────────
function setChange(selector, percent) {
  const el = $(selector);
  el.removeClass('up down neutral');
  if (percent > 0) {
    el.addClass('up').html(`<span>+${percent}%</span><span class="arrow">&#8599;</span>`);
  } else if (percent < 0) {
    el.addClass('down').html(`<span>${percent}%</span><span class="arrow">&#8600;</span>`);
  } else {
    el.addClass('neutral').html(`<span>0%</span><span class="arrow">&#8594;</span>`);
  }
}

$(function() {
  // ─── 1) Populate YOY dropdown dynamically for Sales Trend ────────────────
  const currentYear = new Date().getFullYear();
  const $yoy = $('#salesTrendYOY');
  for (let y = currentYear; y > currentYear - 5; y--) {
    const text = `${y}-${y - 1}`;
    $yoy.append(`<option value="${y}">${text}</option>`);
  }

  // ─── 2) Initialize Custom Range picker for Sales Trend ─────────────────
  $('#salesTrendCustom')
    .daterangepicker({
      autoUpdateInput: false,
      opens: 'right',
      locale: {
        format: 'YYYY-MM-DD',
        cancelLabel: 'Clear'
      },
      alwaysShowCalendars: true,
      linkedCalendars: false,
      showDropdowns: true
    })
    .on('apply.daterangepicker', (e, picker) => {
      const start = picker.startDate.format('YYYY-MM-DD');
      const end   = picker.endDate.format('YYYY-MM-DD');
      $(e.target).val(`${start} to ${end}`);
      loadSales('custom', start, end, 'prev');
    })
    .on('cancel.daterangepicker', e => {
      $(e.target).val('');
      const preset = $('#salesTrendPreset').val();
      loadSales(preset, null, null, 'prev');
    });

  // ─── 3) Show/hide custom input when “Custom Range” chosen ─────────────
  $('#salesTrendPreset').on('change', function() {
    const val = $(this).val();
    if (val === 'today') {
      $('#salesTrendCustom').hide().val('');
      loadSales('today', null, null, 'prev');
    } else if (val === 'custom') {
      $('#salesTrendCustom').show().val('');
    } else {
      $('#salesTrendCustom').hide().val('');
      loadSales(val, null, null, 'prev');
    }
  });

  // ─── 4) When YOY dropdown changes, load YoY mode ───────────────────────
  $('#salesTrendYOY').on('change', function() {
    $('#salesTrendPreset').val('');
    $('#salesTrendCustom').hide().val('');
    const selectedYear = parseInt($(this).val(), 10);
    loadSales('year', null, null, 'yoy', selectedYear);
  });

  // ─── 5) Initial load for Sales Trend: “Last 7 Days” ─────────────────────
  $('#salesTrendPreset').val('7d').trigger('change');

  // ─── 6) Inventory init (unchanged) ────────────────────────────────────
  $('#inventoryRange').on('change', () => {
    loadInventoryOverview($('#inventoryRange').val());
  });
  loadInventoryOverview();
  loadYearKPIs();

  // ─── 7) Populate “Sales by Category” & “Sales by Product” dropdowns ─────
  // Let the Expired Products dropdown drive its table
$(document).on('change', '#expiredCategorySelect', refreshExpiredProductsList);

  populateCategoryDropdown().then(() => {
    // After categories are loaded, fetch the top category for the last 7 days
    $.getJSON('/admin/get-top-category?range=week')
      .done(resp => {
        const topCat = resp.topCategory;
        if (topCat) {
          $('#categorySelect').val(topCat);
          $('#prodCategorySelect').val(topCat);
          $('#categoryRangeSelect').val('week');
          $('#prodRangeSelect').val('day');
          // Trigger immediate loads:
          refreshCategoryKPIs();
          refreshProductList();
        } else {
          refreshCategoryKPIs();
          refreshProductList();
        }
      })
      .fail(() => {
        refreshCategoryKPIs();
        refreshProductList();
      });
  });

  // ─── 8) When category or range changes, refresh KPIs / product list ─────────
  $('#categorySelect, #categoryRangeSelect').on('change', refreshCategoryKPIs);
  $('#prodCategorySelect, #prodRangeSelect').on('change', refreshProductList);

  // ─── 9) Search filtering for product list ─────────────────────────────────
  $('#prodSearchInput').on('input', () => {
    refreshProductList();
  });
});

// ─── Refresh “Sales by Category” KPIs ─────────────────────────────────────
function refreshCategoryKPIs() {
  const category = $('#categorySelect').val();
  const range = $('#categoryRangeSelect').val() || 'week';

  if (!category) {
    $('#catSales, #catProfit, #catLoss, #catRate').text('₱0');
    setChange('#catGrowth', 0);
    $('#catComparisonText').text('');
    if (window.catSparklineChart) {
      window.catSparklineChart.destroy();
      $('#catSparkline').html('');
    }
    return;
  }

  $.getJSON(
    `/admin/get-sales-by-category?category=${encodeURIComponent(category)}&range=${encodeURIComponent(range)}`
  )
  .done(data => {
    const rev = data.totalRevenue || 0;
    const cogs = data.totalCOGS || 0;
    const loss = data.totalExpiredLoss || 0;
    const profit = Math.max(rev - cogs - loss, 0);

    // Update current KPIs:
    $('#catSales').text('₱' + rev.toLocaleString());
    $('#catProfit').text('₱' + profit.toLocaleString());
    $('#catLoss').text('₱' + loss.toLocaleString());

    // Compute growth % vs previous period:
    const lastRev = data.lastPeriodRevenue || 0;
    let pctGrowth = 0;
    if (lastRev > 0) {
      pctGrowth = ((rev - lastRev) / lastRev) * 100;
    }
    const pctRounded = parseFloat(pctGrowth.toFixed(1));
    setChange('#catGrowth', Math.round(pctRounded));

    // Update “Sales Rate” small sparkline & percent text:
    $('#catRate').text((pctRounded >= 0 ? '+' : '') + `${pctRounded}%`);

    // If there's already a previous chart, destroy it:
    if (window.catSparklineChart) {
      window.catSparklineChart.destroy();
      $('#catSparkline').html('');
    }

    // Build a mini sparkline with two points: [ lastRev, rev ]
    const isUp = pctRounded > 0;
    const sparklineOptions = {
      chart: {
        type: 'line',
        height: 20,
        width: 50,
        sparkline: { enabled: true }
      },
      series: [{
        data: [lastRev, rev]
      }],
      stroke: {
        curve: 'smooth',
        width: 2
      },
      colors: [ isUp ? '#28a745' : '#e74c3c' ], // green if up, red if down
      tooltip: { enabled: false }
    };
    window.catSparklineChart = new ApexCharts(
      document.querySelector('#catSparkline'),
      sparklineOptions
    );
    window.catSparklineChart.render();

    // Finally, show a comparison sentence below:
    let comparisonText = '';
    if (range === 'day') {
      if (pctRounded > 0) {
        comparisonText = 'Your today’s sales are performing better than yesterday.';
      } else if (pctRounded < 0) {
        comparisonText = 'Your today’s sales are lower than yesterday.';
      } else {
        comparisonText = 'Your today’s sales are the same as yesterday.';
      }
    } else if (range === 'week') {
      if (pctRounded > 0) {
        comparisonText = 'Your sales in the last 7 days are higher than the previous 7 days.';
      } else if (pctRounded < 0) {
        comparisonText = 'Your sales in the last 7 days are lower than the previous 7 days.';
      } else {
        comparisonText = 'Your sales in the last 7 days are the same as the previous 7 days.';
      }
    } else if (range === 'month') {
      if (pctRounded > 0) {
        comparisonText = 'This month’s sales are higher than last month.';
      } else if (pctRounded < 0) {
        comparisonText = 'This month’s sales are lower than last month.';
      } else {
        comparisonText = 'This month’s sales are the same as last month.';
      }
    } else if (range === 'year') {
      if (pctRounded > 0) {
        comparisonText = 'This year’s sales are higher than last year.';
      } else if (pctRounded < 0) {
        comparisonText = 'This year’s sales are lower than last year.';
      } else {
        comparisonText = 'This year’s sales are the same as last year.';
      }
    } else {
      // fallback
      if (pctRounded > 0) {
        comparisonText = 'Current period sales are higher than the previous period.';
      } else if (pctRounded < 0) {
        comparisonText = 'Current period sales are lower than the previous period.';
      } else {
        comparisonText = 'Current period sales are the same as the previous period.';
      }
    }
    $('#catComparisonText').text(comparisonText);
  })
  .fail(() => {
    console.warn(
      'Failed to load sales-by-category for:',
      $('#categorySelect').val(),
      'range:',
      $('#categoryRangeSelect').val()
    );
    $('#catSales').text('₱0');
    $('#catProfit').text('₱0');
    $('#catLoss').text('₱0');
    $('#catRate').text('0%');
    setChange('#catGrowth', 0);
    $('#catComparisonText').text('');
    if (window.catSparklineChart) {
      window.catSparklineChart.destroy();
      $('#catSparkline').html('');
    }
  });
}

// ─── Refresh “Sales by Product” Table ─────────────────────────────────────
function refreshProductList() {
  const category = $('#prodCategorySelect').val() || '';
  const range = $('#prodRangeSelect').val() || 'day';
  const searchTerm = $('#prodSearchInput').val().toLowerCase();

  // Clear table & “no data” message
  const $tbody = $('#salesByProdTable tbody').empty();
  $('#prodNoData').hide();

  // Build query params
  const qCategory = encodeURIComponent(category);
  const qRange = encodeURIComponent(range);

  // If no category selected → fetch all products
  // Endpoint: /admin/get-sales-by-product?category=<>&range=<>
  // It should return an array: [{ productName, unitsSold, revenue }, ...]
  $.getJSON(`/admin/get-sales-by-product?category=${qCategory}&range=${qRange}`)
    .done(data => {
      let items = data.products || [];

      // Apply client-side search filter if needed
      if (searchTerm) {
        items = items.filter(item =>
          item.productName.toLowerCase().includes(searchTerm)
        );
      }

      if (!items.length) {
        $('#prodNoData').show();
        return;
      }

      // Populate table
      items.forEach(item => {
        const units = item.unitsSold || 0;
        const rev   = item.revenue || 0;
        $tbody.append(`
          <tr>
            <td>${item.productName}</td>
            <td class="text-right">${units.toLocaleString()}</td>
            <td class="text-right">₱${rev.toLocaleString()}</td>
          </tr>
        `);
      });
    })
    .fail(() => {
      console.warn(
        'Failed to load sales-by-product for:',
        category,
        'range:',
        range
      );
      $('#prodNoData').text('Error loading products.').show();
    });
}

// ─── Fetch “Current Year YTD” and “Last Calendar Year” KPIs ─────────────────
function loadYearKPIs() {
  const today = new Date();
  const currentYear = today.getFullYear();

  const curStart = `${currentYear}-01-01`;
  const curEnd = today.toISOString().slice(0, 10);

  const prevYear = currentYear - 1;
  const prevStart = `${prevYear}-01-01`;
  const prevEnd = `${prevYear}-12-31`;

  $.getJSON(`/admin/get-dashboard-stats?range=custom&start=${curStart}&end=${curEnd}&compare=none`)
    .done(curData => {
      const curRev = curData.sales?.totalRevenue || 0;
      const curTxns = curData.sales?.totalTransactions || 0;
      $('#kpiRevenue').text('₱' + curRev.toLocaleString());
      $('#kpiTxns').text(curTxns);

      $.getJSON(`/admin/get-dashboard-stats?range=custom&start=${prevStart}&end=${prevEnd}&compare=none`)
        .done(prevData => {
          const prevRev = prevData.sales?.totalRevenue || 0;
          const prevTxns = prevData.sales?.totalTransactions || 0;
          $('#kpiAov').text('₱' + prevRev.toLocaleString());

          let revPctChange = 0;
          if (prevRev > 0) revPctChange = ((curRev - prevRev) / prevRev) * 100;
          const revPctRounded = parseFloat(revPctChange.toFixed(1));
          $('#kpiRevChange').text((revPctRounded >= 0 ? '+' : '') + `${revPctRounded}%`);
          setChange('#kpiRevChange', Math.round(revPctRounded));

          let txnPctChange = 0;
          if (prevTxns > 0) txnPctChange = ((curTxns - prevTxns) / prevTxns) * 100;
          const txnPctRounded = parseFloat(txnPctChange.toFixed(1));
          $('#kpiTxnChange').text((txnPctRounded >= 0 ? '+' : '') + `${txnPctRounded}%`);
          setChange('#kpiTxnChange', Math.round(txnPctRounded));

          const convText = (revPctRounded >= 0 ? '+' : '') + `${revPctRounded}%`;
          $('#kpiConv').text(convText);
          const $growthIcon = $('#growthIcon');
          $growthIcon.removeClass('up down neutral fa-arrow-up fa-arrow-down');
          if (revPctRounded > 0) {
            $('#kpiConv').addClass('up').removeClass('down neutral');
            $growthIcon.addClass('up fa-arrow-up');
          } else if (revPctRounded < 0) {
            $('#kpiConv').addClass('down').removeClass('up neutral');
            $growthIcon.addClass('down fa-arrow-down');
          } else {
            $('#kpiConv').addClass('neutral').removeClass('up down');
            $growthIcon.addClass('neutral fa-arrow-down');
          }
        })
        .fail(() => {
          console.warn('Failed to load full last-year data.');
          $('#kpiAov').text('₱0');
          $('#kpiRevChange').text('0%');
          setChange('#kpiRevChange', 0);
          $('#kpiTxnChange').text('0%');
          setChange('#kpiTxnChange', 0);
          $('#kpiConv').text('0%').removeClass('up down').addClass('neutral');
          $('#growthIcon').removeClass('up down').addClass('neutral fa-arrow-down');
        });
    })
    .fail(() => {
      console.warn('Failed to load current-year YTD data.');
      $('#kpiRevenue').text('₱0');
      $('#kpiTxns').text(0);
      $('#kpiAov').text('₱0');
      $('#kpiRevChange').text('0%');
      setChange('#kpiRevChange', 0);
      $('#kpiTxnChange').text('0%');
      setChange('#kpiTxnChange', 0);
      $('#kpiConv').text('0%').removeClass('up down').addClass('neutral');
      $('#growthIcon').removeClass('up down').addClass('neutral fa-arrow-down');
    });
}

/**
 * @param {string}   range   – 'today' | '7d' | '30d' | 'month' | 'year' | 'custom'
 * @param {string?}  start   – e.g. '2024-01-01' if range==='custom'
 * @param {string?}  end     – e.g. '2024-12-31' if range==='custom'
 * @param {string}   compare – 'prev' | 'yoy' | 'none'
 * @param {number?}  year    – only used when compare==='yoy'
 */
function loadSales(range, start, end, compare, year) {
  // ─── 1) YOY BRANCH (compare === 'yoy') ─────────────────────────────────
  if (compare === 'yoy' && typeof year === 'number') {
    const curYear  = year;
    const prevYear = year - 1;

    console.log('YOY branch triggered:', curYear, 'vs', prevYear);

    // Build “2024-01-01 → 2024-12-31” and “2023-01-01 → 2023-12-31”
    const curStart  = `${curYear}-01-01`;
    const curEnd    = `${curYear}-12-31`;
    const prevStart = `${prevYear}-01-01`;
    const prevEnd   = `${prevYear}-12-31`;

    // 1a) Fetch “curYear” data
    $.getJSON(
      `/admin/get-dashboard-stats?range=custom&start=${curStart}&end=${curEnd}&compare=none`
    ).done(curData => {
      // 1b) Fetch “prevYear” data
      $.getJSON(
        `/admin/get-dashboard-stats?range=custom&start=${prevStart}&end=${prevEnd}&compare=none`
      ).done(prevData => {
        // Extract current & previous profits(!!!)
        const curSales    = curData.sales?.totalRevenue        || 0;
        const prevSales   = prevData.sales?.totalRevenue       || 0;
        const curTxns     = curData.sales?.totalTransactions   || 0;
        const prevTxns    = prevData.sales?.totalTransactions  || 0;
        const curProfit   = curData.sales?.profit              || 0;
        // ← THIS must be `.sales.profit`, not `.sales.comparison.prevProfit`
        const prevProfit  = prevData.sales?.profit             || 0;

        // YoY growth % calculation
        let pctGrowth = 0;
        if (prevSales > 0) {
          pctGrowth = ((curSales - prevSales) / prevSales) * 100;
        }
        const pctRounded = pctGrowth.toFixed(1);

        // Destroy existing chart (if any)
        if (salesTrendChart) {
          salesTrendChart.destroy();
          $('#salesTrendChart').html('');
        }

        // Show KPI table and fill in labels
        $('#salesTrendKPITable').show();
        $('#stCurLabel'). text(`${curYear}`);
        $('#stPrevLabel').text(`${prevYear}`);
        $('#stCurSales'). text(`₱${curSales.toLocaleString()}`);
        $('#stCurTxns').  text(curTxns);
        $('#stCurProfit').text(`₱${curProfit.toLocaleString()}`);
        $('#stPrevSales'). text(`₱${prevSales.toLocaleString()}`);
        $('#stPrevTxns').  text(prevTxns);
        $('#stPrevProfit').text(`₱${prevProfit.toLocaleString()}`);

        // Build and render a two‐bar comparison chart: [curYear, prevYear]
        salesTrendChart = new ApexCharts(
          document.querySelector('#salesTrendChart'),
          {
            chart: {
              type: 'bar',
              height: 320,
              toolbar: { show: false }
            },
            series: [
              { name: 'Sales (₱)',       data: [curSales,    prevSales] },
              { name: 'Transactions',     data: [curTxns,     prevTxns] },
              { name: 'Profit (₱)',       data: [curProfit,   prevProfit] }
            ],
            xaxis: {
              categories: [`${curYear}`, `${prevYear}`],
              labels: { style: { fontSize: '13px' } }
            },
            yaxis: {
              labels: {
                formatter: (val) => Number(val.toFixed(0)).toLocaleString()
              }
            },
            colors: ['#008FFB', '#FEB019', '#28A745'],
            plotOptions: {
              bar: {
                columnWidth: '45%',
                dataLabels: { position: 'top' }
              }
            },
            dataLabels: {
              enabled: true,
              offsetY: -28,
              style: {
                colors: ['#222'],
                fontWeight: 700,
                fontSize: '15px'
              },
              background: {
                enabled: true,
                foreColor: '#fff',
                borderRadius: 4,
                opacity: 0.95,
                padding: 3,
                dropShadow: { enabled: false }
              },
              formatter: (val, opts) => {
                const seriesIdx = opts.seriesIndex;
                const pointIdx  = opts.dataPointIndex;
                if (seriesIdx === 0 && pointIdx === 0) {
                  // On the “current” (2024) bar of the “Sales” series:
                  // show two lines: “₱<curSales>” + “+<growth>%”
                  return `₱${Number(val).toLocaleString()}\n${
                    pctGrowth >= 0 ? '+' : ''
                  }${pctRounded}%`;
                }
                if (seriesIdx === 0) {
                  return `₱${Number(val).toLocaleString()}`;
                }
                if (seriesIdx === 1) {
                  return `${Number(val).toLocaleString()}`;
                }
                // seriesIdx === 2
                return `₱${Number(val).toLocaleString()}`;
              }
            },
            legend: {
              show: true,
              position: 'top',
              horizontalAlign: 'right'
            },
            tooltip: {
              y: (v, opts) => {
                // Format currency for “Sales” and “Profit” series
                if (opts.seriesIndex === 0 || opts.seriesIndex === 2) {
                  return `₱${Number(v).toLocaleString()}`;
                }
                return `${Number(v).toLocaleString()}`;
              }
            }
          }
        );
        salesTrendChart.render();
      }).fail(() => {
        console.warn('Failed to fetch prevYear data');
      });
    }).fail(() => {
      console.warn('Failed to fetch curYear data');
    });

    return;
  }

  // ─── 2) “Today” (compare = 'prev') ────────────────────────────────────────
  // ─── 2) “Today” (compare = 'prev') ────────────────────────────────────────
  if (range === 'today' && compare === 'prev') {
    // We ask the server to compute “today vs. yesterday” all at once.
    $.getJSON(`/admin/get-dashboard-stats?range=today&compare=prev`)
      .done(data => {
        // Extract today’s and yesterday’s numbers (or zeroes, if no data)
        const curRev       = data.sales.totalRevenue       || 0;
        const curTxns      = data.sales.totalTransactions  || 0;
        const curProfit    = data.sales.profit             || 0;
        const prevRev      = data.sales.comparison.prevRevenue      || 0;
        const prevTxns     = data.sales.comparison.prevTransactions || 0;
        const prevProfit   = data.sales.comparison.prevProfit       || 0;

        // Build labels “Aug 25” / “Aug 24” (or whatever today/yesterday are)
        const todayLabel     = moment().format('MMM D');
        const yesterdayLabel = moment().subtract(1, 'day').format('MMM D');

        // Compute % growth (just for the “Sales” data‐label)
        let pctGrowth = 0;
        if (prevRev > 0) {
          pctGrowth = ((curRev - prevRev) / prevRev) * 100;
        }
        const pctRounded = pctGrowth.toFixed(1);

        // Destroy any existing chart, then show the KPI table
        if (salesTrendChart) {
          salesTrendChart.destroy();
          $('#salesTrendChart').html('');
        }
        $('#salesTrendKPITable').show();
        $('#stCurLabel'). text(todayLabel);
        $('#stPrevLabel').text(yesterdayLabel);
        $('#stCurSales'). text(`₱${curRev.toLocaleString()}`);
        $('#stCurTxns').  text(curTxns);
        $('#stCurProfit').text(`₱${curProfit.toLocaleString()}`);
        $('#stPrevSales'). text(`₱${prevRev.toLocaleString()}`);
        $('#stPrevTxns').  text(prevTxns);
        $('#stPrevProfit').text(`₱${prevProfit.toLocaleString()}`);

        // Render a two‐bar chart ([Today, Yesterday] → [curRev, prevRev], etc.)
        salesTrendChart = new ApexCharts(
          document.querySelector('#salesTrendChart'),
          {
            chart: {
              type: 'bar',
              height: 320,
              toolbar: { show: false }
            },
            series: [
              { name: 'Sales (₱)',       data: [curRev,    prevRev] },
              { name: 'Transactions',     data: [curTxns,   prevTxns] },
              { name: 'Profit (₱)',       data: [curProfit, prevProfit] }
            ],
            xaxis: {
              categories: [todayLabel, yesterdayLabel],
              labels: { style: { fontSize: '13px' } }
            },
            yaxis: {
              labels: {
                formatter: val => Number(val.toFixed(0)).toLocaleString()
              }
            },
            colors: ['#008FFB', '#FEB019', '#28A745'],
            plotOptions: {
              bar: {
                columnWidth: '45%',
                dataLabels: { position: 'top' }
              }
            },
            dataLabels: {
              enabled: true,
              offsetY: -28,
              style: {
                colors: ['#222'],
                fontWeight: 700,
                fontSize: '15px'
              },
              background: {
                enabled: true,
                foreColor: '#fff',
                borderRadius: 4,
                opacity: 0.95,
                padding: 3,
                dropShadow: { enabled: false }
              },
              formatter: (val, opts) => {
                const seriesIdx = opts.seriesIndex;
                const pointIdx  = opts.dataPointIndex;
                if (seriesIdx === 0 && pointIdx === 0) {
                  // On the “today” bar of the “Sales” series, show:
                  //   ₱<todayRevenue>
                  // +<growth>% (if any)
                  return `₱${Number(val).toLocaleString()}\n${
                    pctGrowth >= 0 ? '+' : ''
                  }${pctRounded}%`;
                }
                if (seriesIdx === 0) {
                  return `₱${Number(val).toLocaleString()}`;
                }
                if (seriesIdx === 1) {
                  return `${Number(val).toLocaleString()}`;
                }
                // seriesIdx === 2 (“Profit”)
                return `₱${Number(val).toLocaleString()}`;
              }
            },
            legend: {
              show: true,
              position: 'top',
              horizontalAlign: 'right'
            },
            tooltip: {
              y: (v, opts) => {
                // Format currency for “Sales” and “Profit” series
                if (opts.seriesIndex === 0 || opts.seriesIndex === 2) {
                  return `₱${Number(v).toLocaleString()}`;
                }
                return `${Number(v).toLocaleString()}`;
              }
            }
          }
        );
        salesTrendChart.render();
      })
      .fail(() => {
        // If the AJAX itself fails, zero everything out and draw [0, 0]
        $('#salesTrendKPITable').show();
        $('#stCurLabel'). text('Today');
        $('#stPrevLabel').text('Yesterday');
        $('#stCurSales'). text('₱0');
        $('#stCurTxns').  text('0');
        $('#stCurProfit').text('₱0');
        $('#stPrevSales'). text('₱0');
        $('#stPrevTxns').  text('0');
        $('#stPrevProfit').text('₱0');

        if (salesTrendChart) {
          salesTrendChart.destroy();
          $('#salesTrendChart').html('');
        }
        const todayLabel = moment().format('MMM D');
        const yesterday = moment().subtract(1, 'day').format('MMM D');
        salesTrendChart = new ApexCharts(
          document.querySelector('#salesTrendChart'),
          {
            chart: { type: 'bar', height: 320, toolbar: { show: false } },
            series: [
              { name: 'Sales (₱)', data: [0, 0] },
              { name: 'Transactions', data: [0, 0] },
              { name: 'Profit (₱)', data: [0, 0] }
            ],
            xaxis: {
              categories: [todayLabel, yesterday],
              labels: { style: { fontSize: '13px' } }
            },
            yaxis: {
              labels: {
                formatter: val => Number(val.toFixed(0)).toLocaleString()
              }
            },
            colors: ['#008FFB', '#FEB019', '#28A745'],
            plotOptions: {
              bar: {
                columnWidth: '45%',
                dataLabels: { position: 'top' }
              }
            },
            dataLabels: {
              enabled: false // no need to show zero labels
            },
            legend: {
              show: false
            }
          }
        );
        salesTrendChart.render();
      });

    return;
  }


  // ─── 3) ALL OTHER “compare=prev” CASES (“7d”, “30d”, “month”, “year”, “custom”) ─────────────
  let qs = `?range=${range}&compare=${compare}`;
  if (range === 'custom') {
    qs += `&start=${start}&end=${end}`;
  }

  $.getJSON(`/admin/get-dashboard-stats${qs}`)
    .done(data => {
      const s = data.sales || {};
      const u = data.userStats || {};

      // ── 3a) Update your small KPI cards (unchanged) ─────────────────────────
     
      const doctorsChange   = u.doctorsChange || 0;
      const hrChange        = u.hrChange || 0;
      const customersChange = u.customersChange || 0;
      const newC = data.descriptive?.newCustomers       || 0;
      const retC = data.descriptive?.returningCustomers || 0;
      const totCR = newC + retC || 1;
      const retentionPercent = ((retC / totCR) * 100).toFixed(1);

      $('#doctorsCountSmall').text(u.doctors || 0);
      $('#hrCountSmall').     text(u.hr      || 0);
      $('#customersCountSmall').text(u.customers || 0);
      setChange('#doctorsChange',   doctorsChange);
      setChange('#hrChange',        hrChange);
      setChange('#customersChange', customersChange);
      setChange('#kpiRetPct',       retentionPercent);

      const isComparePrev = compare === 'prev';
      const isCompareYoY  = compare === 'yoy';

      // Destroy existing chart:
      if (salesTrendChart) {
        salesTrendChart.destroy();
        $('#salesTrendChart').html('');
      }

      // ── 3b) Build “current vs previous” labels ─────────────────────────────
      let curLabel  = '';
      let prevLabel = '';

      if (isCompareYoY) {
        // Already handled above
      } else if (isComparePrev) {
        // “Today” was handled. Now handle “7d”, “30d”, “month”, “quarter”, “year”, “custom”
        if (range === '7d') {
          const now     = moment().endOf('day');
          const curFrom = now.clone().subtract(6, 'days').startOf('day');
          const curTo   = now.clone().endOf('day');
          const prevTo  = curFrom.clone().subtract(1, 'day').endOf('day');
          const prevFrom= prevTo.clone().subtract(6, 'days').startOf('day');

          curLabel  = `${curFrom.format('MMM D')} – ${curTo.format('MMM D')}`;
          prevLabel = `${prevFrom.format('MMM D')} – ${prevTo.format('MMM D')}`;
        } else if (range === '30d') {
          const now     = moment().endOf('day');
          const curFrom = now.clone().subtract(29, 'days').startOf('day');
          const curTo   = now.clone().endOf('day');
          const prevTo  = curFrom.clone().subtract(1, 'day').endOf('day');
          const prevFrom= prevTo.clone().subtract(29, 'days').startOf('day');

          curLabel  = `${curFrom.format('MMM D')} – ${curTo.format('MMM D')}`;
          prevLabel = `${prevFrom.format('MMM D')} – ${prevTo.format('MMM D')}`;
        } else if (range === 'month') {
          const now     = moment().endOf('day');
          const curFrom = moment().startOf('month');
          const prevFrom= curFrom.clone().subtract(1, 'month').startOf('month');
          const prevTo  = now.clone().subtract(1, 'month');

          curLabel  = `${curFrom.format('MMM D')} – ${now.format('MMM D')}`;
          prevLabel = `${prevFrom.format('MMM D')} – ${prevTo.format('MMM D')}`;
        } else if (range === 'quarter') {
          const now       = moment().endOf('day');
          const curStartQ = moment().startOf('quarter');
          const prevStartQ= curStartQ.clone().subtract(1, 'quarter');
          const prevEndQ  = now.clone().subtract(1, 'quarter');

          curLabel  = `${curStartQ.format('MMM D')} – ${now.format('MMM D')}`;
          prevLabel = `${prevStartQ.format('MMM D')} – ${prevEndQ.format('MMM D')}`;
        } else if (range === 'year') {
          const now     = moment().endOf('day');
          const curFrom = moment().startOf('year');
          const prevFrom= curFrom.clone().subtract(1, 'year').startOf('year');
          const prevTo  = now.clone().subtract(1, 'year');

          curLabel  = `${curFrom.format('MMM D')} – ${now.format('MMM D')}`;
          prevLabel = `${prevFrom.format('MMM D')} – ${prevTo.format('MMM D')}`;
        } else if (range === 'custom' && start && end) {
          const curFrom  = moment(start, 'YYYY-MM-DD').startOf('day');
          const curTo    = moment(end,   'YYYY-MM-DD').endOf('day');
          const dayCount = curTo.diff(curFrom, 'days') + 1;
          const prevTo   = curFrom.clone().subtract(1, 'day').endOf('day');
          const prevFrom = prevTo.clone().subtract(dayCount - 1, 'days').startOf('day');

          curLabel  = `${curFrom.format('MMM D')} – ${curTo.format('MMM D')}`;
          prevLabel = `${prevFrom.format('MMM D')} – ${prevTo.format('MMM D')}`;
        }
      }

      // ── 3c) Draw comparison bar‐chart (current vs previous) ─────────────────
      if (isComparePrev) {
        const currentRev   = s.totalRevenue      || 0;
        const previousRev  = s.comparison?.prevRevenue      || 0;
        const currentTxns  = s.totalTransactions|| 0;
        const previousTxns = s.comparison?.prevTransactions || 0;
        const currentProfit= s.profit            || 0;
        const previousProfit= s.comparison?.prevProfit      || 0;

        // Compute growth % for “current vs previous”
        let pctGrowth = 0;
        if (previousRev > 0) {
          pctGrowth = ((currentRev - previousRev) / previousRev) * 100;
        }
        const pctRounded = pctGrowth.toFixed(1);

        // Render with exactly the same style as the YoY block:
        salesTrendChart = new ApexCharts(
          document.querySelector('#salesTrendChart'),
          {
            chart: {
              type: 'bar',
              height: 320,
              toolbar: { show: false }
            },
            series: [
              {
                name: 'Sales (₱)',
                data: [currentRev, previousRev]
              },
              {
                name: 'Transactions',
                data: [currentTxns, previousTxns]
              },
              {
                name: 'Profit (₱)',
                data: [currentProfit, previousProfit]
              }
            ],
            xaxis: {
              categories: [curLabel, prevLabel],
              labels: { style: { fontSize: '13px' } }
            },
            yaxis: {
              labels: {
                formatter: function(val) {
                  return Number(val.toFixed(0)).toLocaleString();
                }
              }
            },
            colors: ['#008FFB', '#FEB019', '#28A745'],
            plotOptions: {
              bar: {
                columnWidth: '45%',
                dataLabels: { position: 'top' }
              }
            },
            dataLabels: {
              enabled: true,
              offsetY: -28,
              style: {
                colors: ['#222'],
                fontWeight: 700,
                fontSize: '15px'
              },
              background: {
                enabled: true,
                foreColor: '#fff',
                borderRadius: 4,
                opacity: 0.95,
                padding: 3,
                dropShadow: { enabled: false }
              },
              formatter: function(val, opts) {
                const seriesIdx = opts.seriesIndex;
                const pointIdx  = opts.dataPointIndex;
                if (seriesIdx === 0 && pointIdx === 0) {
                  return `₱${Number(val).toLocaleString()}\n${pctGrowth >= 0 ? '+' : ''}${pctRounded}%`;
                }
                if (seriesIdx === 0) {
                  return `₱${Number(val).toLocaleString()}`;
                }
                if (seriesIdx === 1) {
                  return `${Number(val).toLocaleString()}`;
                }
                return `₱${Number(val).toLocaleString()}`;
              }
            },
            legend: {
              show: true,
              position: 'top',
              horizontalAlign: 'right'
            },
            tooltip: {
              y: (v, opts) => {
                const idx = opts.seriesIndex;
                if (idx === 0 || idx === 2) {
                  return `₱${Number(v).toLocaleString()}`;
                }
                return `${Number(v).toLocaleString()}`;
              }
            }
          }
        );
        salesTrendChart.render();

        // Also fill in the KPI table if you want (this part is exactly the same)
        $('#salesTrendKPITable').show();
        $('#stCurLabel'). text(curLabel);
        $('#stPrevLabel').text(prevLabel);
        $('#stCurSales'). text(`₱${currentRev.toLocaleString()}`);
        $('#stCurTxns').  text(currentTxns);
        $('#stCurProfit').text(`₱${currentProfit.toLocaleString()}`);
        $('#stPrevSales'). text(`₱${previousRev.toLocaleString()}`);
        $('#stPrevTxns').  text(previousTxns);
        $('#stPrevProfit').text(`₱${previousProfit.toLocaleString()}`);
      }

      // ── 3d) (Optional) Populate other tables if you have them…

    })
    .fail(() => {
      alert('Failed to load sales data.');
    });
}


// ─── Populate “Sales by Category” & “Sales by Product” dropdown ─────────────────
function populateCategoryDropdown() {
  const $catSel         = $('#categorySelect');          // Sales by Category (single)
  const $prodCatSel     = $('#prodCategorySelect');      // Sales by Product (filter)
  const $expiredCatSel  = $('#expiredCategorySelect');   // Expired Products (new)

  // Remember current selections so we can restore them after repopulating
  const prevCatSel        = $catSel.val();
  const prevProdCatSel    = $prodCatSel.val();
  const prevExpiredCatSel = $expiredCatSel.val();

  // Reset base options
  $catSel.empty().append('<option value="" disabled>Select Category</option>');
  $prodCatSel.empty().append('<option value="">All Categories</option>');
  if ($expiredCatSel.length) {
    $expiredCatSel.empty().append('<option value="">All Categories</option>');
  }

  // Fetch and populate
  return $.getJSON('/admin/get-categories')
    .done((categories = []) => {
      // Normalize + sort
      const list = categories
        .filter(c => typeof c === 'string' && c.trim().length)
        .map(c => c.trim())
        .sort((a, b) => a.localeCompare(b));

      list.forEach(cat => {
        const displayText = cat.charAt(0).toUpperCase() + cat.slice(1);

        // Sales by Category
        $catSel.append(`<option value="${cat}">${displayText}</option>`);

        // Sales by Product
        $prodCatSel.append(`<option value="${cat}">${displayText}</option>`);

        // Expired Products (if present in DOM)
        if ($expiredCatSel.length) {
          $expiredCatSel.append(`<option value="${cat}">${displayText}</option>`);
        }
      });

      // Restore previous selections if still available
      if (prevCatSel && list.includes(prevCatSel)) $catSel.val(prevCatSel);
      if (prevProdCatSel && (prevProdCatSel === '' || list.includes(prevProdCatSel))) {
        $prodCatSel.val(prevProdCatSel);
      }
      if ($expiredCatSel.length && prevExpiredCatSel !== undefined) {
        if (prevExpiredCatSel === '' || list.includes(prevExpiredCatSel)) {
          $expiredCatSel.val(prevExpiredCatSel);
        }
      }

      // Trigger change handlers if needed
      $catSel.trigger('change');         // refreshCategoryKPIs
      $prodCatSel.trigger('change');     // refreshProductList
      if ($expiredCatSel.length) {
        $expiredCatSel.trigger('change'); // your expired-products refresh handler
      }
    })
    .fail(() => {
      console.warn('Failed to load categories.');
    });
}

// ─── INVENTORY OVERVIEW ────────────────────────────────────────────────────
function loadInventoryOverview(range = 'all') {
  $.getJSON(`/admin/inventory-stats?range=${range}`)
    .done(data => {
      $('#invTotalSKUs').text(data.totalSKUs);
      $('#invTotalValue').text('₱' + data.totalValue.toLocaleString());
      $('#invCategories').text(data.categoriesCount);
      $('#invLowStockCount').text(data.lowStock.length);
      $('#invExpiringCount').text(data.expiringSoon.length);

      $('#turnoverRate').text(data.turnoverRate || '--');
      $('#daysLeft').text(data.daysLeft || '--');
      $('#topCategory').text(
        data.topCategory
          ? `${data.topCategory} (₱${Number(data.topCategoryValue).toLocaleString()})`
          : '--'
      );
      $('#nextExpiry').text(
        data.nextExpiry
          ? new Date(data.nextExpiry).toLocaleDateString()
          : '--'
      );

      if (stockByCategoryChartInstance) {
        stockByCategoryChartInstance.destroy();
        $('#stockByCategoryChart').html('');
      }
      if (valueByCategoryChartInstance) {
        valueByCategoryChartInstance.destroy();
        $('#valueByCategoryChart').html('');
      }

      stockByCategoryChartInstance = new ApexCharts(
        document.querySelector('#stockByCategoryChart'),
        {
          chart: { type: 'bar', height: 250, toolbar: { show: false } },
          series: [
            { name: 'Units', data: data.stockByCategory.map(x => x.totalStock) }
          ],
          xaxis: {
            categories: data.stockByCategory.map(x => x._id),
            labels: { rotate: -45 }
          },
          tooltip: { y: { formatter: v => v + ' units' } }
        }
      );
      stockByCategoryChartInstance.render();

      valueByCategoryChartInstance = new ApexCharts(
        document.querySelector('#valueByCategoryChart'),
        {
          chart: { type: 'donut', height: 250 },
          series: data.valueByCategory.map(x => x.totalValue),
          labels: data.valueByCategory.map(x => x._id),
          tooltip: { y: { formatter: v => '₱' + Number(v).toLocaleString() } }
        }
      );
      valueByCategoryChartInstance.render();

      $('#topSoldList').empty();
      data.topSold.forEach(p => {
        $('#topSoldList').append(`
          <li class="list-group-item d-flex justify-content-between">
            ${p._id} <span>${p.soldQuantity}</span>
          </li>
        `);
      });
    })
    .fail(() => {
      $('#inventoryOverview .card-body').html(
        '<p class="text-danger">Failed to load inventory data.</p>'
      );
    });
}
// ─── INVENTORY: Expired Products list ─────────────────────────────────────
function refreshExpiredProductsList() {
  const category = $('#expiredCategorySelect').val() || '';
  const $tbody = $('#expiredProductsTbody').empty();
  const $empty = $('#expiredProductsEmpty').hide().text('No expired products.');

  // Build URL safely
  const url = '/admin/expired-products' + (category ? `?category=${encodeURIComponent(category)}` : '');

  $.getJSON(url)
    .done(raw => {
      // Normalize possible response shapes
      const candidates = [
        raw?.items,
        raw?.data?.items,
        raw?.data,
        raw?.products,
        raw?.expired,
        Array.isArray(raw) ? raw : null
      ].filter(Boolean);

      const items = (candidates[0] || []).map(it => {
        const name =
          it.productName ?? it.name ?? it.title ?? it._id ?? '—';
        const count =
          it.expiredCount ?? it.count ?? it.quantity ?? it.total ?? 0;
        const lastRaw =
          it.lastExpired ?? it.lastExpiry ?? it.last_date ?? it.lastDate ?? it.last ?? null;

        let last = '--';
        if (lastRaw) {
          const d = new Date(lastRaw);
          if (!isNaN(d.getTime())) last = d.toLocaleDateString();
        }
        return { name, count: Number(count) || 0, last };
      });

      if (!items.length) {
        $empty.show();
        return;
      }

      items.forEach(({ name, count, last }) => {
        $tbody.append(`
          <tr>
            <td>${name}</td>
            <td class="text-right">${count.toLocaleString()}</td>
            <td class="text-right">${last}</td>
          </tr>
        `);
      });
    })
    .fail((jqXHR, textStatus, errorThrown) => {
      // Log full details for debugging
      console.error('[expired-products] AJAX failed', {
        status: jqXHR.status,
        statusText: jqXHR.statusText,
        textStatus,
        errorThrown,
        responseText: (jqXHR.responseText || '').slice(0, 500)
      });

      // Show a clear message to the user
      $empty.text('Error loading expired products.').show();
    });
}


// ─── APPOINTMENTS ──────────────────────────────────────────────────────────
// 1) Total Appointments + User Stats
function loadTotalAppointments() {
  $.getJSON('/admin/get-dashboard-stats')
    .done(data => {
      const total = (data.appointmentTrends?.completed || []).reduce((a, b) => a + b, 0);
      $('#kpiAppointments').text(total);
      $('#kpiAppChange').text('+0%');
      $('#kpiDoctors').text(data.userStats?.doctors ?? 0);
      $('#kpiDocChange').text('+0%');
      $('#kpiClients').text(data.userStats?.customers ?? 0);
    })
    .fail(() => {
      console.warn('Failed to load total appointments.');
    });
}

// 2) Peak Day-of-Week
let peakDayChartInstance = null;
function loadPeakDayOfWeek(range = '30d') {
  $.getJSON(`/admin/peak-day-of-week?range=${range}`)
    .done(resp => {
      if (peakDayChartInstance) {
        peakDayChartInstance.destroy();
        $('#peakDayChart').remove();
        $('#peakDayChartWrapper').append('<canvas id="peakDayChart"></canvas>');
      }
      const ctx = document.getElementById('peakDayChart').getContext('2d');
      peakDayChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: resp.days.map(d => d.dayLabel),
          datasets: [
            {
              label: 'Appointments',
              data: resp.days.map(d => d.count),
              borderColor: '#2196f3',
              backgroundColor: '#2196f3'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: { ticks: { autoSkip: false, maxRotation: 0 } },
            y: { beginAtZero: true, ticks: { stepSize: 1 } }
          },
          plugins: { legend: { display: false } }
        }
      });
      $('#peakDayTable tbody').html(
        resp.days
          .map(
            d =>
              `<tr><td>${d.dayLabel}</td><td class="text-right">${d.count}</td></tr>`
          )
          .join('')
      );
    })
    .fail(() => {
      $('#peakDayChart').hide();
      $('#peakDayTable tbody').html(
        '<tr><td colspan="2" class="text-center text-muted">No data.</td></tr>'
      );
    });
}

// 3) Appointment Trends Chart
function loadAppointmentTrendsChart(range = '7d') {
  $.getJSON(`/admin/get-dashboard-stats?range=${range}`)
    .done(data => {
      const tr = data.appointmentTrends || {};
      const labels = tr.labels || [];
      const pending = tr.pending || [];
      const approved = tr.approved || [];
      const completed = tr.completed || [];

      if (appointmentTrendChart) {
        appointmentTrendChart.destroy();
        $('#appointmentsTrendChart').html('');
      }
      if (!labels.length) {
        $('#appointmentsTrendChart').html(
          '<p class="text-center text-muted">No appointments data.</p>'
        );
        return;
      }
      appointmentTrendChart = new ApexCharts(
        document.querySelector('#appointmentsTrendChart'),
        {
          chart: { type: 'line', height: 250, toolbar: { show: false } },
          series: [
            { name: 'Pending', data: pending },
            { name: 'Approved', data: approved },
            { name: 'Completed', data: completed }
          ],
          xaxis: { categories: labels, labels: { rotate: -45 } },
          stroke: { curve: 'smooth', width: 2 },
          tooltip: { y: v => `${v}` }
        }
      );
      appointmentTrendChart.render();
    })
    .fail(() => {
      $('#appointmentsTrendChart').html(
        '<p class="text-center text-danger">Failed to load data.</p>'
      );
    });
}

// 4) Forecast (Next 3 Days)
let predictionChartInstance = null;
function loadPredictions() {
  $.getJSON('/admin/predict-appointments')
    .done(resp => {
      const preds = resp.predictions || [];
      const labels = preds.map(p => p.date.slice(5)); // “MM-DD”
      const data = preds.map(p => p.predictedCount);

      if (predictionChartInstance) {
        predictionChartInstance.destroy();
        $('#predictionChart').html('');
      }
      predictionChartInstance = new ApexCharts(
        document.querySelector('#predictionChart'),
        {
          chart: {
            type: 'area',
            height: 120,
            sparkline: { enabled: true }
          },
          series: [{ name: 'Forecast', data }],
          stroke: { curve: 'smooth', width: 2 },
          fill: { opacity: 0.3 },
          tooltip: { enabled: true, theme: 'light' }
        }
      );
      predictionChartInstance.render();

      const $fv = $('#forecastValues').empty();
      preds.forEach((p, i) => {
        const label =
          i === 0
            ? 'Tomorrow'
            : new Date(p.date).toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric'
              });
        $fv.append(`
          <div class="text-center" style="flex:1">
            <small class="text-muted d-block">${label}</small>
            <strong>${p.predictedCount}</strong>
          </div>
        `);
      });
    })
    .fail(() => {
      $('#predictionChart').html(
        '<p class="text-center text-danger">Failed to load forecast.</p>'
      );
    });
}

// 5) Event Bindings for Appointment Trends Tab
$('#appointmentTrendRange').on('change', () =>
  loadAppointmentTrendsChart($('#appointmentTrendRange').val())
);
$('#peakDayRange').on('change', () =>
  loadPeakDayOfWeek($('#peakDayRange').val())
);
$('a[href="#appointmentTrends"]').on('shown.bs.tab', () => {
  loadTotalAppointments();
  loadPeakDayOfWeek($('#peakDayRange').val());
  loadAppointmentTrendsChart($('#appointmentTrendRange').val());
  loadPredictions();
});

// 6) Initial calls for Appointments section
$(function() {
  loadTotalAppointments();
  loadPeakDayOfWeek($('#peakDayRange').val());
  loadAppointmentTrendsChart($('#appointmentTrendRange').val());
  loadPredictions();
});
// ────────────────────────────────────────────────────────────────────────────
// ─── 1) Populate “Service Category” dropdown ───────────────────────────────
function populateServiceCategoryDropdown() {
  const $svcCatSel = $('#servCategorySelect');
  $svcCatSel.empty().append('<option value="">All Service Categories</option>');

  // We fetch all service categories from the ServiceCategory collection:
  return $.getJSON('/services/categories/list')
    .done(categories => {
      categories.forEach(cat => {
        // Each `cat` should be something like { _id: '…', name: 'Grooming' }
        $svcCatSel.append(`<option value="${cat._id}">${cat.name}</option>`);
      });
    })
    .fail(() => {
      console.warn('Failed to load service categories.');
    });
}

// ─── 2) Refresh “Sales by Service” Table ───────────────────────────────────
function refreshServiceList() {
  const range = $('#servRangeSelect').val() || 'day';

  // Clear table & hide "no data" message
  const $tbody = $('#salesByServTable tbody').empty();
  $('#servNoData').hide();

  // Build query string: only time-range parameter
  const qRange = encodeURIComponent(range);

  $.getJSON(`/admin/get-sales-by-service?range=${qRange}`)
    .done(data => {
      const items = data.services || [];

      if (!items.length) {
        $('#servNoData').show();
        return;
      }

      items.forEach(item => {
        const count = item.unitsSold || 0;
        const rev   = item.revenue  || 0;
        $tbody.append(`
          <tr>
            <td>${item.serviceName}</td>
            <td class="text-right">${count.toLocaleString()}</td>
            <td class="text-right">₱${rev.toLocaleString()}</td>
          </tr>
        `);
      });
    })
    .fail(() => {
      console.warn('Failed to load sales-by-service for range:', range);
      $('#servNoData').text('Error loading data.').show();
    });
}

// Bind on change and initial load:
$(function() {
  $('#servRangeSelect').on('change', refreshServiceList);

  // Initial “Today” load:
  $('#servRangeSelect').val('day');
  refreshServiceList();
});
$(function() {
  // ── Initialize the daterangepicker for the “Report Range” input ──
  $('#reportRange').daterangepicker({
    autoUpdateInput: false,
    opens: 'right',
    locale: {
      format: 'YYYY-MM-DD',
      cancelLabel: 'Clear'
    },
    alwaysShowCalendars: true,
    linkedCalendars: false,
    showDropdowns: true
  })
  .on('apply.daterangepicker', function(ev, picker) {
    // When user selects dates, show them in the input:
    $(this).val(picker.startDate.format('YYYY-MM-DD') + ' to ' + picker.endDate.format('YYYY-MM-DD'));
  })
  .on('cancel.daterangepicker', function(ev) {
    $(this).val('');
  });

  // ── Click handler: Download Excel ───────────────────────────────────────
  $('#downloadExcelBtn').on('click', function() {
    let range = $('#reportRange').val().trim();
    // If no range chosen, just navigate to endpoint without params (full history)
    if (!range) {
      window.location.href = '/admin/downloadSalesExcel';
      return;
    }
    // Otherwise parse “YYYY-MM-DD to YYYY-MM-DD”
    const [start, end] = range.split(' to ');
    window.location.href = `/admin/downloadSalesExcel?start=${start}&end=${end}`;
  });

  // ── Click handler: Download CSV ────────────────────────────────────────
  $('#downloadCsvBtn').on('click', function() {
    let range = $('#reportRange').val().trim();
    if (!range) {
      window.location.href = '/admin/downloadSalesCSV';
      return;
    }
    const [start, end] = range.split(' to ');
    window.location.href = `/admin/downloadSalesCSV?start=${start}&end=${end}`;
  });


  // ─── When Inventory tab is shown, reload its data ─────────────────────
 $('a[href="#inventoryOverview"]').on('shown.bs.tab', function () {
  const invRange = $('#inventoryRange').length
    ? $('#inventoryRange').val()
    : 'all';
  loadInventoryOverview(invRange);
  refreshExpiredProductsList(); // <-- add this
});


  // ─── Force “shown.bs.tab” on the default active tab (Sales Overview) ──
  $('a[href="#salesOverview"]').trigger('shown.bs.tab');
  });
