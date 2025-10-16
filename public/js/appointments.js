(function (window, $) {
  'use strict';

  // Always get fresh JSON (avoid browser cache)
  $.ajaxSetup({ cache: false });

  let peakDayChart = null;
  let diseaseChart = null;
  let diseaseXhr   = null;
let peakDayXhr = null;   // cancel in-flight calls
let peakRenderToken = 0; // ignore stale responses
  // ---------- Delegated, namespaced bindings (safe across SPA reloads) ----------
  // Range changes
  // ---- NEW: Month/Year helpers for Top Conditions ----
function buildYearOptions($sel) {
  const now = new Date();
  const curY = now.getFullYear();
  const yearsBack = 6; // show current year and 5 previous (tweak as you like)

  const opts = [];
  opts.push(`<option value="">All Years</option>`);
  for (let y = curY; y >= curY - yearsBack; y--) {
    opts.push(`<option value="${y}">${y}</option>`);
  }
  $sel.html(opts.join('')).val(String(curY)); // default to current year
}

function buildMonthOptions($sel) {
  const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
  const now = new Date();
  const curM = now.getMonth() + 1; // 1..12

  const opts = ['<option value="">All Months</option>'];
  monthNames.forEach((name, idx) => {
    const m = idx + 1;
    opts.push(`<option value="${m}">${name}</option>`);
  });
  $sel.html(opts.join('')).val(String(curM)); // default to current month
}

function toggleDiseaseYM(range) {
  const enable = (range === 'month' || range === 'year');
  $('#diseaseYear, #diseaseMonth').prop('disabled', !enable);
}

  $(document)
    .off('change.appointments', '#peakDayRange')
    .on('change.appointments', '#peakDayRange', function () {
      loadPeakDayOfWeek(this.value);
    });

$(document)
  .off('change.appointments', '#diseaseRange')
  .on('change.appointments', '#diseaseRange', function () {
    toggleDiseaseYM(this.value);     // NEW: enable/disable YM
    loadTopDiseases(this.value);
  });
// NEW: Year/Month changes -> reload Top Conditions
$(document)
  .off('change.appointments', '#diseaseYear, #diseaseMonth')
  .on('change.appointments', '#diseaseYear, #diseaseMonth', function () {
    const r = $('#diseaseRange').val() || 'month';
    loadTopDiseases(r);
  });

  // Tab shown (delegated!)
$(document)
  .off('shown.bs.tab.appointments', 'a[href="#appointmentTrends"]')
  .on('shown.bs.tab.appointments', 'a[href="#appointmentTrends"]', function () {
    // re-render when tab becomes visible

    // NEW: ensure YM selects are built/toggled when the tab shows
    if ($('#diseaseYear').length && $('#diseaseMonth').length) {
      if (!$('#diseaseYear').children().length)  buildYearOptions($('#diseaseYear'));
      if (!$('#diseaseMonth').children().length) buildMonthOptions($('#diseaseMonth'));
      toggleDiseaseYM($('#diseaseRange').val() || 'month');
    }

    if ($('#appointmentTrends').length) {
      loadPeakDayOfWeek($('#peakDayRange').val() || '30d');
      loadTopDiseases($('#diseaseRange').val() || 'month');
    }
  });


  // ---------- Public API for the shell ----------
  const Appointments = {
    init() {
      // Run only if the dashboard panel is present
      if (!$('#appointmentTrends').length) return;
  if ($('#diseaseYear').length && $('#diseaseMonth').length) {
      buildYearOptions($('#diseaseYear'));
      buildMonthOptions($('#diseaseMonth'));
      toggleDiseaseYM($('#diseaseRange').val() || 'month');
    }

      // Kick both cards using currently selected ranges (with fallbacks)
      loadPeakDayOfWeek($('#peakDayRange').val() || '30d');
      loadTopDiseases($('#diseaseRange').val() || 'month');
    },
    refresh() { this.init(); },
    destroy() {
      // Abort any inflight call
      try { diseaseXhr && diseaseXhr.abort(); } catch(e) {}
      diseaseXhr = null;

      // Destroy charts and clear containers (avoid ghosting when page is removed)
      try { peakDayChart && peakDayChart.destroy(); } catch(e) {}
      try { diseaseChart && diseaseChart.destroy(); } catch(e) {}
      peakDayChart = diseaseChart = null;

      $('#peakDayChart').empty();
      $('#diseaseChart').empty();
    }
  };
  window.Appointments = Appointments;
function loadPeakDayOfWeek(range) {
  if (!$('#peakDayChartWrapper').length) return;

  // cancel previous fetch (prevents two .done()’s racing)
  try { peakDayXhr && peakDayXhr.abort(); } catch(e){}
  peakDayXhr = null;

  // destroy previous chart & reset mount
  try { peakDayChart && peakDayChart.destroy(); } catch(e){}
  peakDayChart = null;
  $('#peakDayChartWrapper').empty().append('<div id="peakDayChart"></div>');

  const r = range || ($('#peakDayRange').val() || '30d');
  const token = ++peakRenderToken; // snapshot

  peakDayXhr = $.getJSON(`/admin/peak-day-of-week?range=${encodeURIComponent(r)}&_=${Date.now()}`)
    .done(resp => {
      // if another call started after this one, do nothing
      if (token !== peakRenderToken) return;

      const days = Array.isArray(resp.days) ? resp.days : [];
      const total = days.reduce((a, d) => a + (Number(d.count) || 0), 0);

      if (!days.length || total === 0) {
        $('#peakDayTable tbody').html('<tr><td colspan="2" class="text-center text-muted">No data.</td></tr>');
        $('#peakDayChart').empty();
        return;
      }

      const ranked = [...days]
        .map(d => ({ dayLabel: String(d.dayLabel || ''), count: Number(d.count) || 0 }))
        .sort((a, b) => b.count - a.count);

      peakDayChart = new ApexCharts(document.querySelector('#peakDayChart'), {
        chart: { type: 'bar', height: 200, toolbar: { show: false } },
        series: [{ name: 'Appointments', data: ranked.map(d => d.count) }],
        xaxis: {
          categories: ranked.map(d => d.dayLabel),
          labels: { style: { fontSize: '12px' }, rotate: -15, trim: true },
          axisBorder: { show: false }, axisTicks: { show: false }
        },
        yaxis: { labels: { formatter: v => Number(Number(v).toFixed(0)).toLocaleString() } },
        colors: ['#008FFB'],
        plotOptions: { bar: { columnWidth: '45%', dataLabels: { position: 'top' } } },
        dataLabels: {
          enabled: true, offsetY: -16,
          style: { colors: ['#222'], fontWeight: 700, fontSize: '12px' },
          background: { enabled: true, foreColor: '#fff', borderRadius: 4, opacity: 0.95, padding: 3 },
          formatter: val => `${Number(val).toLocaleString()}`
        },
        tooltip: { y: { formatter: v => `${Number(v).toLocaleString()}` } },
        legend: { show: false },
        grid: { strokeDashArray: 4 }
      });
      peakDayChart.render();

      // table rows (rank badges kept)
      const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      const badgeClass = r => r === 1 ? 'rank-1' : r === 2 ? 'rank-2' : r === 3 ? 'rank-3' : 'rank-n';
      $('#peakDayTable tbody').html(ranked.map((d,i)=>`
        <tr>
          <td><span class="rank-badge ${badgeClass(i+1)}">${i+1}</span>${esc(d.dayLabel)}</td>
          <td class="text-right">${Number(d.count).toLocaleString()}</td>
        </tr>
      `).join(''));
    })
    .fail(() => {
      try { peakDayChart && peakDayChart.destroy(); } catch(e){}
      peakDayChart = null;
      $('#peakDayChart').empty();
      $('#peakDayTable tbody').html('<tr><td colspan="2" class="text-center text-muted">Failed to load.</td></tr>');
    })
    .always(() => { peakDayXhr = null; });
}


  // ---------- Top Conditions (Apex) ----------
function loadTopDiseases(range) {
  if (!$('#diseaseChart').length) return;

  // Abort previous request if any
  try { diseaseXhr && diseaseXhr.abort(); } catch(e){}
  diseaseXhr = null;

  // Collect YM (only apply when range is month or year)
  const r = String(range || $('#diseaseRange').val() || 'month');
  let y = '', m = '';
  if (r === 'month' || r === 'year') {
    y = String($('#diseaseYear').val() || '');
    m = String($('#diseaseMonth').val() || '');
  }

  // Build query
  let qs = `range=${encodeURIComponent(r)}&_=${Date.now()}`;
  if (y) qs += `&year=${encodeURIComponent(y)}`;
  // For 'month' range, a month selection is meaningful; for 'year', month is optional (treated as "all months" if blank)
  if (m && r === 'month') qs += `&month=${encodeURIComponent(m)}`;
  // If you later add species, append here: qs += `&species=${encodeURIComponent(speciesVal)}`;

  diseaseXhr = $.getJSON(`/admin/top-diseases?${qs}`)
    .done(resp => {
      const labels = Array.isArray(resp.labels) ? resp.labels : [];
      const counts = (resp.counts || []).map(n => Number(n) || 0);
      const total  = counts.reduce((a, b) => a + b, 0);

      if (!labels.length || !counts.length || total === 0) {
        $('#diseaseEmpty').show();
        $('#diseaseTable tbody').empty();
        try { diseaseChart && diseaseChart.destroy(); } catch(e){}
        diseaseChart = null;
        $('#diseaseChart').empty();
        return;
      }
      $('#diseaseEmpty').hide();

      try { diseaseChart && diseaseChart.destroy(); } catch(e){}
      diseaseChart = null;
      $('#diseaseChart').empty();

      diseaseChart = new ApexCharts(document.querySelector('#diseaseChart'), {
        chart: { type: 'bar', height: 220, toolbar: { show: false } },
        series: [{ name: 'Cases', data: counts }],
        xaxis: {
          categories: labels,
          labels: { style: { fontSize: '12px' }, rotate: -15, trim: true },
          axisBorder: { show: false }, axisTicks: { show: false }
        },
        yaxis: { labels: { formatter: v => Number(Number(v).toFixed(0)).toLocaleString() } },
        colors: ['#008FFB'],
        plotOptions: { bar: { columnWidth: '45%', dataLabels: { position: 'top' } } },
        dataLabels: {
          enabled: true, offsetY: -16,
          style: { colors: ['#222'], fontWeight: 700, fontSize: '12px' },
          background: { enabled: true, foreColor: '#fff', borderRadius: 4, opacity: 0.95, padding: 3 },
          formatter: val => `${Number(val).toLocaleString()}`
        },
        tooltip: { y: { formatter: v => `${Number(v).toLocaleString()} case${v === 1 ? '' : 's'}` } },
        legend: { show: false },
        grid: { strokeDashArray: 4 }
      });
      diseaseChart.render();

      const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      const badgeClass = rnk => rnk === 1 ? 'rank-1' : rnk === 2 ? 'rank-2' : rnk === 3 ? 'rank-3' : 'rank-n';
      const fmt = n => Number(n || 0).toLocaleString();

      const rows = (resp.top && resp.top.length
        ? resp.top.map(x => ({ rank: x.rank, name: x.name, count: x.count }))
        : labels.map((name, i) => ({ rank: i + 1, name, count: counts[i] }))
      ).map(row => `
        <tr>
          <td><span class="rank-badge ${badgeClass(row.rank)}">${row.rank}</span>${esc(row.name)}</td>
          <td class="text-right">${fmt(row.count)}</td>
        </tr>
      `).join('');

      $('#diseaseTable tbody').html(rows);
    })
    .fail(() => {
      try { diseaseChart && diseaseChart.destroy(); } catch(e){}
      diseaseChart = null;
      $('#diseaseChart').empty();
      $('#diseaseTable tbody').html('<tr><td colspan="2" class="text-center text-muted">Failed to load.</td></tr>');
      $('#diseaseEmpty').hide();
    })
    .always(() => { diseaseXhr = null; });
}

})(window, jQuery);
