// /js/appointments.js
(function (window, $) {
  'use strict';

  let appointmentTrendChart = null;
  let peakDayChartInstance = null;
  let predictionChartInstance = null;

  // Bind range changes
  $('#appointmentTrendRange').on('change', () =>
    loadAppointmentTrendsChart($('#appointmentTrendRange').val())
  );
  $('#peakDayRange').on('change', () =>
    loadPeakDayOfWeek($('#peakDayRange').val())
  );

  // Load when tab becomes visible
  $('a[href="#appointmentTrends"]').on('shown.bs.tab', () => {
    loadTotalAppointments();
    loadPeakDayOfWeek($('#peakDayRange').val());
    loadAppointmentTrendsChart($('#appointmentTrendRange').val());
    loadPredictions();
  });

  // Also trigger once on page load
  $(function () {
    loadTotalAppointments();
    loadPeakDayOfWeek($('#peakDayRange').val());
    loadAppointmentTrendsChart($('#appointmentTrendRange').val());
    loadPredictions();
  });

  // ---- Total Appointments + simple user stats
  function loadTotalAppointments() {
    $.getJSON('/admin/get-dashboard-stats')
      .done(data => {
        const total = (data.appointmentTrends?.completed || []).reduce((a, b) => a + b, 0);
        $('#kpiAppointments').text(total);
        $('#kpiDoctors').text(data.userStats?.doctors ?? 0);
        $('#kpiClients').text(data.userStats?.customers ?? 0);
      })
      .fail(() => console.warn('Failed to load total appointments.'));
  }

  // ---- Peak day-of-week (Chart.js)
  function loadPeakDayOfWeek(range = '30d') {
    $.getJSON(`/admin/peak-day-of-week?range=${encodeURIComponent(range)}`)
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
            datasets: [{ label: 'Appointments', data: resp.days.map(d => d.count), borderColor: '#2196f3', backgroundColor: '#2196f3' }]
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            scales: { x: { ticks: { autoSkip: false, maxRotation: 0 } }, y: { beginAtZero: true, ticks: { stepSize: 1 } } },
            plugins: { legend: { display: false } }
          }
        });
        $('#peakDayTable tbody').html(
          resp.days.map(d => `<tr><td>${d.dayLabel}</td><td class="text-right">${d.count}</td></tr>`).join('')
        );
      })
      .fail(() => {
        $('#peakDayChart').hide();
        $('#peakDayTable tbody').html('<tr><td colspan="2" class="text-center text-muted">No data.</td></tr>');
      });
  }

  // ---- Appointments trend (ApexCharts)
  function loadAppointmentTrendsChart(range = '7d') {
    $.getJSON(`/admin/get-dashboard-stats?range=${encodeURIComponent(range)}`)
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
          $('#appointmentsTrendChart').html('<p class="text-center text-muted">No appointments data.</p>');
          return;
        }
        appointmentTrendChart = new ApexCharts(document.querySelector('#appointmentsTrendChart'), {
          chart: { type: 'line', height: 250, toolbar: { show: false } },
          series: [
            { name: 'Pending', data: pending },
            { name: 'Approved', data: approved },
            { name: 'Completed', data: completed }
          ],
          xaxis: { categories: labels, labels: { rotate: -45 } },
          stroke: { curve: 'smooth', width: 2 },
          tooltip: { y: v => `${v}` }
        });
        appointmentTrendChart.render();
      })
      .fail(() => {
        $('#appointmentsTrendChart').html('<p class="text-center text-danger">Failed to load data.</p>');
      });
  }

  // ---- Simple 3-day forecast (ApexCharts area sparkline)
  function loadPredictions() {
    $.getJSON('/admin/predict-appointments')
      .done(resp => {
        const preds = resp.predictions || [];
        const data = preds.map(p => p.predictedCount);

        if (predictionChartInstance) {
          predictionChartInstance.destroy();
          $('#predictionChart').html('');
        }
        predictionChartInstance = new ApexCharts(document.querySelector('#predictionChart'), {
          chart: { type: 'area', height: 120, sparkline: { enabled: true } },
          series: [{ name: 'Forecast', data }],
          stroke: { curve: 'smooth', width: 2 },
          fill: { opacity: 0.3 },
          tooltip: { enabled: true, theme: 'light' }
        });
        predictionChartInstance.render();

        const $fv = $('#forecastValues').empty();
        preds.forEach((p, i) => {
          const label = i === 0
            ? 'Tomorrow'
            : new Date(p.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
          $fv.append(`
            <div class="text-center" style="flex:1">
              <small class="text-muted d-block">${label}</small>
              <strong>${p.predictedCount}</strong>
            </div>
          `);
        });
      })
      .fail(() => {
        $('#predictionChart').html('<p class="text-center text-danger">Failed to load forecast.</p>');
      });
  }
})(window, jQuery);
