// /js/inventory-overview.js
(function (window, $) {
  'use strict';

  let stockByCategoryChartInstance = null;
  let valueByCategoryChartInstance = null;

  // in-flight guards
  let expiredListReq = null;
  let expiredListReqToken = 0;

  // ───────────────────────────────────────────────────────────────────────────
  // Event wiring
  // ───────────────────────────────────────────────────────────────────────────
  $(document)
    .off('shown.bs.tab', 'a[href="#inventoryOverview"]')
    .on('shown.bs.tab', 'a[href="#inventoryOverview"]', function () {
      const invRange = $('#inventoryRange').length ? $('#inventoryRange').val() : 'all';
      loadInventoryOverview(invRange);

      // Expired categories
      ensureExpiredCategories({ force: true }).then(() => {
        refreshExpiredProductsList();
        updateExpiredKPIOverall();
        updateExpiredCategoryBadges();
      });

      // === Top 5 Best-Sellers ===
      ensureTopSoldCategories({ force: true }).then(() => {
        refreshTopBestSellers();
      });
    });

  $(function () {
    const invRange = $('#inventoryRange').length ? $('#inventoryRange').val() : 'all';
    loadInventoryOverview(invRange);

    // Expired categories (initial)
    ensureExpiredCategories({ force: true }).then(() => {
      refreshExpiredProductsList();
      updateExpiredKPIOverall();
      updateExpiredCategoryBadges();
    });

    // === Top 5 Best-Sellers (initial) ===
    ensureTopSoldCategories({ force: true }).then(() => {
      refreshTopBestSellers();
    });

    // Expired table filter change
    $(document)
      .off('change', '#expiredCategorySelect')
      .on('change', '#expiredCategorySelect', function () {
        refreshExpiredProductsList();
        updateExpiredCategoryBadges();
      });

    // Top 5 filters change
    $(document)
      .off('change', '#topSoldCategorySelect, #topSoldRangeSelect')
      .on('change', '#topSoldCategorySelect, #topSoldRangeSelect', function () {
        refreshTopBestSellers();
      });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Categories <select> for Expired (deduped + rebuilt)
  // ───────────────────────────────────────────────────────────────────────────
  function ensureExpiredCategories({ force = true } = {}) {
    const $sel = $('#expiredCategorySelect');
    if (!$sel.length) return Promise.resolve();
    if (!force && $sel.data('catInit')) return Promise.resolve();

    return $.getJSON('/admin/get-categories')
      .done(cats => {
        const uniq = new Set();
        // Rebuild from scratch, keep "All Categories"
        $sel.empty().append('<option value="">All Categories</option>');
        (cats || []).forEach(c => {
          const label = (c == null ? '' : String(c)).trim();
          if (!label || uniq.has(label)) return;
          uniq.add(label);
          $sel.append(
            `<option value="${escapeAttr(label)}" data-label="${escapeAttr(label)}">${escapeHtml(label)}</option>`
          );
        });
        $sel.data('catInit', true);
      })
      .fail(() => {
        $sel.empty().append('<option value="">All Categories</option>').data('catInit', true);
      });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Annotate Expired options with red "(N)" when expired items exist
  // ───────────────────────────────────────────────────────────────────────────
  function updateExpiredCategoryBadges() {
    const $sel = $('#expiredCategorySelect');
    if (!$sel.length) return;

    $.getJSON('/admin/expired-products?summary=byCategory')
      .done(payload => applyCategoryCounts(mapCountsFromSummary(payload)))
      .fail(() => {
        $.getJSON('/admin/expired-products')
          .done(rawAll => applyCategoryCounts(mapCountsFromFullList(rawAll)))
          .fail(() => {
            const options = $sel.find('option').toArray().map(o => o.value).filter(v => v);
            if (!options.length) return;
            const results = {};
            const run = (i = 0) => {
              if (i >= options.length) { applyCategoryCounts(results); return; }
              const cat = options[i];
              $.getJSON('/admin/expired-products?category=' + encodeURIComponent(cat))
                .done(raw => {
                  const list = pickExpiredArray(raw).map(normalizeExpiredRow);
                  const total = list.reduce((s, r) => s + (r.count || 0), 0);
                  results[cat] = total;
                })
                .always(() => run(i + 1));
            };
            run();
          });
      });

    function mapCountsFromSummary(payload) {
      const arr = pickExpiredArray(payload);
      const out = {};
      arr.forEach(it => {
        const cat = it.category ?? it._id ?? it.name ?? it.label;
        const cnt = Number(it.count ?? it.expiredCount ?? it.total ?? 0) || 0;
        if (cat) out[String(cat)] = cnt;
      });
      return out;
    }

    function mapCountsFromFullList(rawAll) {
      const list = pickExpiredArray(rawAll);
      const out = {};
      list.forEach(it => {
        const cnt = Number(it.expiredCount ?? it.count ?? it.quantity ?? it.total ?? 0) || 0;
        const cat = it.category ?? it.categoryName ?? it.cat ?? it.group ?? it.type ?? null;
        if (!cat) return;
        const key = String(cat);
        out[key] = (out[key] || 0) + cnt;
      });
      return out;
    }

    function applyCategoryCounts(counts) {
      const $sel = $('#expiredCategorySelect');
      const current = $sel.val();
      $sel.find('option').each(function () {
        const $opt = $(this);
        const base = $opt.data('label') || $opt.val() || $opt.text();
        if ($opt.val() === '') {
          $opt.text('All Categories').removeClass('expired-has');
          return;
        }
        const n = Number(counts[base] || 0);
        if (n > 0) {
          $opt.text(`${base} (${n})`).addClass('expired-has');
        } else {
          $opt.text(base).removeClass('expired-has');
        }
      });
      if (current != null) $sel.val(current);
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Overall Expired KPI (not affected by the dropdown filter)
  // ───────────────────────────────────────────────────────────────────────────
  function updateExpiredKPIOverall() {
    $.getJSON('/admin/expired-products')
      .done(raw => {
        const list = pickExpiredArray(raw).map(normalizeExpiredRow);
        const totalExpired = list.reduce((sum, r) => sum + (r.count || 0), 0);
        if (!isNaN(totalExpired)) $('#invExpiredCount').text(totalExpired);
      });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Inventory Overview (KPIs + Charts)                (Top 5 handled separately)
  // ───────────────────────────────────────────────────────────────────────────
  function loadInventoryOverview(range = 'all') {
    $.getJSON(`/admin/inventory-stats?range=${encodeURIComponent(range)}`)
      .done(data => {
        $('#invTotalSKUs').text(data.totalSKUs ?? 0);
        $('#invLowStockCount').text((data.lowStock || []).length);

        // Use full expiringSoonCount if provided; otherwise fallback to items array length
        const expSoonCount = (typeof data.expiringSoonCount === 'number')
          ? data.expiringSoonCount
          : (Array.isArray(data.expiringSoon) ? data.expiringSoon.length : 0);
        $('#invExpiringCount').text(expSoonCount);

        if (typeof data.expiredCount === 'number') {
          $('#invExpiredCount').text(data.expiredCount);
        }

        // Destroy old charts
        if (stockByCategoryChartInstance) {
          stockByCategoryChartInstance.destroy();
          $('#stockByCategoryChart').html('');
        }
        if (valueByCategoryChartInstance) {
          valueByCategoryChartInstance.destroy();
          $('#valueByCategoryChart').html('');
        }

        // Stock by Category (bar)
        if (document.querySelector('#stockByCategoryChart') && Array.isArray(data.stockByCategory)) {
          stockByCategoryChartInstance = new ApexCharts(document.querySelector('#stockByCategoryChart'), {
            chart: { type: 'bar', height: 250, toolbar: { show: false } },
            series: [{ name: 'Units', data: data.stockByCategory.map(x => x.totalStock) }],
            xaxis: { categories: data.stockByCategory.map(x => x._id), labels: { rotate: -45 } },
            tooltip: { y: { formatter: v => `${v} units` } }
          });
          stockByCategoryChartInstance.render();
        }

        // Value by Category (donut)
        if (document.querySelector('#valueByCategoryChart') && Array.isArray(data.valueByCategory)) {
          valueByCategoryChartInstance = new ApexCharts(document.querySelector('#valueByCategoryChart'), {
            chart: { type: 'donut', height: 250 },
            series: data.valueByCategory.map(x => x.totalValue),
            labels: data.valueByCategory.map(x => x._id),
            tooltip: { y: { formatter: v => '₱' + Number(v).toLocaleString() } }
          });
          valueByCategoryChartInstance.render();
        }

        // Keep the KPI accurate even if server omitted expiredCount
        updateExpiredKPIOverall();
      })
      .fail(() => {
        $('#inventoryOverview .card-body').first().append('<p class="text-danger mt-2">Failed to load inventory data.</p>');
      });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Expired Products table (filtered by dropdown)
  // ───────────────────────────────────────────────────────────────────────────
  function refreshExpiredProductsList() {
    const category = $('#expiredCategorySelect').val() || '';
    const $tbody = $('#expiredProductsTbody').empty();
    const $empty = $('#expiredProductsEmpty').hide().text('No expired products.');
    const $expiredTable = $('#expiredProductsTable').removeClass('scroll-when-5'); // reset; JS toggles below
    const url = '/admin/expired-products' + (category ? `?category=${encodeURIComponent(category)}` : '');

    if (expiredListReq && expiredListReq.readyState !== 4) {
      try { expiredListReq.abort(); } catch (_) {}
    }
    const myToken = ++expiredListReqToken;

    expiredListReq = $.getJSON(url)
      .done(raw => {
        if (myToken !== expiredListReqToken) return;
        const list = pickExpiredArray(raw).map(normalizeExpiredRow);
        if (!list.length) { $empty.show(); return; }

        list.forEach(r => {
          $tbody.append(`
            <tr>
              <td>${escapeHtml(r.name)}</td>
              <td class="text-right">${Number(r.count).toLocaleString()}</td>
              <td class="text-right">${r.last}</td>
            </tr>
          `);
        });

        // Make tbody scroll when we have 5 or more rows
        if (list.length >= 5) {
          $expiredTable.addClass('scroll-when-5');
        }

        updateExpiredCategoryBadges();
      })
      .fail((jqXHR, textStatus) => {
        if (textStatus === 'abort') return;
        $empty.text('Error loading expired products.').show();
      });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // === Top 5 Best-Sellers (Category + Range dropdowns)
  //     Uses /admin/get-sales-by-product?category=&range=
  //     Range values: day | week | month | year
  // ───────────────────────────────────────────────────────────────────────────
  function ensureTopSoldCategories({ force = false } = {}) {
    const $sel = $('#topSoldCategorySelect');
    if (!$sel.length) return Promise.resolve();
    if (!force && $sel.data('catInit')) return Promise.resolve();

    return $.getJSON('/admin/get-categories')
      .done(cats => {
        const uniq = new Set();
        $sel.empty().append('<option value="">All Categories</option>');
        (cats || []).forEach(c => {
          const label = (c == null ? '' : String(c)).trim();
          if (!label || uniq.has(label)) return;
          uniq.add(label);
          $sel.append(`<option value="${escapeAttr(label)}">${escapeHtml(label)}</option>`);
        });
        $sel.data('catInit', true);
      })
      .fail(() => {
        $sel.empty().append('<option value="">All Categories</option>').data('catInit', true);
      });
  }

  function refreshTopBestSellers() {
    // Support for (accidentally) duplicated IDs in the DOM:
    const $allTopSoldTbodies = $('#topSoldTbody');
    const $allTopSoldEmpty = $('#topSoldEmpty');
    const $allTopSoldTables = $('#topSoldTable');

    if ($allTopSoldTables.length === 0) return;

    if ($allTopSoldTbodies.length > 1 || $allTopSoldTables.length > 1 || $allTopSoldEmpty.length > 1) {
      console.warn('[Top 5] Multiple instances detected:',
        { tbodies: $allTopSoldTbodies.length, tables: $allTopSoldTables.length, empties: $allTopSoldEmpty.length });
    }

    const cat = ($('#topSoldCategorySelect').val() || '').trim();
    let range = ($('#topSoldRangeSelect').val() || 'week').trim();

    const url = `/admin/get-sales-by-product?range=${encodeURIComponent(range)}${cat ? `&category=${encodeURIComponent(cat)}` : ''}`;
    fetchTopSold(url);

    function fetchTopSold(url) {
      // Clear ALL matching tbodies to avoid duplicates if markup was accidentally duplicated
      $allTopSoldTbodies.each(function () { $(this).empty(); });
      // Hide all empties initially
      $allTopSoldEmpty.each(function () { $(this).hide().text('No top sellers to display.'); });

      $.getJSON(url)
        .done(resp => {
          const raw = Array.isArray(resp?.products) ? resp.products : [];

          if (!raw.length) {
            $allTopSoldEmpty.each(function () { $(this).show(); });
            return;
          }

          // Data-level de-dupe: merge by product key and sum unitsSold
          const merged = new Map();
          raw.forEach(p => {
            const key = (p.productId ?? p._id ?? p.productName ?? '').toString();
            if (!key) return;
            const units = Number(p.unitsSold ?? p.soldQuantity ?? 0) || 0;
            const label = (p.productName ?? key).toString();
            const prev = merged.get(key);
            if (prev) {
              prev.units += units;
            } else {
              merged.set(key, { label, units });
            }
          });

          const top5 = [...merged.values()]
            .sort((a, b) => b.units - a.units)
            .slice(0, 5); // strictly cap to 5

          if (!top5.length) {
            $allTopSoldEmpty.each(function () { $(this).show(); });
            return;
          }

          const rowsHtml = top5.map(p => `
            <tr>
              <td>${escapeHtml(p.label)}</td>
              <td class="text-right">${Number(p.units).toLocaleString()}</td>
            </tr>
          `).join('');

          // Render into every potential Top-5 tbody found
          $allTopSoldTbodies.each(function () { $(this).html(rowsHtml); });

          // Lock visual height to ~5 rows if CSS helper is present
          $allTopSoldTables.addClass('max5');
        })
        .fail(() => {
          $allTopSoldTbodies.each(function () { $(this).empty(); });
          $allTopSoldEmpty.each(function () { $(this).text('Error loading top sellers.').show(); });
        });
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Helpers
  // ───────────────────────────────────────────────────────────────────────────
  function pickExpiredArray(raw) {
    const candidates = [
      raw?.items,
      raw?.data?.items,
      raw?.data,
      raw?.products,
      raw?.expired,
      Array.isArray(raw) ? raw : null
    ].filter(Boolean);
    return candidates[0] || [];
  }

  function normalizeExpiredRow(it) {
    const name = it.productName ?? it.name ?? it.title ?? it._id ?? '—';
    const count = Number(it.expiredCount ?? it.count ?? it.quantity ?? it.total ?? 0) || 0;
    const lastRaw = it.lastExpired ?? it.lastExpiry ?? it.last_date ?? it.lastDate ?? it.last ?? null;
    let last = '--';
    if (lastRaw) {
      const d = new Date(lastRaw);
      if (!isNaN(d.getTime())) last = d.toLocaleDateString();
    }
    return { name, count, last };
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;');
  }

  function escapeAttr(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;');
  }

  // expose if needed elsewhere
  window.refreshExpiredProductsList = refreshExpiredProductsList;

})(window, jQuery);
