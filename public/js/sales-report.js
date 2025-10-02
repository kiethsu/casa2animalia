/* global window, document */
(() => {
  if (window.__SALES_REPORT_ACTIVE__) return;
  window.__SALES_REPORT_ACTIVE__ = true;

  const DEFAULT_ENDPOINTS = {
    stats:        '/admin/get-dashboard-stats',
    categories:   '/admin/get-categories',
    serviceCats:  '/admin/services/categories/list',
    byProduct:    '/admin/report/get-sales-by-product',
    byService:    '/admin/report/get-sales-by-service',
    byCategory:   '/admin/report/get-sales-by-category',
    expired:      '/admin/report/expired-products',
    kpis:         '/admin/report/get-sales-kpis',
    topProfit:    '/admin/report/top-profit-items',
    expiringSoon: '/admin/report/expiring-soon',
    slowMovers:   '/admin/report/slow-movers',          // NEW

    exportExcel:  '/admin/report/export-excel',

    exportCSV:    '/admin/downloadSalesCSV',
    exportPDF:    '/admin/download-sales-report.pdf'
  };

  let EP = DEFAULT_ENDPOINTS;

  // DOM refs
  let startEl, endEl, btnApply, presetSelect;
  let bdProducts, bdServices, bdBoth;
  let categoryWrap, categoryLabel, categorySelect;

  let kpiSalesAmount, kpiSalesChange;
  let kpiLoss, kpiLossLabel, kpiLossSub;
  let kpiProfit, kpiProfitChange, kpiProfitCol;

  // Top Profit Drivers
  let tableHead, tableBody, tableRangeLabel;
  let tpdSingle, tpdDual, tableBodyProd, tableBodySvc;

  let btnExportExcel, btnExportCSV, btnExportPDF, btnExportVisibleCSV;

  // Slow Movers (new)
  let slowRangeLabel, slowSingle, slowDual, slowBody, slowBodyProd, slowBodySvc;

  // Categories cache
  let PRODUCT_CATS = [];
  let SERVICE_CATS = [];

  // ----------------- Helpers -----------------
  const pad = n => String(n).padStart(2,'0');
  const fmtDate = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
  const parseISO = s => { const [y,m,d]=s.split('-').map(Number); return new Date(y,m-1,d); };
  const diffDaysInclusive = (a,b)=> Math.round((b-a)/86400000)+1;

  const toNum = v => {
    if (v === undefined || v === null || v === '') return 0;
    const n = typeof v === 'string' ? Number(v.replace(/,/g, '')) : Number(v);
    return Number.isFinite(n) ? n : 0;
  };

  const peso = (n=0) => `₱${(toNum(n)).toLocaleString(undefined,{maximumFractionDigits:0})}`;
  const pctStr  = n => `${(toNum(n)).toFixed(1)}%`;

  const currentBreakdown = () =>
    bdProducts?.checked ? 'products' : (bdServices?.checked ? 'services' : 'both');

  const modeLabel  = m => m==='products' ? 'Products' : (m==='services' ? 'Services' : 'All');
  const unitsLabel = m => m==='both' ? 'Transactions' : 'Units';

  async function getJSON(url){
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json();
  }

  function chosenRangeKey(sISO, eISO){
    const s=parseISO(sISO), e=parseISO(eISO);
    const d=diffDaysInclusive(s,e);
    if (d<=1) return 'day';
    if (d<=7) return 'week';
    if (d<=31) return 'month';
    return 'year';
  }

  function setPreset(p){
    const now = new Date(); now.setHours(0,0,0,0);
    let s = new Date(now), e = new Date(now);
    if (p==='today') {/* noop */} else if (p==='7d'){ s.setDate(now.getDate()-6); }
    else if (p==='mtd'){ s = new Date(now.getFullYear(), now.getMonth(), 1); }
    else if (p==='ytd'){ s = new Date(now.getFullYear(), 0, 1); }
    startEl.value = fmtDate(s);
    endEl.value   = fmtDate(e);
  }

  // === Slow Movers: toggle scroll when rows >= 5 ===
  function setScrollForSlowTable(tbodyEl, rowCount) {
    const table = tbodyEl?.closest('table');
    if (!table) return;
    if (rowCount >= 5) table.classList.add('scrollable-table');
    else table.classList.remove('scrollable-table');
  }

  // ----------------- KPI setters -----------------
  function setSalesAndProfitKPIs(
    sales,
    { mode='products', serviceCount=0, totalLoss=0 } = {}
  ){
    const amount = toNum(sales.totalRevenue ?? sales.revenue ?? sales.totalSales ?? 0);
    kpiSalesAmount.textContent = peso(amount);

    if (sales.comparison){
      const rchg = toNum(sales.comparison.revenueChangePercent ?? 0);
      kpiSalesChange.textContent = `${rchg>=0?'▲':'▼'} ${pctStr(Math.abs(rchg))} vs prev period`;
    } else {
      kpiSalesChange.textContent = '—';
    }

    if (mode === 'services') {
      kpiProfitCol?.classList.add('d-none');
      kpiProfitChange.textContent = '—';
      kpiProfit.textContent = '—';

      kpiLossLabel.textContent = 'Services Count';
      kpiLossSub.textContent   = 'Number of services in range';
      kpiLoss.textContent      = toNum(serviceCount).toLocaleString();
      return;
    }

    kpiProfitCol?.classList.remove('d-none');

    const profitRaw =
      sales.profit ?? sales.netProfit ?? sales.grossProfit ?? sales.totalProfit ?? 0;
    kpiProfit.textContent = peso(profitRaw);

    if (sales.comparison){
      const curP = toNum(
        sales.comparison.currentProfit ?? sales.comparison.profit ?? sales.comparison.currentNetProfit ?? profitRaw
      );
      const prevP = toNum(sales.comparison.prevProfit ?? sales.comparison.previousProfit ?? 0);
      const pchg = prevP !== 0 ? ((curP - prevP) / Math.abs(prevP)) * 100 : 0;
      kpiProfitChange.textContent = `${pchg>=0?'▲':'▼'} ${pctStr(Math.abs(pchg))} vs prev period`;
    } else {
      kpiProfitChange.textContent = '—';
    }

    kpiLossLabel.textContent = 'Loss';
    kpiLossSub.textContent   = 'Expired / write-off loss';
    kpiLoss.textContent      = peso(totalLoss);
  }

  // ----------------- Top Profit Drivers (render) -----------------
  function setTableHeader(mode){
    if (mode === 'both') {
      tpdSingle.classList.add('d-none');
      tpdDual.classList.remove('d-none');
    } else {
      tpdDual.classList.add('d-none');
      tpdSingle.classList.remove('d-none');
      tableHead.innerHTML = `
        <th>${mode==='services'?'Service':(mode==='products'?'Product':'Name')}</th>
        <th class="text-end">${unitsLabel(mode)}</th>
        <th class="text-end">Profit (₱)</th>
      `;
    }
  }

  const rankClass = (idx) => (idx===0?'rank-1':idx===1?'rank-2':idx===2?'rank-3':idx===3?'rank-4':'rank-5');

  function renderProfitTable(rows){
    tableBody.innerHTML = '';
    if (!rows || !rows.length){
      tableBody.innerHTML = `<tr><td colspan="3" class="text-center muted py-4">No data.</td></tr>`;
      return;
    }
    const max = Math.max(0, ...rows.map(r=>toNum(r.profit)));
    rows.forEach((r, idx)=>{
      const rk  = rankClass(idx);
      const pct = max > 0 ? Math.max(0, Math.min(100, (toNum(r.profit)/max)*100)) : 0;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>
          <span class="rank-badge ${rk} me-2" title="Rank ${idx+1}">${idx+1}</span>
          <span>${r.name}</span>
        </td>
        <td class="text-end">${toNum(r.units).toLocaleString()}</td>
        <td class="text-end profit-cell">
          <div class="profit-val">${peso(r.profit)}</div>
          <div class="mini-bar"><div class="bar ${rk}" style="width:${pct}%;"></div></div>
        </td>
      `;
      tableBody.appendChild(tr);
    });
  }

  function renderProfitTableDual(prodRows, svcRows){
    const renderSide = (rows, tbodyEl) => {
      tbodyEl.innerHTML = '';
      if (!rows || !rows.length){
        tbodyEl.innerHTML = `<tr><td colspan="3" class="text-center muted py-4">No data.</td></tr>`;
        return;
      }
      const max = Math.max(0, ...rows.map(r=>toNum(r.profit)));
      rows.forEach((r, idx)=>{
        const rk  = rankClass(idx);
        const pct = max > 0 ? Math.max(0, Math.min(100, (toNum(r.profit)/max)*100)) : 0;
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>
            <span class="rank-badge ${rk} me-2" title="Rank ${idx+1}">${idx+1}</span>
            <span>${r.name}</span>
          </td>
          <td class="text-end">${toNum(r.units).toLocaleString()}</td>
          <td class="text-end profit-cell">
            <div class="profit-val">${peso(r.profit)}</div>
            <div class="mini-bar"><div class="bar ${rk}" style="width:${pct}%;"></div></div>
          </td>
        `;
        tbodyEl.appendChild(tr);
      });
    };
    renderSide(prodRows, tableBodyProd);
    renderSide(svcRows,  tableBodySvc);
  }

  // ----------------- Data loaders -----------------
  async function loadKPIsByMode(mode, startISO, endISO){
    const m = (mode === 'products' || mode === 'services' || mode === 'both') ? mode : 'products';

    const params = new URLSearchParams({ mode:m, start:startISO, end:endISO, compare:'prev' });
    if (m === 'products' && categorySelect.value) params.set('category', categorySelect.value);
    if (m === 'services' && categorySelect.value) params.set('serviceCategory', categorySelect.value);

    const json = await getJSON(`${EP.kpis}?${params.toString()}`);
    const totalLoss = toNum(json.totalExpiredFullLoss ?? json.totalExpiredLoss ?? 0);

    let serviceCount = 0;
    if (m === 'services') {
      const sc = categorySelect.value || '';
      const url = `${EP.byService}?start=${startISO}&end=${endISO}${sc ? `&category=${encodeURIComponent(sc)}` : ''}`;
      const svc = await getJSON(url);
      serviceCount = (svc.services || []).reduce((sum, s) =>
        sum + toNum(s.unitsSold ?? s.count ?? 0), 0);
    }

    setSalesAndProfitKPIs(
      { totalRevenue: json.totalRevenue ?? json.revenue,
        profit:       json.profit ?? json.netProfit ?? json.grossProfit,
        comparison:   json.comparison
      },
      { mode: m, serviceCount, totalLoss }
    );
  }

  async function loadTopProfitItems(mode, startISO, endISO){
    if (mode === 'both') {
      try {
        const [prodRes, svcRes] = await Promise.all([
          getJSON(`${EP.topProfit}?${new URLSearchParams({ mode:'products', start:startISO, end:endISO, limit:5 }).toString()}`),
          getJSON(`${EP.topProfit}?${new URLSearchParams({ mode:'services', start:startISO, end:endISO, limit:5 }).toString()}`)
        ]);
        renderProfitTableDual((prodRes.items || []), (svcRes.items || []));
      } catch (err) {
        tableBodyProd.innerHTML = `<tr><td colspan="3" class="text-center text-danger py-4">Failed to load (${err.message}).</td></tr>`;
        tableBodySvc.innerHTML  = `<tr><td colspan="3" class="text-center text-danger py-4">Failed to load (${err.message}).</td></tr>`;
      }
      return;
    }
    const params = new URLSearchParams({ mode, start: startISO, end: endISO, limit: 5 });
    if (mode === 'products' && categorySelect.value) params.set('category', categorySelect.value);
    if (mode === 'services' && categorySelect.value) params.set('serviceCategory', categorySelect.value);
    try {
      const json = await getJSON(`${EP.topProfit}?${params.toString()}`);
      renderProfitTable(json.items || []);
    } catch (err) {
      tableBody.innerHTML = `<tr><td colspan="3" class="text-center text-danger py-4">Failed to load Top Profit Drivers (${err.message}).</td></tr>`;
    }
  }

  // ----------------- Slow Movers (new) -----------------
  function setSlowHeader(mode, s, e){
    const rangeKey = chosenRangeKey(s, e);
    slowRangeLabel.textContent = `${rangeKey.toUpperCase()} • ${s} → ${e}`;
    if (mode === 'both') {
      slowSingle.classList.add('d-none');
      slowDual.classList.remove('d-none');
    } else {
      slowDual.classList.add('d-none');
      slowSingle.classList.remove('d-none');
    }
  }

  const pickName = (r) => r?.name || r?.productName || r?.serviceName || r?.title || '—';
  const pickLastSoldRaw = (r) =>
    r?.lastSoldAt || r?.lastSold || r?.lastSaleDate || r?.latestSaleDate || r?.lastTxnDate || null;

  function daysSinceFrom(dateStr, refISO){
    if (!dateStr) return null;
    const d = new Date(dateStr);
    if (isNaN(d)) return null;
    const ref = parseISO(refISO);
    return Math.max(0, Math.round((ref - d)/86400000));
  }

  function renderSlowTable(rows, tbodyEl){
    tbodyEl.innerHTML = '';
    const count = Array.isArray(rows) ? rows.length : 0;

    if (!rows || rows.length === 0){
      tbodyEl.innerHTML = `<tr><td colspan="3" class="text-center muted py-4">No slow movers.</td></tr>`;
      setScrollForSlowTable(tbodyEl, 0);
      return;
    }
    rows.forEach(r=>{
      const lastRaw = pickLastSoldRaw(r);
      const lastTxt = lastRaw ? new Date(lastRaw).toLocaleDateString() : `<span class="pill gray">Never</span>`;
      const days    = (r.daysSince ?? r.days ?? null);
      const daysTxt = days !== null ? `${toNum(days).toLocaleString()}` :
                      (lastRaw ? `${daysSinceFrom(lastRaw, endEl.value)}` : '—');

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${pickName(r)}</td>
        <td class="text-end">${lastTxt}</td>
        <td class="text-end">${daysTxt}</td>
      `;
      tbodyEl.appendChild(tr);
    });

    setScrollForSlowTable(tbodyEl, count); // enable scroll when 5+
  }

  async function loadSlowMovers(mode, startISO, endISO){
    setSlowHeader(mode, startISO, endISO);

    const build = (m) => {
      const params = new URLSearchParams({ mode:m, start:startISO, end:endISO, zeroSales:1 });
      if (m === 'products' && categorySelect.value) params.set('category', categorySelect.value);
      if (m === 'services' && categorySelect.value) params.set('serviceCategory', categorySelect.value);
      return `${EP.slowMovers}?${params.toString()}`;
    };

    try {
      if (mode === 'both') {
        const [p, s] = await Promise.all([ getJSON(build('products')), getJSON(build('services')) ]);
        renderSlowTable((p.items || p.products || []), slowBodyProd);
        renderSlowTable((s.items || s.services || []), slowBodySvc);
      } else {
        const res = await getJSON(build(mode));
        const rows = res.items || res.products || res.services || [];
        renderSlowTable(rows, slowBody);
      }
    } catch (err) {
      const msg = `<tr><td colspan="3" class="text-center text-danger py-4">Unable to load slow movers (${err.message}).</td></tr>`;
      if (mode === 'both') {
        slowBodyProd.innerHTML = msg; setScrollForSlowTable(slowBodyProd, 0);
        slowBodySvc.innerHTML  = msg; setScrollForSlowTable(slowBodySvc, 0);
      } else {
        slowBody.innerHTML = msg; setScrollForSlowTable(slowBody, 0);
      }
    }
  }

  // ----------------- Export helpers -----------------
function exportWithDates(base){
  if (!base) return;
  const s = startEl.value, e = endEl.value;
  const mode = currentBreakdown(); // products | services | both

  const params = new URLSearchParams();
  if (s && e) { params.set('start', s); params.set('end', e); }
  params.set('mode', mode);

  // Pass the relevant category filter
  if (mode === 'products' && categorySelect?.value) {
    params.set('category', categorySelect.value); // product category (string)
  }
  if (mode === 'services' && categorySelect?.value) {
    params.set('serviceCategory', categorySelect.value); // ObjectId as string
  }

  // (Optional) name tag for human-friendly filename on server
  const rangeKey = chosenRangeKey(s, e);
  params.set('rangeKey', rangeKey);

  window.location = `${base}?${params.toString()}`;
}

  function exportVisibleTableCSV(){
    const mode = currentBreakdown();
    const rows = [];

    if (mode === 'both') {
      rows.push(['Products — Top 5']);
      rows.push(['Name','Units','Profit (PHP)']);
      tableBodyProd.querySelectorAll('tr').forEach(tr=>{
        const tds = [...tr.querySelectorAll('td')].map(td=>td.textContent.trim());
        if (tds.length === 3) rows.push(tds);
      });
      rows.push([]);
      rows.push(['Services — Top 5']);
      rows.push(['Name','Units','Profit (PHP)']);
      tableBodySvc.querySelectorAll('tr').forEach(tr=>{
        const tds = [...tr.querySelectorAll('td')].map(td=>td.textContent.trim());
        if (tds.length === 3) rows.push(tds);
      });
    } else {
      rows.push([`${modeLabel(mode)} — Top 5`]);
      rows.push(['Name', unitsLabel(mode), 'Profit (PHP)']);
      tableBody.querySelectorAll('tr').forEach(tr=>{
        const tds = [...tr.querySelectorAll('td')].map(td=>td.textContent.trim());
        if (tds.length === 3) rows.push(tds);
      });
    }

    if (rows.length <= 2) return;

    const csv = rows.map(r=> r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type:'text/csv;charset=utf-8;' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `top-profit-drivers-${startEl.value}_to_${endEl.value}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  // ----------------- UI wiring -----------------
  function bindDOMRefs(){
    startEl = document.getElementById('startDate');
    endEl   = document.getElementById('endDate');
    btnApply= document.getElementById('btnApply');
    presetSelect = document.getElementById('presetSelect');

    bdProducts = document.getElementById('bdProducts');
    bdServices = document.getElementById('bdServices');
    bdBoth     = document.getElementById('bdBoth');

    categoryWrap   = document.getElementById('categoryWrap');
    categoryLabel  = document.getElementById('categoryLabel');
    categorySelect = document.getElementById('categorySelect');

    kpiSalesAmount  = document.getElementById('kpiSalesAmount');
    kpiSalesChange  = document.getElementById('kpiSalesChange');
    kpiLoss         = document.getElementById('kpiLoss');
    kpiLossLabel    = document.getElementById('kpiLossLabel');
    kpiLossSub      = document.getElementById('kpiLossSub');
    kpiProfit       = document.getElementById('kpiProfit');
    kpiProfitChange = document.getElementById('kpiProfitChange');
    kpiProfitCol    = document.getElementById('kpiProfitCol');

    // Top Profit Drivers
    tpdSingle       = document.getElementById('tpdSingle');
    tpdDual         = document.getElementById('tpdDual');
    tableHead       = document.getElementById('tableHead');
    tableBody       = document.getElementById('tableBody');
    tableBodyProd   = document.getElementById('tableBodyProd');
    tableBodySvc    = document.getElementById('tableBodySvc');
    tableRangeLabel = document.getElementById('tableRangeLabel');

    btnExportExcel      = document.getElementById('btnExportExcel');
    btnExportCSV        = document.getElementById('btnExportCSV');
    btnExportPDF        = document.getElementById('btnExportPDF');
    btnExportVisibleCSV = document.getElementById('btnExportVisibleCSV');

    // Slow Movers
    slowRangeLabel = document.getElementById('slowRangeLabel');
    slowSingle     = document.getElementById('slowSingle');
    slowDual       = document.getElementById('slowDual');
    slowBody       = document.getElementById('slowBody');
    slowBodyProd   = document.getElementById('slowBodyProd');
    slowBodySvc    = document.getElementById('slowBodySvc');
  }

  function attachEvents(){
    if (presetSelect) {
      presetSelect.addEventListener('change', () => {
        const v = presetSelect.value;
        if (v !== 'custom') setPreset(v);
      });
    }
    startEl?.addEventListener('change', ()=> { if (presetSelect) presetSelect.value='custom'; });
    endEl?.addEventListener('change',   ()=> { if (presetSelect) presetSelect.value='custom'; });

    btnApply?.addEventListener('click', applyAll);

    bdProducts?.addEventListener('change', () => { updateCategoryUI(); setTableHeader('products'); });
    bdServices?.addEventListener('change', () => { updateCategoryUI(); setTableHeader('services'); });
    bdBoth?.addEventListener('change',     () => { updateCategoryUI(); setTableHeader('both');     });

    categorySelect?.addEventListener('change', () => {}); // waits for Apply

    btnExportExcel?.addEventListener('click', ()=> exportWithDates(EP.exportExcel));
    btnExportCSV?.addEventListener('click',   ()=> exportWithDates(EP.exportCSV));
    btnExportPDF?.addEventListener('click',   ()=> exportWithDates(EP.exportPDF));
    btnExportVisibleCSV?.addEventListener('click', exportVisibleTableCSV);
  }

  function updateCategoryUI(){
    const mode = currentBreakdown();

    if (mode === 'both') {
      categoryWrap.classList.add('d-none');
      categorySelect.innerHTML = '';
      categorySelect.value = '';
      return;
    }

    categoryWrap.classList.remove('d-none');
    categoryLabel.textContent = 'Category';

    if (mode === 'products') {
      categorySelect.innerHTML = PRODUCT_CATS.length
        ? `<option value="">All categories</option>${PRODUCT_CATS.map(c=>`<option value="${c}">${c}</option>`).join('')}`
        : `<option value="">No categories found</option>`;
    } else {
      categorySelect.innerHTML = SERVICE_CATS.length
        ? `<option value="">All categories</option>${SERVICE_CATS.map(c=>`<option value="${c._id}">${c.name}</option>`).join('')}`
        : `<option value="">No categories found</option>`;
    }
    categorySelect.value = '';
  }

  async function loadCategories(){
    try {
      const [prodRes, svcRes] = await Promise.all([
        fetch(EP.categories,  { cache:'no-store' }),
        fetch(EP.serviceCats, { cache:'no-store' })
      ]);
      const prodJson = prodRes.ok ? await prodRes.json() : [];
      const svcJson  = svcRes.ok  ? await svcRes.json()  : [];

      PRODUCT_CATS = (Array.isArray(prodJson) ? prodJson : (prodJson?.categories||[]))
        .map(x => (typeof x === 'string' ? x.trim() : String(x ?? '').trim()))
        .filter(Boolean)
        .filter((v,i,a)=>a.indexOf(v)===i)
        .sort((a,b)=>a.localeCompare(b));

      SERVICE_CATS = (Array.isArray(svcJson) ? svcJson : (svcJson?.categories||[]))
        .map(c => ({ _id:String(c?._id??c?.id??'').trim(), name:String(c?.name ?? c?.label ?? '').trim() }))
        .filter(c=>c._id && c.name)
        .filter((v,i,a)=>a.findIndex(x=>x._id===v._id)===i)
        .sort((a,b)=>a.name.localeCompare(b.name));
    } catch (err) {
      console.error('[SalesReport] Failed to load categories:', err);
      PRODUCT_CATS = [];
      SERVICE_CATS = [];
    }
  }

  // ----------------- Orchestration -----------------
  async function applyAll(){
    const s = startEl.value, e = endEl.value;
    if (!s || !e) return;
    const mode = currentBreakdown();

    setTableHeader(mode);
    const rangeKey = chosenRangeKey(s, e);
    tableRangeLabel.textContent = `${rangeKey.toUpperCase()} • ${s} → ${e}`;

    await Promise.allSettled([
      loadKPIsByMode(mode, s, e),
      loadTopProfitItems(mode, s, e),
      loadSlowMovers(mode, s, e)
    ]);
  }

  // ----------------- Init -----------------
  function init(){
    EP = (window.SALES_REPORT_CONFIG && window.SALES_REPORT_CONFIG.endpoints) || DEFAULT_ENDPOINTS;

    bindDOMRefs();
    if (!startEl || !endEl || !categorySelect) return;

    const now = new Date(); now.setHours(0,0,0,0);
    startEl.value = fmtDate(now);
    endEl.value   = fmtDate(now);
    if (presetSelect) presetSelect.value = 'today';

    loadCategories().then(() => {
      updateCategoryUI();
      applyAll();
    });

    attachEvents();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
