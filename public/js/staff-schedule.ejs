// Works with views/staff-schedule.ejs
// Optional deps: flatpickr, SweetAlert2

(function(){
  if (window.__STAFF_SCHEDULE_JS__) return;
  window.__STAFF_SCHEDULE_JS__ = true;

  // ---------- utils ----------
  const $  = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
  const escapeHtml = s => String(s||'')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');

  // detect /admin or /adm
  const ADMIN = (function(){
    if (window.__ADMIN_BASE__) return String(window.__ADMIN_BASE__).replace(/\/+$/,'');
    const m = location.pathname.match(/^\/([^/?#]+)\/staff-schedule/i);
    if (m) return `/${m[1]}`;
    if (location.pathname.startsWith('/adm/')) return '/adm';
    return '/admin';
  })();
  const api = p => p.startsWith('/') ? (ADMIN + p) : (ADMIN + '/' + p);

  async function fetchJSON(url, opts){
    const r = await fetch(url, opts);
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      const text = await r.text();
      throw new Error(`Bad response ${r.status} ${r.statusText}. Body: ${text.slice(0,200)}`);
    }
    return r.json();
  }

  function sweet(title, textOrHtml, icon='success', useHtml=false){
    if (window.Swal){
      return Swal.fire({ icon, title, ...(useHtml ? { html: textOrHtml } : { text: textOrHtml }) });
    }
    alert(typeof textOrHtml === 'string' ? textOrHtml : title);
  }

  // --- Button spinner helpers ---
  function spinButton(btn, label){
    if (!btn || btn.classList.contains('is-loading')) return;
    btn.dataset.origHtml = btn.innerHTML;
    // Fix width to prevent layout shift during spinner
    const w = btn.getBoundingClientRect().width;
    btn.style.width = w ? w + 'px' : btn.style.width;
    btn.innerHTML = `<span class="btn-spinner" aria-hidden="true"></span>${label || 'Working…'}`;
    btn.classList.add('is-loading');
    btn.setAttribute('aria-busy','true');
    btn.disabled = true;
  }
  function unspinButton(btn){
    if (!btn || !btn.classList.contains('is-loading')) return;
    btn.innerHTML = btn.dataset.origHtml || btn.innerHTML;
    btn.classList.remove('is-loading');
    btn.removeAttribute('aria-busy');
    btn.style.width = '';
    btn.disabled = false;
  }

  // ---------- state ----------
  let startPicker=null, endPicker=null, staffCache=null, bound=false;
  let dowBound=false, monthBound=false;

  // per-day time state
  let perDayTimes = new Map();      // weekday (1..7) -> { start:'HH:MM', end:'HH:MM' }
  let dayStartPickers = new Map();  // weekday -> flatpickr instance
  let dayEndPickers   = new Map();

  // ---------- UI helpers ----------
  function ensureTimePickers(){
    if (!window.flatpickr) return;
    if (!startPicker) startPicker = flatpickr('#ss-start', { enableTime:true, noCalendar:true, dateFormat:'H:i' });
    if (!endPicker)   endPicker   = flatpickr('#ss-end',   { enableTime:true, noCalendar:true, dateFormat:'H:i' });
  }

  function weekdayName(d){
    return ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][d-1] || `Day ${d}`;
  }
  function hhmmToMin(v){
    const [h,m] = String(v||'').split(':').map(n=>parseInt(n,10));
    if (Number.isInteger(h) && Number.isInteger(m)) return h*60+m;
    return NaN;
  }

  // ===== Month picker (radio-like) =====
  function populateYearSelect(){
    const sel = $('#ss-year');
    if (!sel) return;
    const now = new Date();
    const yNow = now.getFullYear();
    const years = [];
    for (let y = yNow - 1; y <= yNow + 2; y++){
      years.push(`<option value="${y}">${y}</option>`);
    }
    sel.innerHTML = years.join('');
    sel.value = String(yNow);
  }
  function setMonthActive(m){
    const btns = $$('#ss-months .ss-month-btn');
    btns.forEach(b => b.classList.toggle('active', String(b.dataset.value) === String(m)));
  }
  function getSelectedMonth(){
    const active = $('#ss-months .ss-month-btn.active');
    if (!active) return NaN;
    const m = parseInt(active.dataset.value, 10);
    return Number.isInteger(m) ? m : NaN;
  }
  function getYearMonthFromUI(){
    const ySel = $('#ss-year');
    if (!ySel) return '';
    const year = parseInt(ySel.value, 10);
    const m = getSelectedMonth();
    if (!Number.isInteger(year) || !Number.isInteger(m)) return '';
    return `${year}-${String(m).padStart(2,'0')}`;
  }
  function bindMonthPicker(){
    if (monthBound) return;
    const box = $('#ss-months'); if (!box) return;
    box.addEventListener('click', (e)=>{
      const btn = e.target.closest('.ss-month-btn');
      if (!btn) return;
      e.preventDefault();
      // radio behavior: only one active
      setMonthActive(btn.dataset.value);
      preselectExistingWeekdays(); // changing month may adjust preselection
    });
    $('#ss-year')?.addEventListener('change', preselectExistingWeekdays);
    monthBound = true;
  }

  // ===== Weekday picker =====
  function setWeekdayActive(btn, on){
    btn.classList.toggle('active', !!on);
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    btn.dataset.selected = on ? '1' : '0';
  }
  function bindWeekdayPicker(){
    if (dowBound) return;
    const container = $('#ss-dow');
    if (!container) return;

    container.addEventListener('click', (e)=>{
      const btn = e.target.closest('.ss-dow-btn');
      if (!btn) return;
      e.preventDefault();
      setWeekdayActive(btn, !(btn.classList.contains('active')));
      if (!$('#ss-same-time')?.checked) updatePerDayList();
    });

    $('#ss-dow-all')?.addEventListener('click', (e)=>{
      e.preventDefault(); e.stopPropagation();
      $$('.ss-dow-btn', container).forEach(b => setWeekdayActive(b, true));
      if (!$('#ss-same-time')?.checked) updatePerDayList();
    });
    $('#ss-dow-clear')?.addEventListener('click', (e)=>{
      e.preventDefault(); e.stopPropagation();
      $$('.ss-dow-btn', container).forEach(b => setWeekdayActive(b, false));
      if (!$('#ss-same-time')?.checked) updatePerDayList();
    });

    dowBound = true;
  }

  function selectedWeekdays(){
    return $$('#ss-dow .ss-dow-btn.active')
      .map(b => parseInt(b.getAttribute('data-value'), 10))
      .filter(n => !Number.isNaN(n));
  }

  // clear & preselect helpers
  function clearWeekdaySelection(){
    $$('#ss-dow .ss-dow-btn').forEach(b => setWeekdayActive(b, false));
  }

  async function preselectExistingWeekdays(){
    const staffId   = $('#ss-staff-select')?.value || '';
    const yearMonth = getYearMonthFromUI();
    if (!staffId || !/^\d{4}-(0[1-9]|1[0-2])$/.test(yearMonth)){
      clearWeekdaySelection();
      return;
    }
    try{
      const dows = await getExistingDOWs(staffId, yearMonth);
      clearWeekdaySelection();
      dows.forEach(d => {
        const btn = $(`.ss-dow-btn[data-value="${d}"]`);
        if (btn) setWeekdayActive(btn, true);
      });

      // Prefill per-day times from existing entries
      const map = await fetchExistingDayTimes(staffId, yearMonth);
      map.forEach((v,k)=> perDayTimes.set(k, v));
      if (!$('#ss-same-time')?.checked) updatePerDayList();
    } catch(e){
      console.warn('preselectExistingWeekdays failed', e);
    }
  }

  // role filter (Doctor/HR)
  function currentRole(){
    return ($('#ss-role-filter')?.value || '').trim();
  }

  // staff dropdowns
  function populateStaff(list){
    const filterSel = $('#ss-staff');
    if (filterSel){
      filterSel.innerHTML = ['<option value="">All</option>']
        .concat(list.map(u => `<option value="${u._id}">${escapeHtml(u.username)} (${escapeHtml(u.role)})</option>`))
        .join('');
    }
    const addSel = $('#ss-staff-select');
    if (addSel){
      addSel.innerHTML = ['<option value="">Select staff</option>']
        .concat(list.map(u => `<option value="${u._id}">${escapeHtml(u.username)} (${escapeHtml(u.role)})</option>`))
        .join('');
    }
  }

  function loadStaff(){
    const applyRoleToDropdowns = () => {
      const role = currentRole();
      const filtered = role ? (staffCache || []).filter(u => (u.role||'') === role) : (staffCache || []);
      populateStaff(filtered);
    };

    if (staffCache){ applyRoleToDropdowns(); return; }
    fetchJSON(api('/staff/list?roles=Doctor,HR'), { cache:'no-store' })
      .then(resp => { staffCache = resp.staff || []; applyRoleToDropdowns(); })
      .catch(() => populateStaff([]));
  }

  // panel
  async function showPanel(){
    $('#ss-add-panel')?.classList.remove('d-none');
    ensureTimePickers();
    loadStaff();

    // init year + month to current
    populateYearSelect();
    const now = new Date();
    setMonthActive(now.getMonth()+1);

    // auto-preselect on open (await so we can stop spinner precisely)
    await preselectExistingWeekdays();
    $('#ss-add-panel')?.scrollIntoView({ behavior:'smooth', block:'start' });
  }
  function hidePanel(){ $('#ss-add-panel')?.classList.add('d-none'); }

  // ---------- per-day time inputs ----------
  function ensureDayPicker(inputId, isStart, weekday){
    if (!window.flatpickr) return;
    const el = document.getElementById(inputId);
    if (!el) return;

    const map = isStart ? dayStartPickers : dayEndPickers;
    if (map.has(weekday)) return;

    const fp = flatpickr(el, { enableTime:true, noCalendar:true, dateFormat:'H:i' });
    map.set(weekday, fp);

    // Keep values even if user toggles day off then on (capture both 'change' and 'input')
    const updateVal = () => {
      const row = perDayTimes.get(weekday) || { start:'', end:'' };
      if (isStart) row.start = el.value; else row.end = el.value;
      perDayTimes.set(weekday, row);
    };
    el.addEventListener('change', updateVal);
    el.addEventListener('input', updateVal);
  }

  function updatePerDayList(){
    const container = document.getElementById('ss-per-day-list');
    if (!container) return;

    const days = selectedWeekdays();
    container.innerHTML = '';

    dayStartPickers.forEach(fp => fp.destroy()); dayStartPickers.clear();
    dayEndPickers.forEach(fp => fp.destroy());   dayEndPickers.clear();

    days.forEach(d => {
      const row = perDayTimes.get(d) || { start:'', end:'' };
      const startId = `ss-day-start-${d}`;
      const endId   = `ss-day-end-${d}`;
      container.insertAdjacentHTML('beforeend', `
        <div class="ss-day-row" data-weekday="${d}">
          <label class="mb-0">${weekdayName(d)}</label>
          <input id="${startId}" class="form-control" placeholder="Start HH:MM" value="${row.start || ''}">
          <span>–</span>
          <input id="${endId}" class="form-control" placeholder="End HH:MM" value="${row.end || ''}">
        </div>
      `);
      ensureDayPicker(startId, true, d);
      ensureDayPicker(endId,   false, d);
    });
  }

  // payload
  function assemblePayload(){
    const staffId   = $('#ss-staff-select')?.value || '';
    const yearMonth = getYearMonthFromUI();
    const weekdays  = selectedWeekdays();
    const sameTime  = $('#ss-same-time')?.checked;

    if (!weekdays.length) return { ok:false, msg:'Please pick at least one weekday.' };
    if (!yearMonth || !/^\d{4}-(0[1-9]|1[0-2])$/.test(yearMonth)) return { ok:false, msg:'Please pick a year and a month.' };
    if (!staffId) return { ok:false, msg:'Please select a staff member.' };

    const uniqueWeekdays = Array.from(new Set(weekdays)).sort((a,b)=>a-b);

    if (sameTime){
      const start = $('#ss-start')?.value || '';
      const end   = $('#ss-end')?.value   || '';
      if (!start || !end)   return { ok:false, msg:'Please set both start and end time.' };

      const sMin = hhmmToMin(start);
      const eMin = hhmmToMin(end);
      if (!Number.isFinite(sMin) || !Number.isFinite(eMin) || !(sMin < eMin)){
        return { ok:false, msg:'End time must be after start time.' };
      }
      return {
        ok:true,
        payload:{ mode:'same', staffId, yearMonth, weekdays: uniqueWeekdays, startMinutes:sMin, endMinutes:eMin }
      };
    }

    // per-day mode
    const dayTimes = [];
    for (const d of uniqueWeekdays){
      const mem = perDayTimes.get(d) || { start:'', end:'' };
      const start = document.getElementById(`ss-day-start-${d}`)?.value || mem.start || '';
      const end   = document.getElementById(`ss-day-end-${d}`)?.value   || mem.end   || '';

      if (!start || !end) return { ok:false, msg:`Please set time for ${weekdayName(d)}.` };

      const sMin = hhmmToMin(start), eMin = hhmmToMin(end);
      if (!Number.isFinite(sMin) || !Number.isFinite(eMin) || !(sMin < eMin)){
        return { ok:false, msg:`End time must be after start time for ${weekdayName(d)}.` };
      }
      dayTimes.push({ weekday:d, startMinutes:sMin, endMinutes:eMin });
    }

    return { ok:true, payload:{ mode:'per-day', staffId, yearMonth, dayTimes } };
  }

  // ---------- helpers ----------
  async function getExistingDOWs(staffId, yearMonth){
    const url = new URL(api('/staff-schedule/week'), window.location.origin);
    url.searchParams.set('yearMonth', yearMonth);
    url.searchParams.set('staffId', staffId);
    const resp = await fetchJSON(url.toString(), { cache:'no-store' });
    const row = Array.isArray(resp.rows) ? resp.rows[0] : null;

    const dows = [];
    if (row && row.days){
      for (let d=1; d<=7; d++){
        const arr = row.days[d];
        if (Array.isArray(arr) && arr.length) dows.push(d);
      }
    }
    return dows;
  }

  async function deleteWeekdaysForStaff(staffId, yearMonth, weekdays){
    if (!weekdays?.length) return { success:true, deletedCount:0, endpoint:null };

    const body = JSON.stringify({ staffId, yearMonth, weekdays });
    const opts = { method:'POST', headers:{ 'Content-Type':'application/json' }, body };

    const candidates = [
      '/staff-schedule/delete-weekdays',
      '/staff-schedule/delete',
      '/staff-schedule/remove-weekdays'
    ];

    for (const path of candidates){
      try{
        const resp = await fetchJSON(api(path), opts);
        if (resp && resp.success === true){
          return {
            success:true,
            deletedCount: Number(resp.deletedCount || resp.deleted || 0),
            endpoint: path
          };
        }
      }catch(_){}
    }
    throw new Error('Delete endpoint not available. Please add /staff-schedule/delete-weekdays on the server.');
  }

  // Prefill first time slot per day for staff+month
  async function fetchExistingDayTimes(staffId, yearMonth){
    const url = new URL(api('/staff-schedule/week'), window.location.origin);
    url.searchParams.set('yearMonth', yearMonth);
    url.searchParams.set('staffId', staffId);
    const resp = await fetchJSON(url.toString(), { cache:'no-store' });

    const row = (resp.rows && resp.rows[0]) ? resp.rows[0] : null;
    const map = new Map();
    if (!row || !row.days) return map;

    for (let d=1; d<=7; d++){
      const labels = Array.isArray(row.days[d]) ? row.days[d] : [];
      if (!labels.length) continue;
      const m = String(labels[0]).split(/–|-/);
      if (m.length === 2){
        map.set(d, { start: m[0], end: m[1] });
      }
    }
    return map;
  }

  // grid
  async function fetchGrid(){
    const fy = $('#ss-filter-ym');
    if (fy && !fy.value){
      const d = new Date();
      fy.value = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
    }
    const ym = ($('#ss-filter-ym')?.value || '').trim();
    const staffId = $('#ss-staff')?.value || '';
    const role = currentRole();

    const url = new URL(api('/staff-schedule/week'), window.location.origin);
    url.searchParams.set('yearMonth', ym);
    if (staffId) url.searchParams.set('staffId', staffId);

    try {
      const resp = await fetchJSON(url.toString(), { cache:'no-store' });
      let rows = resp.rows || [];
      if (role) rows = rows.filter(r => (r.staff?.role || '') === role);
      renderGrid(rows);
    } catch (e) {
      console.error(e);
      renderGrid([]);
      sweet('Load failed', 'Failed to load schedule grid.', 'error');
    }
  }

  function renderGrid(rows){
    const body = $('#ss-body');
    if (!body) return;
    if (!rows.length){
      body.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No data for selected month.</td></tr>`;
      return;
    }
    const dow = [1,2,3,4,5,6,7];
    const html = rows.map(r => {
      const staffLabel = `${escapeHtml(r.staff.username)} <small class="text-muted">(${escapeHtml(r.staff.role)})</small>`;
      const cells = dow.map(d => {
        let arr = Array.isArray(r.days[d]) ? r.days[d] : [];
        arr = Array.from(new Set(arr));
        if (!arr.length) return `<td class="align-middle text-muted text-center">—</td>`;
        return `<td class="align-middle">${arr.map(x => `<div class="ss-badge">${escapeHtml(x)}</div>`).join('')}</td>`;
      }).join('');
      return `<tr><td class="align-middle">${staffLabel}</td>${cells}</tr>`;
    }).join('');
    body.innerHTML = html;
  }

  // events
  function bind(){
    if (bound) return; bound = true;

    // show/hide panel with spinner on "Add Shift"
    document.addEventListener('click', async (e)=>{
      const add  = e.target.closest('#ss-add-shift');
      const canc = e.target.closest('#ss-cancel-panel');
      if (add){
        e.preventDefault();
        spinButton(add, 'Opening…');
        try { await showPanel(); } finally { unspinButton(add); }
        return;
      }
      if (canc){ e.preventDefault(); hidePanel(); return; }
    });

    // SAVE — replace selected weekdays (delete then create) with spinner
    document.addEventListener('click', async (e)=>{
      const btn = e.target.closest('#ss-save');
      if (!btn) return;
      e.preventDefault();
      if (btn.disabled) return;

      const res = assemblePayload();
      if (!res.ok) return sweet('Validation', res.msg, 'warning');

      spinButton(btn, 'Saving…');
      try {
        const staffId   = res.payload.staffId;
        const yearMonth = res.payload.yearMonth;

        const selectedWeekdaysForSave =
          res.payload.mode === 'same'
            ? Array.from(res.payload.weekdays)
            : res.payload.dayTimes.map(dt => parseInt(dt.weekday,10));

        // delete any existing for THESE weekdays in that month for that staff
        const removedInfo = await deleteWeekdaysForStaff(staffId, yearMonth, selectedWeekdaysForSave);

        // create new
        let created = 0, skipped = 0;

        if (res.payload.mode === 'same'){
          const createResp = await fetchJSON(api('/staff-schedule/create'), {
            method:'POST',
            headers:{ 'Content-Type':'application/json' },
            body: JSON.stringify({
              staffId,
              yearMonth,
              weekdays: res.payload.weekdays,
              startMinutes: res.payload.startMinutes,
              endMinutes: res.payload.endMinutes
            })
          });
          if (!createResp || createResp.success !== true) throw new Error(createResp?.message || 'Save failed');
          created = Number(createResp.created?.length || 0);
          skipped = Number(createResp.skipped?.length || 0);
        } else {
          const createResp = await fetchJSON(api('/staff-schedule/create-multi'), {
            method:'POST',
            headers:{ 'Content-Type':'application/json' },
            body: JSON.stringify({
              staffId,
              yearMonth,
              dayTimes: res.payload.dayTimes
            })
          });
          if (!createResp || createResp.success !== true) throw new Error(createResp?.message || 'Save failed');
          created = Number(createResp.created?.length || 0);
          skipped = Number(createResp.skipped?.length || 0);
        }

        const removed = Number(removedInfo.deletedCount || 0);
        const msg =
          `Updated weekday(s).<br/>` +
          `<b>${created}</b> created, <b>${skipped}</b> skipped, <b>${removed}</b> replaced.`;
        await sweet('Weekly shifts saved', msg, 'success', true);

        // show saved month in the grid filter
        const fy = document.getElementById('ss-filter-ym');
        if (fy) fy.value = yearMonth;

        hidePanel();
        await fetchGrid();
      } catch (err) {
        sweet('Save failed', err.message || 'Failed to save shifts.', 'error');
      } finally {
        unspinButton(btn);
      }
    });

    // Filters → Apply (with spinner)
    document.addEventListener('click', async (e)=>{
      const apply = e.target.closest('#ss-refresh');
      if (!apply) return;
      e.preventDefault();
      spinButton(apply, 'Applying…');
      try { await fetchGrid(); } finally { unspinButton(apply); }
    });

    // Role filter: re-populate staff dropdowns + refresh grid
    document.addEventListener('change', (e)=>{
      if (e.target && e.target.id === 'ss-role-filter'){
        loadStaff();
        const staffSel = $('#ss-staff');
        if (staffSel) staffSel.value = '';
        clearWeekdaySelection();
        fetchGrid();
      }
    });

    // When selecting staff, or toggling year/month in Add panel, auto-preselect existing weekdays
    document.addEventListener('change', (e)=>{
      if (!e.target) return;
      if (e.target.id === 'ss-staff-select'){
        preselectExistingWeekdays();
      }
      if (e.target.id === 'ss-same-time'){
        const on = e.target.checked;
        $('#ss-global-time-row')?.classList.toggle('d-none', !on);
        $('#ss-per-day-times')?.classList.toggle('d-none', on);
        if (!on) updatePerDayList();
      }
    });

    // bind pickers
    bindWeekdayPicker();
    bindMonthPicker();
  }

  // init
  function init(){
    ensureTimePickers();
    loadStaff();

    // week grid filter default
    const fy = $('#ss-filter-ym');
    if (fy && !fy.value){
      const d = new Date();
      fy.value = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
    }
    bind();
    fetchGrid();
  }

  window.StaffSchedule = { init };
  if (document.getElementById('ss-body')) init();
})();
