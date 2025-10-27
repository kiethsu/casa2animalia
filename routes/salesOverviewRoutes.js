// routes/salesOverviewRoutes.js
const express   = require('express');
const router    = express.Router();

const Payment   = require('../models/Payment');
const Inventory = require('../models/inventory');
const Service   = require('../models/service');
const Operating = require('../models/operating'); // <-- OPEX

// Helpers
function startOfMonth(year, monthIdx) {           // monthIdx: 0..11
  return new Date(Number(year), Number(monthIdx), 1, 0, 0, 0, 0);
}
function endOfMonth(year, monthIdx) {
  return new Date(Number(year), Number(monthIdx) + 1, 0, 23, 59, 59, 999);
}
const peso = (n) => Number(n || 0);

// --- name normalizers ---
function normalize(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/[^\w\s]/g, '')     // strip punctuation
    .trim();
}
function removeParenContent(s) {
  return String(s || '').replace(/\([^)]*\)/g, '').replace(/\s+/g, ' ').trim();
}
function hyphenToSpace(s) {
  return String(s || '').replace(/[-–—]+/g, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * GET /admin/sales-kpis?month=0..11&year=YYYY
 * {
 *   sales,         // revenue (products+services at selling price)
 *   productCost,   // COP = (products sold base) + (expired base)
 *   serviceCost,   // Σ(qty × Service.basePrice) for sold services
 *   opex,          // Σ Operating.amount in month
 *   operatingIncome
 * }
 */
router.get('/sales-kpis', async (req, res) => {
  try {
    const monthIdx = req.query.month ?? new Date().getMonth();
    const year     = req.query.year ?? new Date().getFullYear();

    const from = startOfMonth(year, monthIdx);
    const to   = endOfMonth(year, monthIdx);

    // Pull payments in period (revenue + qtys)
    const payments = await Payment.find(
      { paidAt: { $gte: from, $lte: to } },
      { products: 1, services: 1 }
    ).lean();

    let salesRevenue = 0;

    // For product cost (base)
    const soldQtyByProductName = Object.create(null);

    // For service cost (need per-line details for matching)
    const serviceLines = []; // { name, qty, unitPrice }

    for (const p of payments) {
      // PRODUCTS
      for (const li of (p.products || [])) {
        salesRevenue += peso(li.lineTotal); // selling price
        const key = String(li.name || '').trim();
        if (!key) continue;
        soldQtyByProductName[key] = (soldQtyByProductName[key] || 0) + Number(li.quantity || 0);
      }

      // SERVICES
      for (const li of (p.services || [])) {
        salesRevenue += peso(li.lineTotal); // selling price
        serviceLines.push({
          name: String(li.name || '').trim(),
          qty: Number(li.quantity || 0),
          unitPrice: Number(li.unitPrice || 0)
        });
      }
    }

    /* ------------------- Cost of Products Sold (BASE) ------------------- */
    const productNames = Object.keys(soldQtyByProductName);
    let costProductsSoldBase = 0;

    if (productNames.length) {
      const invDocs = await Inventory.find(
        { name: { $in: productNames } },
        { name: 1, basePrice: 1 }
      ).lean();

      const baseByName = Object.create(null);
      for (const d of invDocs) {
        const key = String(d.name || '').trim();
        if (!key) continue;
        baseByName[key] = Number(d.basePrice || 0);
      }

      for (const name of productNames) {
        const qty  = Number(soldQtyByProductName[name] || 0);
        const base = Number(baseByName[name] || 0);
        costProductsSoldBase += qty * base;
      }
    }

    /* ------------------- Expired cost (BASE) ------------------- */
    const invWithExpiries = await Inventory.find(
      { expiredDates: { $elemMatch: { $gte: from, $lte: to } } },
      { basePrice: 1, expiredDates: 1 }
    ).lean();

    let costExpiredBase = 0;
    for (const inv of invWithExpiries) {
      const base = Number(inv.basePrice || 0);
      const countInRange = (inv.expiredDates || []).reduce((acc, d) => {
        const dt = new Date(d);
        return (dt >= from && dt <= to) ? acc + 1 : acc;
      }, 0);
      costExpiredBase += countInRange * base;
    }

    const productCost = costProductsSoldBase + costExpiredBase;

    /* ------------------- Cost of Services (BASE) ------------------- */
    let serviceCost = 0;
    if (serviceLines.length) {
      // load all services once
      const allSvcs = await Service.find(
        {},
        { serviceName: 1, weight: 1, dosage: 1, basePrice: 1, price: 1 }
      ).lean();

      // Build variant map -> service (basePrice)
      const variantMap = new Map();  // key: normalized variant, val: service doc
      const byPrice    = new Map();  // key: price number, val: Service[] (for fallback)

      for (const s of allSvcs) {
        const sName   = String(s.serviceName || '').trim();
        const weight  = String(s.weight || '').trim();
        const dosage  = String(s.dosage || '').trim();

        const variants = new Set();

        // base variants
        variants.add(normalize(sName));
        // with weight
        if (weight) {
          variants.add(normalize(`${sName} ${weight}`));
          variants.add(normalize(`${sName} - ${weight}`));
          variants.add(normalize(`${sName} (${weight})`));
        }
        // with weight + dosage
        if (weight && dosage) {
          variants.add(normalize(`${sName} ${weight} ${dosage}`));
          variants.add(normalize(`${sName} - ${weight} - ${dosage}`));
          variants.add(normalize(`${sName} (${weight}) ${dosage}`));
        }
        // dosage alone (in case UI shows it)
        if (dosage) {
          variants.add(normalize(`${sName} ${dosage}`));
          variants.add(normalize(`${sName} - ${dosage}`));
        }

        // store in variant map
        for (const v of variants) {
          if (!variantMap.has(v)) variantMap.set(v, s);
        }

        // price index for fallback match
        const priceKey = Number(s.price || 0);
        if (!byPrice.has(priceKey)) byPrice.set(priceKey, []);
        byPrice.get(priceKey).push(s);
      }

      // helper: attempt to resolve a line to a service
      function resolveService(lineName, unitPrice) {
        if (!lineName) return null;

        // try direct normalized
        const n1 = normalize(lineName);
        if (variantMap.has(n1)) return variantMap.get(n1);

        // try removing parentheses
        const n2 = normalize(removeParenContent(lineName));
        if (variantMap.has(n2)) return variantMap.get(n2);

        // try hyphen normalization
        const n3 = normalize(hyphenToSpace(removeParenContent(lineName)));
        if (variantMap.has(n3)) return variantMap.get(n3);

        // substring match: find services whose normalized serviceName is contained in line name
        // pick the longest serviceName match (more specific)
        let best = null;
        let bestLen = 0;
        for (const s of allSvcs) {
          const baseName = normalize(s.serviceName || '');
          if (!baseName) continue;
          if (n1.includes(baseName) || n2.includes(baseName) || n3.includes(baseName)) {
            if (baseName.length > bestLen) {
              best = s; bestLen = baseName.length;
            }
          }
        }
        if (best) return best;

        // final fallback: price match (unique)
        const candidates = byPrice.get(Number(unitPrice || 0)) || [];
        if (candidates.length === 1) return candidates[0];

        return null;
      }

      for (const li of serviceLines) {
        const svc = resolveService(li.name, li.unitPrice);
        const base = svc ? Number(svc.basePrice || 0) : 0;
        serviceCost += base * Number(li.qty || 0);
      }
    }

    /* ------------------- OPEX (Operating Expenses) ------------------- */
    let opex = 0;
    try {
      const opexAgg = await Operating.aggregate([
        { $match: { createdAt: { $gte: from, $lte: to } } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]);
      if (opexAgg.length) opex = Number(opexAgg[0].total || 0);
    } catch (e) {
      console.warn('OPEX aggregation failed:', e.message);
      opex = 0; // fail-safe
    }

    /* ------------------- Operating Income ------------------- */
    const operatingIncome = salesRevenue - (productCost + serviceCost + opex);

    res.json({
      sales: salesRevenue,
      productCost,
      serviceCost,
      opex,
      operatingIncome
    });
  } catch (err) {
    console.error('sales-kpis error:', err);
    res.status(500).json({
      sales: 0,
      productCost: 0,
      serviceCost: 0,
      opex: 0,
      operatingIncome: 0
    });
  }
});
// --- helpers for date ranges (put near your other helpers) ---
function startOfDay(d){ const x=new Date(d); x.setHours(0,0,0,0); return x; }
function endOfDay(d){ const x=new Date(d); x.setHours(23,59,59,999); return x; }
function daysAgo(n){ const x=new Date(); x.setDate(x.getDate()-n); return x; }

// --- SALES BREAKDOWN (products & services, selling price) ---
router.get('/sales-breakdown', async (req, res) => {
  try {
    const preset = String(req.query.preset || '7d');
    let from, to;

    if (preset === 'monthpick') {
      const m = Number(req.query.month ?? new Date().getMonth());
      const y = Number(req.query.year  ?? new Date().getFullYear());
      from = startOfMonth(y, m);
      to   = endOfMonth(y, m);
    } else if (preset === 'today') {
      from = startOfDay(new Date());
      to   = endOfDay(new Date());
    } else if (preset === '30d') {
      from = startOfDay(daysAgo(29));
      to   = endOfDay(new Date());
    } else { // '7d' default
      from = startOfDay(daysAgo(6));
      to   = endOfDay(new Date());
    }

    const payments = await Payment.find(
      { paidAt: { $gte: from, $lte: to } },
      { products: 1, services: 1 }
    ).lean();

    // --- aggregate products ---
    const prodMap = new Map(); // key: normalizedName|unitPrice
    const norm = s => String(s||'').trim().toLowerCase().replace(/\s+/g,' ');

    for (const p of payments) {
      for (const li of (p.products || [])) {
        const name = String(li.name || '').trim();
        const qty  = Number(li.quantity || 0);
        const unit = Number(li.unitPrice || 0);
        const tot  = Number(li.lineTotal || (qty * unit));
        if (!name || qty <= 0) continue;

        const key = `${norm(name)}|${unit}`;
        if (!prodMap.has(key)) {
          prodMap.set(key, { name, qty: 0, unitPrice: unit, total: 0 });
        }
        const row = prodMap.get(key);
        row.qty   += qty;
        row.total += tot;
      }
    }

    const products = [...prodMap.values()].sort((a,b) => b.total - a.total);
    const productsSubtotal = products.reduce((s, r) => s + r.total, 0);

    // --- aggregate services ---
    const svcMap = new Map(); // key: normalizedName|unitPrice
    for (const p of payments) {
      for (const li of (p.services || [])) {
        const name = String(li.name || '').trim();
        const qty  = Number(li.quantity || 0);
        const unit = Number(li.unitPrice || 0);
        const tot  = Number(li.lineTotal || (qty * unit));
        if (!name || qty <= 0) continue;

        const key = `${norm(name)}|${unit}`;
        if (!svcMap.has(key)) {
          svcMap.set(key, { name, count: 0, fee: unit, total: 0 });
        }
        const row = svcMap.get(key);
        row.count += qty;
        row.total += tot;
      }
    }

    const services = [...svcMap.values()].sort((a,b) => b.total - a.total);
    const servicesSubtotal = services.reduce((s, r) => s + r.total, 0);

    res.json({
      products,
      productsSubtotal,
      services,
      servicesSubtotal,
      grandTotal: productsSubtotal + servicesSubtotal
    });
  } catch (err) {
    console.error('sales-breakdown error:', err);
    res.json({
      products: [],
      productsSubtotal: 0,
      services: [],
      servicesSubtotal: 0,
      grandTotal: 0
    });
  }
});
// --- extra helpers (place near other helpers) ---
function startOfYear(year){ return new Date(Number(year), 0, 1, 0,0,0,0); }
function endOfYear(year){   return new Date(Number(year), 11, 31, 23,59,59,999); }

// --- COST OF PRODUCT SOLD BREAKDOWN (BASE/PURCHASE PRICE) ---
router.get('/cop-breakdown', async (req, res) => {
  try {
    const preset = String(req.query.preset || '7d');

    let from, to;
    const now = new Date();

    if (preset === 'monthpick') {
      const m = Number(req.query.month ?? now.getMonth());
      const y = Number(req.query.year  ?? now.getFullYear());
      from = startOfMonth(y, m);
      to   = endOfMonth(y, m);
    } else if (preset === 'today') {
      from = startOfDay(now);
      to   = endOfDay(now);
    } else if (preset === '30d') {
      from = startOfDay(daysAgo(29));
      to   = endOfDay(now);
    } else if (preset === 'month') {
      from = startOfMonth(now.getFullYear(), now.getMonth());
      to   = endOfMonth(now.getFullYear(), now.getMonth());
    } else if (preset === 'year') {
      from = startOfYear(now.getFullYear());
      to   = endOfYear(now.getFullYear());
    } else { // '7d' default
      from = startOfDay(daysAgo(6));
      to   = endOfDay(now);
    }

    // 1) SOLD PRODUCTS (qty × basePrice)
    const payments = await Payment.find(
      { paidAt: { $gte: from, $lte: to } },
      { products: 1 }
    ).lean();

    const soldQtyByName = new Map();   // key: product name (trim), val: qty
    for (const p of payments) {
      for (const li of (p.products || [])) {
        const name = String(li.name || '').trim();
        const qty  = Number(li.quantity || 0);
        if (!name || qty <= 0) continue;
        soldQtyByName.set(name, (soldQtyByName.get(name) || 0) + qty);
      }
    }

    let products = [];
    let productsSubtotal = 0;

    if (soldQtyByName.size) {
      const names = [...soldQtyByName.keys()];
      const invDocs = await Inventory.find(
        { name: { $in: names } },
        { name: 1, basePrice: 1 }
      ).lean();

      const baseByName = new Map();
      for (const d of invDocs) {
        baseByName.set(String(d.name || '').trim(), Number(d.basePrice || 0));
      }

      for (const [name, qty] of soldQtyByName.entries()) {
        const purchase = Number(baseByName.get(name) || 0);
        const total = qty * purchase;
        products.push({ name, qty, purchase, total });
        productsSubtotal += total;
      }

      // sort by highest total cost
      products.sort((a, b) => b.total - a.total);
    }

    // 2) EXPIRED PRODUCTS (count × basePrice) within range
    const invWithExp = await Inventory.find(
      { expiredDates: { $elemMatch: { $gte: from, $lte: to } } },
      { name: 1, basePrice: 1, expiredDates: 1 }
    ).lean();

    const expired = [];
    let expiredSubtotal = 0;

    for (const inv of invWithExp) {
      const name = String(inv.name || '').trim();
      const base = Number(inv.basePrice || 0);
      const qty = (inv.expiredDates || []).reduce((acc, d) => {
        const dt = new Date(d);
        return (dt >= from && dt <= to) ? acc + 1 : acc;
      }, 0);
      if (qty > 0) {
        const total = qty * base;
        expired.push({ name, qty, purchase: base, total });
        expiredSubtotal += total;
      }
    }
    expired.sort((a, b) => b.total - a.total);

    res.json({
      products,
      productsSubtotal,
      expired,
      expiredSubtotal,
      grandTotal: productsSubtotal + expiredSubtotal
    });
  } catch (err) {
    console.error('cop-breakdown error:', err);
    res.json({
      products: [],
      productsSubtotal: 0,
      expired: [],
      expiredSubtotal: 0,
      grandTotal: 0
    });
  }
});
router.get('/cos-breakdown', async (req, res) => {
  try {
    const preset = String(req.query.preset || '7d');
    const now = new Date();
    let from, to;

    if (preset === 'monthpick') {
      const m = Number(req.query.month ?? now.getMonth());
      const y = Number(req.query.year  ?? now.getFullYear());
      from = startOfMonth(y, m);
      to   = endOfMonth(y, m);
    } else if (preset === 'today') {
      from = startOfDay(now);
      to   = endOfDay(now);
    } else if (preset === '30d') {
      from = startOfDay(daysAgo(29));
      to   = endOfDay(now);
    } else if (preset === 'month') {
      from = startOfMonth(now.getFullYear(), now.getMonth());
      to   = endOfMonth(now.getFullYear(), now.getMonth());
    } else if (preset === 'year') {
      from = startOfYear(now.getFullYear());
      to   = endOfYear(now.getFullYear());
    } else { // '7d'
      from = startOfDay(daysAgo(6));
      to   = endOfDay(now);
    }

    // Load payments within range (services only)
    const payments = await Payment.find(
      { paidAt: { $gte: from, $lte: to } },
      { services: 1 }
    ).lean();

    // Load services once (for name/variant matching and basePrice)
    const allSvcs = await Service.find(
      {},
      { serviceName: 1, weight: 1, dosage: 1, basePrice: 1, price: 1 }
    ).lean();

    // Build variant map and price index (reuse your normalizers)
    const variantMap = new Map();  // normalized variant -> service doc
    const byPrice    = new Map();  // selling price -> [service docs]

    for (const s of allSvcs) {
      const sName  = String(s.serviceName || '').trim();
      const weight = String(s.weight || '').trim();
      const dosage = String(s.dosage || '').trim();
      const variants = new Set();

      variants.add(normalize(sName));
      if (weight) {
        variants.add(normalize(`${sName} ${weight}`));
        variants.add(normalize(`${sName} - ${weight}`));
        variants.add(normalize(`${sName} (${weight})`));
      }
      if (weight && dosage) {
        variants.add(normalize(`${sName} ${weight} ${dosage}`));
        variants.add(normalize(`${sName} - ${weight} - ${dosage}`));
        variants.add(normalize(`${sName} (${weight}) ${dosage}`));
      }
      if (dosage) {
        variants.add(normalize(`${sName} ${dosage}`));
        variants.add(normalize(`${sName} - ${dosage}`));
      }

      for (const v of variants) {
        if (!variantMap.has(v)) variantMap.set(v, s);
      }

      const priceKey = Number(s.price || 0);
      if (!byPrice.has(priceKey)) byPrice.set(priceKey, []);
      byPrice.get(priceKey).push(s);
    }

    function resolveService(lineName, unitPrice) {
      if (!lineName) return null;

      const n1 = normalize(lineName);
      if (variantMap.has(n1)) return variantMap.get(n1);

      const n2 = normalize(removeParenContent(lineName));
      if (variantMap.has(n2)) return variantMap.get(n2);

      const n3 = normalize(hyphenToSpace(removeParenContent(lineName)));
      if (variantMap.has(n3)) return variantMap.get(n3);

      // substring fallback (longest match)
      let best = null, bestLen = 0;
      for (const s of allSvcs) {
        const baseName = normalize(s.serviceName || '');
        if (!baseName) continue;
        if (n1.includes(baseName) || n2.includes(baseName) || n3.includes(baseName)) {
          if (baseName.length > bestLen) { best = s; bestLen = baseName.length; }
        }
      }
      if (best) return best;

      // price-only fallback (only if unique)
      const candidates = byPrice.get(Number(unitPrice || 0)) || [];
      if (candidates.length === 1) return candidates[0];

      return null;
    }

    // Aggregate: key by resolved service _id
    const agg = new Map(); // _id -> { name, purchase, total }
  function dispName(svc) {
  return String(svc.serviceName || '').trim();
}


    for (const p of payments) {
      for (const li of (p.services || [])) {
        const qty = Number(li.quantity || 0);
        if (qty <= 0) continue;

        const svc = resolveService(String(li.name || '').trim(), Number(li.unitPrice || 0));
        if (!svc) continue;

        const base = Number(svc.basePrice || 0);
        if (base <= 0) continue;

        const key = String(svc._id);
        if (!agg.has(key)) {
          agg.set(key, { name: dispName(svc), purchase: base, total: 0 });
        }
        const row = agg.get(key);
        row.total += base * qty;
      }
    }

    const services = [...agg.values()].sort((a, b) => b.total - a.total);
    const servicesTotal = services.reduce((s, r) => s + Number(r.total || 0), 0);

    res.json({ services, servicesTotal });
  } catch (err) {
    console.error('cos-breakdown error:', err);
    res.json({ services: [], servicesTotal: 0 });
  }
});
// --- OPEX BREAKDOWN (Operating Expenses) ---
router.get('/opex-breakdown', async (req, res) => {
  try {
    const preset = String(req.query.preset || '7d');
    let from, to;

    if (preset === 'today') {
      from = startOfDay(new Date());
      to   = endOfDay(new Date());
    } else if (preset === '30d') {
      from = startOfDay(daysAgo(29));
      to   = endOfDay(new Date());
    } else if (preset === 'year') {
      const y = Number(req.query.year ?? new Date().getFullYear());
      from = new Date(y, 0, 1, 0, 0, 0, 0);
      to   = new Date(y, 11, 31, 23, 59, 59, 999);
    } else if (preset === 'month') {
      // Supports explicit month/year from the GLOBAL filter
      const m = Number(req.query.month ?? new Date().getMonth());
      const y = Number(req.query.year  ?? new Date().getFullYear());
      from = startOfMonth(y, m);
      to   = endOfMonth(y, m);
    } else { // '7d' default
      from = startOfDay(daysAgo(6));
      to   = endOfDay(new Date());
    }

    const docs = await Operating.find(
      { createdAt: { $gte: from, $lte: to } },
      { amount: 1, type: 1, category: 1, name: 1, description: 1 }
    ).lean();

    // Group by the most descriptive available label
    const bucket = new Map(); // key: label, value: total amount
    let total = 0;

    for (const d of docs) {
      const labelRaw = d.type || d.category || d.name || d.description || 'Other';
      const label = String(labelRaw).trim() || 'Other';
      const amt = Number(d.amount || 0);

      total += amt;
      bucket.set(label, (bucket.get(label) || 0) + amt);
    }

    const opex = [...bucket.entries()]
      .map(([type, amount]) => ({ type, amount }))
      .sort((a, b) => b.amount - a.amount);

    res.json({ opex, total });
  } catch (err) {
    console.error('opex-breakdown error:', err);
    res.json({ opex: [], total: 0 });
  }
});
// === Predictive Insights (top service & product based on past month) ===
function monthName(idx){ 
  return ['January','February','March','April','May','June','July','August','September','October','November','December'][Number(idx)] || ''; 
}
function clamp(n, lo, hi){ return Math.max(lo, Math.min(hi, n)); }
function roundPct(n){ return Math.round(Number(n) || 0); }
function normalizeKey(s){
  return String(s||'').toLowerCase().replace(/\s+/g,' ').trim();
}
const RECURRING_SERVICE_HINTS = [
  /groom/i, /bath/i, /nail/i, /trim/i, /hair/i,
  /vaccine/i, /vaccination/i, /booster/i, /deworm/i,
  /consult/i, /check.?up/i, /follow.?up/i, /boarding/i
];

router.get('/predictive-insights', async (req, res) => {
  try {
    // Determine base month (default: last complete month)
    const now = new Date();
    let baseMonth = (req.query.month !== undefined && req.query.month !== 'all')
      ? Number(req.query.month)
      : (now.getMonth() + 11) % 12;                   // previous month
    let baseYear  = (req.query.year  !== undefined && req.query.year  !== 'all')
      ? Number(req.query.year)
      : (now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear());

    // If the query provided month/year but the month equals current (incomplete), fallback to previous complete month
    if (req.query.month !== undefined && Number(req.query.month) === now.getMonth() && Number(req.query.year || now.getFullYear()) === now.getFullYear()) {
      baseMonth = (now.getMonth() + 11) % 12;
      baseYear  = (now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear());
    }

    const baseFrom = startOfMonth(baseYear, baseMonth);
    const baseTo   = endOfMonth(baseYear, baseMonth);

    // Previous month (for trend)
    const prevMonth = (baseMonth + 11) % 12;
    const prevYear  = (baseMonth === 0 ? baseYear - 1 : baseYear);
    const prevFrom  = startOfMonth(prevYear, prevMonth);
    const prevTo    = endOfMonth(prevYear, prevMonth);

    // Helper to read payments and compute totals for a range
    async function getTotals(from, to){
      const pays = await Payment.find(
        { paidAt: { $gte: from, $lte: to } },
        { products: 1, services: 1 }
      ).lean();

      let totalRevenue = 0;

      const byService = new Map(); // key=name -> revenue
      const byProduct = new Map(); // key=name -> revenue

      for (const p of pays) {
        for (const li of (p.products || [])) {
          const name = String(li.name || '').trim();
          const qty  = Number(li.quantity || 0);
          const unit = Number(li.unitPrice || 0);
          const rev  = Number(li.lineTotal || (qty * unit));
          if (!name || rev <= 0) continue;
          totalRevenue += rev;
          const k = normalizeKey(name);
          byProduct.set(k, (byProduct.get(k) || 0) + rev);
        }
        for (const li of (p.services || [])) {
          const name = String(li.name || '').trim();
          const qty  = Number(li.quantity || 0);
          const unit = Number(li.unitPrice || 0);
          const rev  = Number(li.lineTotal || (qty * unit));
          if (!name || rev <= 0) continue;
          totalRevenue += rev;
          const k = normalizeKey(name);
          byService.set(k, (byService.get(k) || 0) + rev);
        }
      }
      return { totalRevenue, byService, byProduct };
    }

    const base = await getTotals(baseFrom, baseTo);
    const prev = await getTotals(prevFrom, prevTo);

    // Utility to find top entry and compute shares/trend
    function pickTop(map, total){
      let topKey = null, topVal = 0;
      for (const [k, v] of map.entries()){
        if (v > topVal){ topVal = v; topKey = k; }
      }
      if (!topKey || total <= 0) return null;
      const share = 100 * (topVal / total);
      return { key: topKey, value: topVal, sharePct: share };
    }
    function prevShareFor(key, prevMap, prevTotal){
      if (!prevTotal || !prevMap.has(key)) return 0;
      return 100 * (Number(prevMap.get(key) || 0) / prevTotal);
    }
    function looksRecurring(name){
      return RECURRING_SERVICE_HINTS.some(rx => rx.test(name || ''));
    }

    const topService = pickTop(base.byService, base.totalRevenue);
    const topProduct = pickTop(base.byProduct, base.totalRevenue);

    // Compose predictions
    function buildServiceForecast(top){
      if (!top) return { text: 'Not enough service data last month to generate a forecast.', empty: true };
      const displayName = top.key.replace(/\b\w/g, c => c.toUpperCase()); // simple title-case
      const share = roundPct(top.sharePct);
      const pShare = prevShareFor(top.key, prev.byService, prev.totalRevenue);
      const trend = roundPct(share - pShare); // percentage points

      const recurring = looksRecurring(displayName);
      // Range logic: same or higher for recurring; allow ± for non-recurring
      const baseLo = recurring ? share : clamp(share - 2, 0, 100);
      const extraUp = (trend > 0 ? Math.min(trend, 3) : 0) + (recurring ? 5 : 3);
      const baseHi = clamp(share + extraUp, 0, 100);

      const monthTxt = `${monthName(baseMonth)} ${baseYear}`;
      const dir = trend > 0 ? 'up' : (trend < 0 ? 'down' : 'flat');

      let reason = recurring
        ? 'This service is typically recurring for many clients.'
        : 'Recent performance suggests similar demand with normal month-to-month noise.';
      if (trend !== 0) {
        reason += ` (${trend > 0 ? '+' : ''}${trend} pp vs ${monthName(prevMonth)}).`;
      }

      const text =
        `Based on ${monthTxt} sales, **${displayName}** comprised **${share}%** of total revenue. ${reason} ` +
        `An estimate for next month is **${baseLo}–${baseHi}%** of total revenue.`;

      return { name: displayName, share, trend, dir, low: baseLo, high: baseHi, text };
    }

    function buildProductForecast(top){
      if (!top) return { text: 'Not enough product data last month to generate a forecast.', empty: true };
      const displayName = top.key.replace(/\b\w/g, c => c.toUpperCase());
      const share = roundPct(top.sharePct);
      const pShare = prevShareFor(top.key, prev.byProduct, prev.totalRevenue);
      const trend = roundPct(share - pShare);

      // Heuristic: staple/medication keywords → narrow upward range like 0–5pp
      const stapleRx = /(insulin|food|kibble|vitamin|supplement|maintenance|flea|tick|deworm|antibiotic|medicat)/i;
      const isStaple = stapleRx.test(displayName);

      const baseLo = clamp(share + Math.min(trend, 0), 0, 100);
      const uplift  = (trend > 0 ? Math.min(trend, 3) : (isStaple ? 3 : 2));
      const pad     = isStaple ? 2 : 1; // small optimism for staples
      const baseHi = clamp(share + uplift + pad, 0, 100);

      const monthTxt = `${monthName(baseMonth)} ${baseYear}`;
      const reason = isStaple
        ? 'This looks like a staple/maintenance product, so demand tends to be steady.'
        : 'Expect normal variation unless a promo or stock-out changes demand.';
      const trendNote = (trend !== 0) ? ` (${trend > 0 ? '+' : ''}${trend} pp vs ${monthName(prevMonth)}).` : '';

      const text =
        `Based on ${monthTxt} sales, **${displayName}** contributed **${share}%** of total revenue. ` +
        `${reason}${trendNote} Estimated share next month: **${baseLo}–${baseHi}%**.`;

      return { name: displayName, share, trend, low: baseLo, high: baseHi, text };
    }

    const svc = buildServiceForecast(topService);
    const prod = buildProductForecast(topProduct);

    res.json({
      baseMonthName: monthName(baseMonth),
      baseYear,
      service: svc,
      product: prod
    });
  } catch (e) {
    console.error('predictive-insights error:', e);
    res.json({
      baseMonthName: '',
      baseYear: '',
      service: { text: 'Predictive analysis unavailable.' },
      product: { text: 'Predictive analysis unavailable.' }
    });
  }
});

module.exports = router;
