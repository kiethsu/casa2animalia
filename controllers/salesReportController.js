// controllers/salesReportController.js
const mongoose   = require('mongoose');
const Payment    = require('../models/Payment');
const Inventory  = require('../models/inventory');
const Service    = require('../models/service');
const ExcelJS = require('exceljs');
const { ChartJSNodeCanvas } = require('chartjs-node-canvas');



/* ------------------------------------------------------------------ *
 * Date utilities
 * ------------------------------------------------------------------ */
function parseDates(req) {
  const { range, start, end } = req.query;
  const now = new Date(); now.setHours(23,59,59,999);

  if (start && end) {
    const s = new Date(start); s.setHours(0,0,0,0);
    const e = new Date(end);   e.setHours(23,59,59,999);
    return { s, e };
  }
  let s = new Date(now), e = new Date(now);
  if (range === 'day' || range === 'today')  s.setHours(0,0,0,0);
  else if (range === '7d' || range === 'week')  { s.setDate(now.getDate()-6); s.setHours(0,0,0,0); }
  else if (range === '30d') { s = new Date(now.getFullYear(), now.getMonth(), now.getDate()-29); s.setHours(0,0,0,0); }
  else if (range === 'mtd' || range === 'month') { s = new Date(now.getFullYear(), now.getMonth(), 1); }
  else if (range === 'ytd' || range === 'year')  { s = new Date(now.getFullYear(), 0, 1); }
  else s.setHours(0,0,0,0);
  return { s, e };
}
function msBetween(a,b){ return (b.getTime() - a.getTime()) + 1; }

function paymentDateMatch(s, e) {
  return {
    $or: [
      { paidAt:    { $gte: s, $lte: e } },
      { createdAt: { $gte: s, $lte: e } }
    ]
  };
}

/* ------------------------------------------------------------------ *
 * Simple: distinct product categories
 * ------------------------------------------------------------------ */
exports.getProductCategories = async (_req, res) => {
  try {
    const cats = await Inventory.distinct('category');
    const out  = cats.filter(Boolean).sort((a,b)=>a.localeCompare(b));
    res.json(out);
  } catch (err) {
    console.error('getProductCategories error:', err);
    res.status(500).json([]);
  }
};

/* ------------------------------------------------------------------ *
 * Sales by PRODUCT (optionally filter by Inventory.category)
 * ------------------------------------------------------------------ */
exports.getSalesByProduct = async (req, res) => {
  try {
    const { s, e } = parseDates(req);
    const category = (req.query.category || '').trim();

    const pipeline = [
      { $match: paymentDateMatch(s, e) },
      { $unwind: '$products' },
      { $lookup: {
          from: 'inventories',
          localField: 'products.name',
          foreignField: 'name',
          as: 'inv'
      }},
      { $unwind: { path: '$inv', preserveNullAndEmptyArrays: true } },
    ];

    if (category) pipeline.push({ $match: { 'inv.category': category } });

    // Revenue: prefer stored lineTotal; fallback to qty * (unitPrice || inv.price)
    const revenueTerm = {
      $ifNull: [
        '$products.lineTotal',
        { $multiply: [
            { $ifNull: ['$products.quantity', 0] },
            { $ifNull: ['$products.unitPrice', { $ifNull: ['$inv.price', 0] }] }
        ] }
      ]
    };

    pipeline.push(
      { $group: {
          _id: '$products.name',
          unitsSold: { $sum: { $ifNull: ['$products.quantity', 0] } },
          revenue:   { $sum: revenueTerm }
      }},
      { $sort: { revenue: -1 } },
      { $project: { _id:0, productName:'$_id', unitsSold:1, revenue:1 } }
    );

    const products = await Payment.aggregate(pipeline);
    res.json({ products });
  } catch (err) {
    console.error('getSalesByProduct error:', err);
    res.status(500).json({ products: [] });
  }
};

/* ------------------------------------------------------------------ *
 * Sales by SERVICE (optionally filter by Service.category ObjectId)
 * ------------------------------------------------------------------ */
exports.getSalesByService = async (req, res) => {
  try {
    const { s, e } = parseDates(req);
    const categoryId = (req.query.serviceCategory || req.query.category || '').trim();

    const pipeline = [
      { $match: paymentDateMatch(s, e) },
      { $unwind: '$services' },
      { $lookup: {
          from: 'services',
          localField: 'services.name',
          foreignField: 'serviceName',
          as: 'svc'
      }},
      { $unwind: { path: '$svc', preserveNullAndEmptyArrays: true } },
    ];

    if (categoryId && mongoose.Types.ObjectId.isValid(categoryId)) {
      pipeline.push({ $match: { 'svc.category': new mongoose.Types.ObjectId(categoryId) } });
    }

    // Revenue: prefer lineTotal; fallback qty * unitPrice
    const revenueTerm = {
      $ifNull: [
        '$services.lineTotal',
        { $multiply: [
            { $ifNull: ['$services.quantity', 1] },
            { $ifNull: ['$services.unitPrice', 0] }
        ] }
      ]
    };

    pipeline.push(
      { $group: {
          _id: '$services.name',
          unitsSold: { $sum: {
            $cond: [
              { $ifNull: ['$services.quantity', false] }, '$services.quantity', 1
            ]
          }},
          revenue: { $sum: revenueTerm }
      }},
      { $sort: { revenue: -1 } },
      { $project: { _id:0, serviceName:'$_id', unitsSold:1, revenue:1 } }
    );

    const services = await Payment.aggregate(pipeline);
    res.json({ services });
  } catch (err) {
    console.error('getSalesByService error:', err);
    res.status(500).json({ services: [] });
  }
};

/* ------------------------------------------------------------------ *
 * Expired loss breakdown (products): full/base/markup
 * ------------------------------------------------------------------ */
async function expiredLossBreakdownForCategory(s, e, category /* string | '' */) {
  const matchStage = category ? { $match: { category } } : { $match: {} };

  const rows = await Inventory.aggregate([
    matchStage,
    { $project: {
        basePrice: { $ifNull: ['$basePrice', 0] },
        price:     { $ifNull: ['$price', 0] },
        markup:    { $ifNull: ['$markup', { $subtract: [{ $ifNull: ['$price', 0] }, { $ifNull: ['$basePrice', 0] }] }] },
        expiredDates: { $ifNull: ['$expiredDates', []] },
        expiredInRange: {
          $size: {
            $filter: {
              input: { $ifNull: ['$expiredDates', []] },
              as: 'd',
              cond: { $and: [
                { $gte: ['$$d', s] },
                { $lte: ['$$d', e] }
              ] }
            }
          }
        }
    }},
    { $project: {
        fullLoss:   { $multiply: ['$expiredInRange', '$price'] },
        baseLoss:   { $multiply: ['$expiredInRange', '$basePrice'] },
        markupLoss: { $multiply: ['$expiredInRange', '$markup'] }
    }},
    { $group: {
        _id: null,
        totalExpiredFullLoss:   { $sum: '$fullLoss' },
        totalExpiredBaseLoss:   { $sum: '$baseLoss' },
        totalExpiredMarkupLoss: { $sum: '$markupLoss' }
    }}
  ]);

  const r = rows?.[0] || {};
  return {
    totalExpiredFullLoss:   r.totalExpiredFullLoss   || 0,
    totalExpiredBaseLoss:   r.totalExpiredBaseLoss   || 0,
    totalExpiredMarkupLoss: r.totalExpiredMarkupLoss || 0
  };
}

/* ------------------------------------------------------------------ *
 * Product metrics (revenue, cost, SOLD markup)
 * ------------------------------------------------------------------ */
async function productMetrics(s, e, productCategory /* '' => all */) {
  // selling price fallback: lineTotal || (qty * (unitPrice || inv.price))
  const revenueTerm = {
    $ifNull: [
      '$products.lineTotal',
      { $multiply: [
          { $ifNull: ['$products.quantity', 0] },
          { $ifNull: ['$products.unitPrice', { $ifNull: ['$inv.price', 0] }] }
      ] }
    ]
  };

  // base COGS
  const cogsTerm = {
    $multiply: [
      { $ifNull: ['$products.quantity', 0] },
      { $ifNull: ['$inv.basePrice', 0] }
    ]
  };

  // direct markup term (prefer inv.markup; else inv.price - inv.basePrice)
  const markupPerUnit = { $ifNull: ['$inv.markup', { $subtract: [{ $ifNull: ['$inv.price', 0] }, { $ifNull: ['$inv.basePrice', 0] }] }] };
  const directMarkupTerm = {
    $multiply: [
      { $ifNull: ['$products.quantity', 0] },
      markupPerUnit
    ]
  };

  const pipeline = [
    { $match: paymentDateMatch(s, e) },
    { $unwind: '$products' },
    { $lookup: {
        from: 'inventories',
        localField: 'products.name',
        foreignField: 'name',
        as: 'inv'
    }},
    { $unwind: { path: '$inv', preserveNullAndEmptyArrays: true } },
  ];

  if (productCategory) pipeline.push({ $match: { 'inv.category': productCategory } });

  pipeline.push(
    { $group: {
        _id: null,
        revenue:    { $sum: revenueTerm },
        cost:       { $sum: cogsTerm },
        soldMarkup: { $sum: directMarkupTerm }
    }},
    { $project: { _id:0, revenue:1, cost:1, soldMarkup:1 } }
  );

  const agg = await Payment.aggregate(pipeline);
  const revenue    = agg?.[0]?.revenue    || 0;
  const cost       = agg?.[0]?.cost       || 0;
  const soldMarkup = agg?.[0]?.soldMarkup ?? Math.max(revenue - cost, 0);

  return { revenue, cost, soldMarkup };
}

/* ------------------------------------------------------------------ *
 * Service metrics (revenue only; profit == revenue)
 * ------------------------------------------------------------------ */
async function serviceMetrics(s, e, serviceCategoryId /* string | '' */) {
  const pipeline = [
    { $match: paymentDateMatch(s, e) },
    { $unwind: '$services' },
    { $lookup: {
        from: 'services',
        localField: 'services.name',
        foreignField: 'serviceName',
        as: 'svc'
    }},
    { $unwind: { path: '$svc', preserveNullAndEmptyArrays: true } },
  ];

  if (serviceCategoryId && mongoose.Types.ObjectId.isValid(serviceCategoryId)) {
    pipeline.push({ $match: { 'svc.category': new mongoose.Types.ObjectId(serviceCategoryId) } });
  }

  const revenueTerm = {
    $ifNull: [
      '$services.lineTotal',
      { $multiply: [
          { $ifNull: ['$services.quantity', 1] },
          { $ifNull: ['$services.unitPrice', 0] }
      ] }
    ]
  };

  pipeline.push(
    { $group: { _id: null, revenue: { $sum: revenueTerm } } },
    { $project: { _id:0, revenue:1 } }
  );

  const agg = await Payment.aggregate(pipeline);
  const revenue = agg?.[0]?.revenue || 0;
  return { revenue, cost: 0 };
}

/* ------------------------------------------------------------------ *
 * KPIs (mode/category aware) — PROFIT = SOLD MARKUP − EXPIRED FULL LOSS
 * ------------------------------------------------------------------ */
exports.getSalesKPIs = async (req, res) => {
  try {
    const { s, e } = parseDates(req);

    const mode = (req.query.mode || 'products').toLowerCase();
    const productCategory = (req.query.category || '').trim(); // product category string
    const serviceCategoryId = (req.query.serviceCategory || req.query.svcCategory || '').trim();
    const compare = (req.query.compare || '').toLowerCase();

    let totalRevenue = 0;
    let profitBeforeLoss = 0; // sold markup (products) + revenue (services)

    // PRODUCTS
    if (mode === 'products' || mode === 'both') {
      const { revenue, soldMarkup } = await productMetrics(s, e, productCategory);
      totalRevenue     += revenue;
      profitBeforeLoss += soldMarkup;
    }

    // SERVICES
    if (mode === 'services' || mode === 'both') {
      const { revenue } = await serviceMetrics(s, e, serviceCategoryId);
      totalRevenue     += revenue;
      profitBeforeLoss += revenue; // services treated as pure profit (no COGS tracked)
    }

    // Expired loss (products inventory, category-aware)
    const lossNow = await expiredLossBreakdownForCategory(s, e, productCategory || '');

    // Default rule: subtract FULL expired value; change this line to use markup-only if desired
    const lossToSubtract = lossNow.totalExpiredFullLoss;

    const profitAfterLoss = profitBeforeLoss - lossToSubtract;

    const out = {
      totalRevenue,
      // expose under several keys for FE compatibility
      profit:            profitAfterLoss,
      profitAfterLoss:   profitAfterLoss,
      profitBeforeLoss:  profitBeforeLoss,
      netProfit:         profitAfterLoss,
      grossProfit:       profitBeforeLoss,

      // loss breakdown (+ legacy alias)
      totalExpiredFullLoss:   lossNow.totalExpiredFullLoss,
      totalExpiredBaseLoss:   lossNow.totalExpiredBaseLoss,
      totalExpiredMarkupLoss: lossNow.totalExpiredMarkupLoss,
      totalExpiredLoss:       lossNow.totalExpiredFullLoss // legacy alias used by FE
    };

    // ---- previous period comparison ----
    if (compare === 'prev') {
      const durationMs = msBetween(s, e);
      const prevEnd   = new Date(s.getTime() - 1);
      const prevStart = new Date(prevEnd.getTime() - durationMs + 1);

      let prevRevenue = 0;
      let prevProfitBeforeLoss = 0;

      if (mode === 'products' || mode === 'both') {
        const { revenue, soldMarkup } = await productMetrics(prevStart, prevEnd, productCategory);
        prevRevenue            += revenue;
        prevProfitBeforeLoss   += soldMarkup;
      }
      if (mode === 'services' || mode === 'both') {
        const { revenue } = await serviceMetrics(prevStart, prevEnd, serviceCategoryId);
        prevRevenue            += revenue;
        prevProfitBeforeLoss   += revenue;
      }

      const lossPrev = await expiredLossBreakdownForCategory(prevStart, prevEnd, productCategory || '');
      const prevProfitAfterLoss = prevProfitBeforeLoss - lossPrev.totalExpiredFullLoss;

      const revenueChangePercent =
        prevRevenue ? ((totalRevenue - prevRevenue) / prevRevenue) * 100 : 0;

      const profitChangePercent =
        prevProfitAfterLoss ? ((profitAfterLoss - prevProfitAfterLoss) / Math.abs(prevProfitAfterLoss)) * 100 : 0;

      out.comparison = {
        currentRevenue: totalRevenue,
        prevRevenue,
        revenueChangePercent,
        currentProfit: profitAfterLoss,
        prevProfit: prevProfitAfterLoss,
        profitChangePercent
      };
    }

    res.json(out);
  } catch (err) {
    console.error('getSalesKPIs error:', err);
    res.status(500).json({
      totalRevenue: 0,
      profit: 0, profitAfterLoss: 0, profitBeforeLoss: 0,
      totalExpiredFullLoss: 0, totalExpiredBaseLoss: 0, totalExpiredMarkupLoss: 0,
      totalExpiredLoss: 0
    });
  }
};

/* ------------------------------------------------------------------ *
 * Sales by Category (products only) — includes markup & loss
 * ------------------------------------------------------------------ */
exports.getSalesByCategory = async (req, res) => {
  try {
    const { s, e } = parseDates(req);
    const category = (req.query.category || '').trim(); // product category string

    // Current period
    const { revenue, cost, soldMarkup } = await productMetrics(s, e, category);
    const lossNow = await expiredLossBreakdownForCategory(s, e, category);
    const profit = soldMarkup - (lossNow.totalExpiredFullLoss || 0); // rule: markup − full expired

    // Previous period revenue (for growth % or display)
    const durationMs = msBetween(s, e);
    const prevEnd   = new Date(s.getTime() - 1);
    const prevStart = new Date(prevEnd.getTime() - durationMs + 1);
    const { revenue: prevRevenue } = await productMetrics(prevStart, prevEnd, category);

    res.json({
      totalRevenue: revenue,
      totalCOGS: cost,
      totalMarkup: soldMarkup,
      totalExpiredFullLoss:   lossNow.totalExpiredFullLoss,
      totalExpiredBaseLoss:   lossNow.totalExpiredBaseLoss,
      totalExpiredMarkupLoss: lossNow.totalExpiredMarkupLoss,
      totalExpiredLoss:       lossNow.totalExpiredFullLoss, // alias for FE
      profit, // final profit for the card (markup − full expired)
      lastPeriodRevenue: prevRevenue
    });
  } catch (err) {
    console.error('getSalesByCategory error:', err);
    res.status(500).json({
      totalRevenue: 0,
      totalCOGS: 0,
      totalMarkup: 0,
      totalExpiredFullLoss: 0,
      totalExpiredBaseLoss: 0,
      totalExpiredMarkupLoss: 0,
      totalExpiredLoss: 0,
      profit: 0,
      lastPeriodRevenue: 0
    });
  }
};

/* ------------------------------------------------------------------ *
 * Top expired PRODUCTS in range (optional category)
 * ------------------------------------------------------------------ */
exports.getExpiredProducts = async (req, res) => {
  try {
    const { s, e } = parseDates(req);
    const category = (req.query.category || '').trim();

    const pipeline = [
      ...(category ? [{ $match: { category } }] : []),
      { $project: {
          name: 1, price:1, expiredDates:1,
          expiredInRange: {
            $size: {
              $filter: {
                input: { $ifNull: ['$expiredDates', []] },
                as: 'd',
                cond: { $and: [
                  { $gte: ['$$d', s] },
                  { $lte: ['$$d', e] }
                ] }
              }
            }
          },
          lastExpired: {
            $max: {
              $filter: {
                input: { $ifNull: ['$expiredDates', []] },
                as: 'd',
                cond: { $and: [
                  { $gte: ['$$d', s] },
                  { $lte: ['$$d', e] }
                ] }
              }
            }
          }
      }},
      { $match: { expiredInRange: { $gt: 0 } } },
      { $sort: { expiredInRange: -1 } },
      { $limit: 20 },
      { $project: { _id:0, productName:'$name', expiredCount:'expiredInRange', lastExpired:1, price:1 } }
    ];

    const rows = await Inventory.aggregate(pipeline);
    res.json({ items: rows });
  } catch (err) {
    console.error('getExpiredProducts error:', err);
    res.status(500).json({ items: [] });
  }
};
// GET /admin/report/top-profit-items?start=YYYY-MM-DD&end=YYYY-MM-DD&mode=products|services|both&category=&serviceCategory=&limit=
exports.getTopProfitItems = async (req, res) => {
  try {
    const { s, e } = parseDates(req);
    const mode = (req.query.mode || 'both').toLowerCase();
    const productCategory = (req.query.category || '').trim();
    const serviceCategoryId = (req.query.serviceCategory || req.query.svcCategory || '').trim();
    const limit = Math.max(1, Math.min(50, Number(req.query.limit)||5));

    const results = [];

    if (mode === 'products' || mode === 'both') {
      const prod = await Payment.aggregate([
        { $match: paymentDateMatch(s,e) },
        { $unwind: "$products" },
        { $lookup: { from:"inventories", localField:"products.name", foreignField:"name", as:"inv" } },
        { $unwind: { path:"$inv", preserveNullAndEmptyArrays:true } },
        ...(productCategory ? [{ $match: { 'inv.category': productCategory } }] : []),
        { $project: {
            name: "$products.name",
            qty:  { $ifNull:["$products.quantity",0] },
            revenue: { $ifNull:["$products.lineTotal",
              { $multiply:[ { $ifNull:["$products.quantity",0] }, { $ifNull:["$products.unitPrice","$inv.price"] } ] }
            ] },
            markupPerUnit: { $ifNull:["$inv.markup", { $subtract:[ { $ifNull:["$inv.price",0] }, { $ifNull:["$inv.basePrice",0] } ] }] }
        }},
        { $project: { name:1, units:"$qty", profit: { $multiply:["$qty","$markupPerUnit"] } } },
        { $group: { _id:"$name", name:{ $first:"$name" }, units:{ $sum:"$units" }, profit:{ $sum:"$profit" } } }
      ]);
      results.push(...prod.map(x=>({ name:x.name, units:x.units, profit:x.profit, type:'product' })));
    }

    if (mode === 'services' || mode === 'both') {
      const svcPipe = [
        { $match: paymentDateMatch(s,e) },
        { $unwind: "$services" },
        { $lookup: { from:"services", localField:"services.name", foreignField:"serviceName", as:"svc" } },
        { $unwind: { path:"$svc", preserveNullAndEmptyArrays:true } },
      ];
      if (serviceCategoryId && mongoose.Types.ObjectId.isValid(serviceCategoryId)) {
        svcPipe.push({ $match: { 'svc.category': new mongoose.Types.ObjectId(serviceCategoryId) } });
      }
      svcPipe.push(
        { $project: {
            name: "$services.name",
            units: { $cond:[ { $ifNull:["$services.quantity",false] }, "$services.quantity", 1 ] },
            revenue: { $ifNull:["$services.lineTotal",
              { $multiply:[ { $ifNull:["$services.quantity",1] }, { $ifNull:["$services.unitPrice",0] } ] }
            ] }
        }},
        { $group: { _id:"$name", name:{ $first:"$name" }, units:{ $sum:"$units" }, revenue:{ $sum:"$revenue" } } },
        { $project: { _id:0, name:1, units:1, profit:"$revenue" } }
      );
      const svc = await Payment.aggregate(svcPipe);
      results.push(...svc.map(x=>({ name:x.name, units:x.units, profit:x.profit, type:'service' })));
    }

    const out = results.sort((a,b)=>b.profit-a.profit).slice(0, limit);
    res.json({ items: out });
  } catch (err) {
    console.error('getTopProfitItems error:', err);
    res.status(500).json({ items: [] });
  }
};

// GET /admin/report/expiring-soon?days=30[&category=]
exports.getExpiringSoon = async (req, res) => {
  try {
    const days = Math.max(1, Math.min(365, Number(req.query.days)||30));
    const category = (req.query.category || '').trim();

    const now = new Date(); now.setHours(0,0,0,0);
    const until = new Date(now); until.setDate(until.getDate()+days); until.setHours(23,59,59,999);

    const pipeline = [
      ...(category ? [{ $match: { category } }] : []),
      { $project: {
          name:1, price:{ $ifNull:["$price",0] }, basePrice:{ $ifNull:["$basePrice",0] },
          expiredDates:{ $ifNull:["$expiredDates",[]] }
      }},
      { $project: {
          name:1, price:1, basePrice:1,
          count: { $size: { $filter: { input:"$expiredDates", as:"d",
            cond:{ $and:[ { $gte:["$$d", now] }, { $lte:["$$d", until] } ] } } } }
      }},
      { $match: { count: { $gt: 0 } } },
      { $project: {
          _id:0, productName:"$name", count:1,
          valueFull:{ $multiply:["$count","$price"] },
          valueBase:{ $multiply:["$count","$basePrice"] }
      }},
      { $sort: { count:-1, valueFull:-1 } },
      { $limit: 50 }
    ];

    const rows = await Inventory.aggregate(pipeline);
    res.json({ items: rows, from: now, to: until });
  } catch (err) {
    console.error('getExpiringSoon error:', err);
    res.status(500).json({ items: [] });
  }
};
// GET /admin/report/slow-movers?mode=products|services&start=YYYY-MM-DD&end=YYYY-MM-DD[&category=][&serviceCategory=]
exports.getSlowMovers = async (req, res) => {
  try {
    const { s, e } = parseDates(req);
    const mode = (req.query.mode || 'products').toLowerCase();

    // helper: compute days between end-of-range and last sold
    const daysSince = (d) => (d ? Math.max(0, Math.round((e - d) / 86400000)) : null);

    if (mode === 'products') {
      const category = (req.query.category || '').trim();

      // 1) list all product names in scope (by category if provided)
      const invFilter = category ? { category } : {};
      const invDocs = await Inventory.find(invFilter, { name: 1, _id: 0 }).lean();
      const allNames = invDocs.map(d => d.name).filter(Boolean);
      if (allNames.length === 0) return res.json({ items: [] });

      // 2) names that HAVE sales within [s,e]
      const soldInRange = await Payment.aggregate([
        { $match: paymentDateMatch(s, e) },
        { $unwind: '$products' },
        { $match: { 'products.name': { $in: allNames } } },
        { $group: { _id: '$products.name' } }
      ]);
      const soldSet = new Set(soldInRange.map(x => x._id));

      // 3) last sold date (up to end of range) for each name
      const lastAgg = await Payment.aggregate([
        { $match: { $or: [ { paidAt: { $lte: e } }, { createdAt: { $lte: e } } ] } },
        { $unwind: '$products' },
        { $match: { 'products.name': { $in: allNames } } },
        { $project: { name: '$products.name', when: { $ifNull: ['$paidAt', '$createdAt'] } } },
        { $group: { _id: '$name', lastSoldAt: { $max: '$when' } } }
      ]);
      const lastMap = new Map(lastAgg.map(r => [r._id, r.lastSoldAt]));

      // 4) slow movers = in inventory but NOT sold in range
      const slow = allNames
        .filter(n => !soldSet.has(n))
        .map(n => {
          const last = lastMap.get(n) || null;
          return { name: n, productName: n, lastSoldAt: last, daysSince: daysSince(last) };
        });

      // sort: Never first, then oldest lastSold
      slow.sort((a, b) => {
        if (!a.lastSoldAt && b.lastSoldAt) return -1;
        if (a.lastSoldAt && !b.lastSoldAt) return 1;
        if (!a.lastSoldAt && !b.lastSoldAt) return a.name.localeCompare(b.name);
        return a.lastSoldAt - b.lastSoldAt;
      });

      return res.json({ items: slow });
    }

    if (mode === 'services') {
      const serviceCategoryId = (req.query.serviceCategory || req.query.category || '').trim();
      const svcFilter = {};
      if (serviceCategoryId && mongoose.Types.ObjectId.isValid(serviceCategoryId)) {
        svcFilter.category = new mongoose.Types.ObjectId(serviceCategoryId);
      }

      // 1) all service names in scope
      const svcDocs = await Service.find(svcFilter, { serviceName: 1, _id: 0 }).lean();
      const allNames = svcDocs.map(d => d.serviceName).filter(Boolean);
      if (allNames.length === 0) return res.json({ items: [] });

      // 2) names sold within [s,e]
      const soldInRange = await Payment.aggregate([
        { $match: paymentDateMatch(s, e) },
        { $unwind: '$services' },
        { $match: { 'services.name': { $in: allNames } } },
        { $group: { _id: '$services.name' } }
      ]);
      const soldSet = new Set(soldInRange.map(x => x._id));

      // 3) last sold date (up to end of range)
      const lastAgg = await Payment.aggregate([
        { $match: { $or: [ { paidAt: { $lte: e } }, { createdAt: { $lte: e } } ] } },
        { $unwind: '$services' },
        { $match: { 'services.name': { $in: allNames } } },
        { $project: { name: '$services.name', when: { $ifNull: ['$paidAt', '$createdAt'] } } },
        { $group: { _id: '$name', lastSoldAt: { $max: '$when' } } }
      ]);
      const lastMap = new Map(lastAgg.map(r => [r._id, r.lastSoldAt]));

      // 4) slow movers = defined services not sold in range
      const slow = allNames
        .filter(n => !soldSet.has(n))
        .map(n => {
          const last = lastMap.get(n) || null;
          return { name: n, serviceName: n, lastSoldAt: last, daysSince: daysSince(last) };
        });

      slow.sort((a, b) => {
        if (!a.lastSoldAt && b.lastSoldAt) return -1;
        if (a.lastSoldAt && !b.lastSoldAt) return 1;
        if (!a.lastSoldAt && !b.lastSoldAt) return a.name.localeCompare(b.name);
        return a.lastSoldAt - b.lastSoldAt;
      });

      return res.json({ items: slow });
    }

    return res.status(400).json({ items: [], message: 'Invalid mode' });
  } catch (err) {
    console.error('getSlowMovers error:', err);
    return res.status(500).json({ items: [] });
  }
};// --- UPDATED: supports Products AND Services export with the requested layout/titles ---
// --- UPDATED: supports Products AND Services export; removed "Category Sales" text,
// color-coded TOTAL rows, and renamed Services Slow Movers column to "Last Service".
// --- UPDATED: Services export shows ALL categories (even with 0 sales),
// removes "Uncategorized" by excluding services with no valid category,
// keeps colored TOTAL rows, and "Last Service" in Slow Movers.
// --- UPDATED: supports Products, Services, and BOTH (combined) Excel export ---
exports.exportExcel = async (req, res) => {
  try {
    const { s, e } = parseDates(req);

    const modeRaw = (req.query.mode || 'products').toLowerCase();
    const mode = ['products','services','both','all'].includes(modeRaw) ? (modeRaw === 'all' ? 'both' : modeRaw) : 'products';

    const productCategory = (req.query.category || '').trim(); // product category (string)
    const serviceCategoryId = (req.query.serviceCategory || req.query.svcCategory || '').trim(); // ObjectId string

    // styles/helpers
    const fmtDateLong = d => new Date(d).toLocaleDateString('en-US',{month:'long',day:'numeric',year:'numeric'});
    const sanitize = s => String(s||'').replace(/[^A-Za-z0-9_]/g,'_').replace(/^(\d)/,'_$1').slice(0,30);

    const wb = new ExcelJS.Workbook();
    wb.creator = 'Sales Report';
    wb.created = new Date();

    const fmtPesoPosNeg = '[$-en-PH]₱#,##0;[Red]-[$-en-PH]₱#,##0';
    const fmtIntPosNeg  = '0;[Red]-0';
    const COLORS = { headerBg: 'FF1F2937', headerFg: 'FFFFFFFF', grid: 'FFCBD5E1' };
    const TOTAL_FILL = 'FFEFF6FF';

    const styleHeaderRow = (ws, row, fromCol, toCol) => {
      for (let c = fromCol; c <= toCol; c++) {
        const cell = ws.getCell(row, c);
        cell.fill = { type:'pattern', pattern:'solid', fgColor:{ argb: COLORS.headerBg } };
        cell.font = { bold:true, color:{ argb: COLORS.headerFg } };
      }
    };
    const setBorders = (ws, r1, c1, r2, c2) => {
      for (let r = r1; r <= r2; r++) {
        for (let c = c1; c <= c2; c++) {
          ws.getCell(r, c).border = {
            top:    { style:'thin', color:{ argb: COLORS.grid } },
            left:   { style:'thin', color:{ argb: COLORS.grid } },
            bottom: { style:'thin', color:{ argb: COLORS.grid } },
            right:  { style:'thin', color:{ argb: COLORS.grid } },
          };
        }
      }
    };

    // ========== Shared computations we’ll reuse ==========
    // PRODUCTS side (category-scoped when productCategory provided)
    const buildProductsData = async () => {
      const invFilter = productCategory ? { category: productCategory } : {};
      const invDocs = await Inventory.find(
        invFilter,
        { name:1, category:1, basePrice:1, price:1, markup:1, expiredDates:1, _id:0 }
      ).lean();

      const allInvNames   = invDocs.map(d => d.name).filter(Boolean);
      const invNameToCat  = new Map(invDocs.map(d => [d.name, d.category || 'Uncategorized']));
      const invNameToMeta = new Map(invDocs.map(d => [d.name, {
        price: d.price || 0,
        basePrice: d.basePrice || 0,
        markupUnit: (d.markup != null) ? d.markup : Math.max((d.price||0) - (d.basePrice||0), 0)
      }]));
      const invCategories = Array.from(new Set(invDocs.map(d => d.category || 'Uncategorized'))).sort((a,b)=>a.localeCompare(b));

      // Category-level sales
      const salesByCat = await Payment.aggregate([
        { $match: paymentDateMatch(s, e) },
        { $unwind: '$products' },
        { $match: { 'products.name': { $in: allInvNames } } },
        { $lookup: { from:'inventories', localField:'products.name', foreignField:'name', as:'inv' } },
        { $unwind: { path:'$inv', preserveNullAndEmptyArrays:true } },
        { $project: {
            category: { $ifNull: ['$inv.category', 'Uncategorized'] },
            qty: { $ifNull: ['$products.quantity', 0] },
            basePrice: { $ifNull: ['$inv.basePrice', 0] },
            markupPerUnit: {
              $ifNull: [
                '$inv.markup',
                { $subtract: [ { $ifNull: ['$inv.price', 0] }, { $ifNull: ['$inv.basePrice', 0] } ] }
              ]
            }
        }} ,
        { $project: {
            category: 1,
            unitsSold: '$qty',
            baseCost:  { $multiply: ['$qty', '$basePrice'] },
            soldMarkup:{ $multiply: ['$qty', '$markupPerUnit'] }
        }},
        { $group: {
            _id: '$category',
            unitsSold: { $sum: '$unitsSold' },
            baseCost:  { $sum: '$baseCost' },
            soldMarkup:{ $sum: '$soldMarkup' }
        }}
      ]);
      const salesMap = new Map(
        salesByCat.map(r => [r._id || 'Uncategorized', {
          unitsSold: r.unitsSold || 0,
          baseCost:  r.baseCost  || 0,
          soldMarkup:r.soldMarkup|| 0
        }])
      );

      // Expired by category
      const expiredScopeMatch = productCategory ? [{ $match: { category: productCategory } }] : [];
      const expiredByCat = await Inventory.aggregate([
        ...expiredScopeMatch,
        { $project: {
            category: { $ifNull: ['$category', 'Uncategorized'] },
            price: { $ifNull: ['$price', 0] },
            basePrice: { $ifNull: ['$basePrice', 0] },
            markupUnit: {
              $ifNull: [
                '$markup',
                { $subtract: [ { $ifNull: ['$price',0] }, { $ifNull: ['$basePrice',0] } ] }
              ]
            },
            expiredDates: { $ifNull: ['$expiredDates', []] }
        }},
        { $project: {
            category: 1,
            expiredInRange: {
              $filter: { input:'$expiredDates', as:'d',
                cond:{ $and:[ { $gte:['$$d', s] }, { $lte:['$$d', e] } ] } }
            },
            price: 1, basePrice: 1, markupUnit: 1
        }},
        { $project: {
            category: 1,
            expiredCount: { $size: '$expiredInRange' },
            fullLoss:   { $multiply: [ { $size: '$expiredInRange' }, '$price' ] },
            baseLoss:   { $multiply: [ { $size: '$expiredInRange' }, '$basePrice' ] },
            markupLoss: { $multiply: [ { $size: '$expiredInRange' }, '$markupUnit' ] }
        }},
        { $group: {
            _id: '$category',
            expiredCount: { $sum: '$expiredCount' },
            fullLoss:     { $sum: '$fullLoss' },
            baseLoss:     { $sum: '$baseLoss' },
            markupLoss:   { $sum: '$markupLoss' }
        }}
      ]);
      const lossMap = new Map(
        expiredByCat.map(r => [r._id || 'Uncategorized', {
          expiredCount: r.expiredCount || 0,
          fullLoss:     r.fullLoss     || 0,
          baseLoss:     r.baseLoss     || 0,
          markupLoss:   r.markupLoss   || 0
        }])
      );

      // Category P&L rows + totals
      const catPLRows = invCategories.map(cat => {
        const sRow = salesMap.get(cat) || { unitsSold:0, baseCost:0, soldMarkup:0 };
        const lRow = lossMap.get(cat)  || { fullLoss:0 };
        const sales  = (sRow.baseCost || 0) + (sRow.soldMarkup || 0);
        const profit = (sRow.soldMarkup || 0) - (lRow.fullLoss || 0);
        return {
          category: cat,
          unitsSold: Math.round(sRow.unitsSold || 0),
          sales:     Math.round(sales || 0),
          loss:      Math.round(lRow.fullLoss || 0),
          profit:    Math.round(profit || 0)
        };
      });
      const totals = catPLRows.reduce((t,r)=>({
        unitsSold: t.unitsSold + r.unitsSold,
        sales:     t.sales     + r.sales,
        loss:      t.loss      + r.loss,
        profit:    t.profit    + r.profit
      }), { unitsSold:0, sales:0, loss:0, profit:0 });

      // Expired detail (for sheet)
      const expiredDetail = await Inventory.aggregate([
        ...expiredScopeMatch,
        { $project: {
            name: 1,
            category: { $ifNull: ['$category', 'Uncategorized'] },
            price: { $ifNull: ['$price', 0] },
            basePrice: { $ifNull: ['$basePrice', 0] },
            markupUnit: {
              $ifNull: [
                '$markup',
                { $subtract: [ { $ifNull: ['$price',0] }, { $ifNull: ['$basePrice',0] } ] }
              ]
            },
            expiredDates: { $ifNull: ['$expiredDates', []] }
        }},
        { $project: {
            name: 1, category: 1,
            expiredInRange: {
              $filter: { input:'$expiredDates', as:'d',
                cond:{ $and:[ { $gte:['$$d', s] }, { $lte:['$$d', e] } ] } }
            },
            price: 1, basePrice: 1, markupUnit: 1
        }},
        { $project: {
            name: 1, category: 1,
            expiredCount: { $size: '$expiredInRange' },
            lastExpired:  { $max:  '$expiredInRange' },
            fullLoss:   { $multiply: [ { $size: '$expiredInRange' }, '$price' ] },
            baseLoss:   { $multiply: [ { $size: '$expiredInRange' }, '$basePrice' ] },
            markupLoss: { $multiply: [ { $size: '$expiredInRange' }, '$markupUnit' ] }
        }},
        { $match: { expiredCount: { $gt: 0 } } }
      ]);
      const expiredLossByProduct = new Map(expiredDetail.map(r => [r.name, r.fullLoss || 0]));

      // Sales by product (for per-product)
      const salesByProductAgg = await Payment.aggregate([
        { $match: paymentDateMatch(s, e) },
        { $unwind: '$products' },
        { $match: { 'products.name': { $in: allInvNames } } },
        { $group: {
            _id: '$products.name',
            unitsSold: { $sum: { $ifNull: ['$products.quantity', 0] } },
            revenue:   { $sum: {
              $ifNull: [
                '$products.lineTotal',
                { $multiply: [
                    { $ifNull: ['$products.quantity', 0] },
                    { $ifNull: ['$products.unitPrice', 0] }
                ] }
              ]
            } }
        } }
      ]);
      const salesByProduct = new Map(
        salesByProductAgg.map(r => [r._id, { unitsSold: r.unitsSold || 0, revenue: r.revenue || 0 }])
      );

      // Per-product rows grouped by category
      const perProductByCat = new Map();
      for (const d of invDocs) {
        const name = d.name;
        const cat  = d.category || 'Uncategorized';
        const sRow = salesByProduct.get(name) || { unitsSold: 0, revenue: 0 };
        const meta = invNameToMeta.get(name) || { price:0, markupUnit:0 };
        const units = sRow.unitsSold || 0;
        const unitPrice  = meta.price || 0;
        const soldMarkup = Math.round(units * (meta.markupUnit || 0));
        const revenue    = Math.round(sRow.revenue || 0);
        const lossFull   = Math.round(expiredLossByProduct.get(name) || 0);
        const profit     = Math.round(soldMarkup - lossFull);

        const row = [ cat, name, units, unitPrice, soldMarkup, revenue, profit ];
        if (!perProductByCat.has(cat)) perProductByCat.set(cat, []);
        perProductByCat.get(cat).push(row);
      }
      for (const [cat, rows] of perProductByCat.entries()) {
        rows.sort((a,b) => (b[6] - a[6]) || a[1].localeCompare(b[1]));
      }

      // Slow movers (products)
      const soldInRange = await Payment.aggregate([
        { $match: paymentDateMatch(s, e) },
        { $unwind: '$products' },
        { $match: { 'products.name': { $in: allInvNames } } },
        { $group: { _id: '$products.name' } }
      ]);
      const soldSet = new Set(soldInRange.map(x => x._id));

      const lastAgg = await Payment.aggregate([
        { $match: { $or: [ { paidAt: { $lte: e } }, { createdAt: { $lte: e } } ] } },
        { $unwind: '$products' },
        { $match: { 'products.name': { $in: allInvNames } } },
        { $project: { name: '$products.name', when: { $ifNull: ['$paidAt', '$createdAt'] } } },
        { $group: { _id: '$name', lastSoldAt: { $max: '$when' } } }
      ]);
      const lastMap = new Map(lastAgg.map(r => [r._id, r.lastSoldAt]));

      const slowProducts = allInvNames
        .filter(n => !soldSet.has(n))
        .map(n => ({
          name: n,
          category: invNameToCat.get(n) || 'Uncategorized',
          lastSoldAt: lastMap.get(n) || null
        }))
        .sort((a, b) => {
          if (!a.lastSoldAt && b.lastSoldAt) return -1;
          if (a.lastSoldAt && !b.lastSoldAt) return 1;
          if (!a.lastSoldAt && !b.lastSoldAt) return a.name.localeCompare(b.name);
          return a.lastSoldAt - b.lastSoldAt;
        });

      return {
        invCategories, catPLRows, totals,
        expiredByCat, expiredDetail, perProductByCat,
        slowProducts
      };
    };

    // SERVICES side (All categories regardless of date; exclude uncategorized)
    const buildServicesData = async () => {
      const svcCatCol = mongoose.connection.collection('servicecategories');

      // canonical category list (no Uncategorized)
      let svcCategoryDocs = [];
      if (serviceCategoryId && mongoose.Types.ObjectId.isValid(serviceCategoryId)) {
        const doc = await svcCatCol.findOne(
          { _id: new mongoose.Types.ObjectId(serviceCategoryId) },
          { projection: { name: 1 } }
        );
        if (doc) svcCategoryDocs = [doc];
      } else {
        svcCategoryDocs = await svcCatCol.find({}, { projection: { name: 1 } }).toArray();
      }
      const svcCategories = (svcCategoryDocs || [])
        .map(d => String(d.name || '').trim())
        .filter(Boolean)
        .sort((a,b)=>a.localeCompare(b));

      // category-level sales
      const svcSalesByCat = await Payment.aggregate([
        { $match: paymentDateMatch(s, e) },
        { $unwind: '$services' },
        { $lookup: { from: 'services', localField: 'services.name', foreignField: 'serviceName', as: 'svc' } },
        { $unwind: { path: '$svc', preserveNullAndEmptyArrays: false } },
        { $lookup: { from: 'servicecategories', localField: 'svc.category', foreignField: '_id', as: 'sc' } },
        { $unwind: { path: '$sc', preserveNullAndEmptyArrays: false } },
        ...(serviceCategoryId && mongoose.Types.ObjectId.isValid(serviceCategoryId)
          ? [{ $match: { 'sc._id': new mongoose.Types.ObjectId(serviceCategoryId) } }]
          : [{ $match: { 'sc.name': { $in: svcCategories } } }]),
        { $project: {
            catName: '$sc.name',
            count:   { $cond: [{ $ifNull: ['$services.quantity', false] }, '$services.quantity', 1] },
            revenue: { $ifNull: [
              '$services.lineTotal',
              { $multiply: [ { $ifNull: ['$services.quantity', 1] }, { $ifNull: ['$services.unitPrice', 0] } ] }
            ] }
        }},
        { $group: { _id: '$catName', serviceCounts: { $sum: '$count' }, sales: { $sum: '$revenue' } } }
      ]);
      const svcSalesMap = new Map(
        (svcSalesByCat || []).map(r => [r._id, { serviceCounts: r.serviceCounts || 0, sales: r.sales || 0 }])
      );

      // per-service rows by category
      const perServiceAgg = await Payment.aggregate([
        { $match: paymentDateMatch(s, e) },
        { $unwind: '$services' },
        { $lookup: { from: 'services', localField: 'services.name', foreignField: 'serviceName', as: 'svc' } },
        { $unwind: { path: '$svc', preserveNullAndEmptyArrays: false } },
        { $lookup: { from: 'servicecategories', localField: 'svc.category', foreignField: '_id', as: 'sc' } },
        { $unwind: { path: '$sc', preserveNullAndEmptyArrays: false } },
        ...(serviceCategoryId && mongoose.Types.ObjectId.isValid(serviceCategoryId)
          ? [{ $match: { 'sc._id': new mongoose.Types.ObjectId(serviceCategoryId) } }]
          : [{ $match: { 'sc.name': { $in: svcCategories } } }]),
        { $project: {
            catName: '$sc.name',
            svcName: '$services.name',
            count:   { $cond: [{ $ifNull: ['$services.quantity', false] }, '$services.quantity', 1] },
            revenue: { $ifNull: [
              '$services.lineTotal',
              { $multiply: [ { $ifNull: ['$services.quantity', 1] }, { $ifNull: ['$services.unitPrice', 0] } ] }
            ] }
        }},
        { $group: {
            _id: { cat: '$catName', svc: '$svcName' },
            catName: { $first: '$catName' },
            svcName: { $first: '$svcName' },
            serviceCounts: { $sum: '$count' },
            sales: { $sum: '$revenue' }
        }}
      ]);

      const perServiceByCat = new Map();
      for (const r of (perServiceAgg || [])) {
        const row = [ r.catName, r.svcName || '—', Math.round(r.serviceCounts || 0), Math.round(r.sales || 0) ];
        if (!perServiceByCat.has(r.catName)) perServiceByCat.set(r.catName, []);
        perServiceByCat.get(r.catName).push(row);
      }
      for (const [cat, rows] of perServiceByCat.entries()) {
        rows.sort((a,b) => (b[3] - a[3]) || a[1].localeCompare(b[1]));
      }

      // slow movers (services) with "Last Service"
      const svcNamesScopeAgg = await Service.aggregate([
        ...(serviceCategoryId && mongoose.Types.ObjectId.isValid(serviceCategoryId)
          ? [{ $match: { category: new mongoose.Types.ObjectId(serviceCategoryId) } }]
          : []),
        { $lookup: { from: 'servicecategories', localField: 'category', foreignField: '_id', as: 'sc' } },
        { $unwind: { path: '$sc', preserveNullAndEmptyArrays: false } },
        { $project: { serviceName: '$serviceName', catName: '$sc.name' } },
        ...(svcCategories.length ? [{ $match: { catName: { $in: svcCategories } } }] : [])
      ]);
      const allSvcNames = svcNamesScopeAgg.map(x => x.serviceName).filter(Boolean);
      const nameToCat = new Map(svcNamesScopeAgg.map(x => [x.serviceName, x.catName]));

      let slowRows = [];
      if (allSvcNames.length) {
        const soldInRange = await Payment.aggregate([
          { $match: paymentDateMatch(s, e) },
          { $unwind: '$services' },
          { $match: { 'services.name': { $in: allSvcNames } } },
          { $group: { _id: '$services.name' } }
        ]);
        const soldSet = new Set(soldInRange.map(x => x._id));

        const lastAgg = await Payment.aggregate([
          { $match: { $or: [ { paidAt: { $lte: e } }, { createdAt: { $lte: e } } ] } },
          { $unwind: '$services' },
          { $match: { 'services.name': { $in: allSvcNames } } },
          { $project: { name: '$services.name', when: { $ifNull: ['$paidAt', '$createdAt'] } } },
          { $group: { _id: '$name', lastSoldAt: { $max: '$when' } } }
        ]);
        const lastMap = new Map(lastAgg.map(r => [r._id, r.lastSoldAt]));

        slowRows = allSvcNames
          .filter(n => !soldSet.has(n))
          .map(n => [ n, nameToCat.get(n), lastMap.get(n) ? new Date(lastMap.get(n)) : 'Never' ])
          .sort((a,b) => {
            const aHas = a[2] instanceof Date, bHas = b[2] instanceof Date;
            if (!aHas && bHas) return -1;
            if (aHas && !bHas) return 1;
            if (!aHas && !bHas) return a[0].localeCompare(b[0]);
            return a[2] - b[2];
          });
      }

      // totals across all categories (for Overall sheet)
      const totals = svcCategories.reduce((t, cat) => {
        const v = svcSalesMap.get(cat) || { serviceCounts:0, sales:0 };
        t.count += v.serviceCounts || 0;
        t.sales += v.sales || 0;
        return t;
      }, { count:0, sales:0 });

      return { svcCategories, svcSalesMap, perServiceByCat, slowRows, totals };
    };

    // ===========================
    // Branch: SERVICES-ONLY
    // ===========================
    if (mode === 'services') {
      const { svcCategories, svcSalesMap, perServiceByCat, slowRows, totals } = await buildServicesData();

      const ws = wb.addWorksheet('Services', { views: [{ state:'frozen', ySplit: 3 }] });
      ws.mergeCells('A1:D1');
      const titleTag = (serviceCategoryId && mongoose.Types.ObjectId.isValid(serviceCategoryId))
        ? 'Services — Selected Category'
        : 'Services — All Categories';
      ws.getCell('A1').value = `${titleTag} • ${fmtDateLong(s)} → ${fmtDateLong(e)}`;
      ws.getCell('A1').font = { bold:true, size:14 };
      ws.getCell('A1').alignment = { horizontal:'center' };

      const catRows = svcCategories.map(cat => {
        const v = svcSalesMap.get(cat) || { serviceCounts: 0, sales: 0 };
        return [cat, Math.round(v.serviceCounts || 0), Math.round(v.sales || 0)];
      });

      ws.addTable({
        name: 'SvcCategorySales',
        ref: 'A3',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [ { name: 'Category' }, { name: 'Service Counts' }, { name: 'Sales (PHP)' } ],
        rows: catRows
      });
      styleHeaderRow(ws, 3, 1, 3);
      setBorders(ws, 3, 1, Math.max(3, 3 + catRows.length), 3);
      [24,18,18].forEach((w,i)=> ws.getColumn(i+1).width = w);
      ws.getColumn(2).numFmt = fmtIntPosNeg;
      ws.getColumn(3).numFmt = fmtPesoPosNeg;

      ws.addRow([]);
      const totalRow = ws.addRow(['TOTAL', totals.count, totals.sales]);
      totalRow.font = { bold: true };
      totalRow.getCell(2).numFmt = fmtIntPosNeg;
      totalRow.getCell(3).numFmt = fmtPesoPosNeg;
      for (let c = 1; c <= 3; c++) {
        const cell = totalRow.getCell(c);
        cell.border = {
          top:    { style:'thin', color:{ argb: COLORS.grid } },
          bottom: { style:'thin', color:{ argb: COLORS.grid } },
          left:   { style:'thin', color:{ argb: COLORS.grid } },
          right:  { style:'thin', color:{ argb: COLORS.grid } },
        };
        cell.fill = { type:'pattern', pattern:'solid', fgColor:{ argb: TOTAL_FILL } };
      }

      ws.addRow([]);
      ws.addRow(['Per-Service by Category']).font = { bold:true };
      ws.addRow([]);

      let blockCount = 0;
      let currentRow = ws.lastRow.number + 1;
      for (const cat of svcCategories) {
        const rows = perServiceByCat.get(cat) || [];
        if (!rows.length) continue;
        if (blockCount > 0) { ws.addRow([]); currentRow = ws.lastRow.number + 1; }
        blockCount++;

        const headerRowIdx = currentRow;
        ws.addTable({
          name: `PerService_${sanitize(cat)}`,
          ref: `A${headerRowIdx}`,
          headerRow: true,
          style: { theme: 'TableStyleLight15', showRowStripes: true },
          columns: [
            { name: 'Category' }, { name: 'Service' },
            { name: 'Service Counts' }, { name: 'Total Sales (PHP)' }
          ],
          rows
        });
        const dataEnd = headerRowIdx + rows.length;
        styleHeaderRow(ws, headerRowIdx, 1, 4);
        setBorders(ws, headerRowIdx, 1, Math.max(headerRowIdx, dataEnd), 4);
        ws.getColumn(3).numFmt = fmtIntPosNeg;
        ws.getColumn(4).numFmt = fmtPesoPosNeg;
        [22,28,16,18].forEach((w,i)=> { if (!ws.getColumn(i+1).width || ws.getColumn(i+1).width < w) ws.getColumn(i+1).width = w; });

        currentRow = dataEnd + 2;
      }

      // Slow movers (services)
      const wsSlow = wb.addWorksheet('Slow Movers (Services)', { views: [{ state:'frozen', ySplit: 1 }] });
      wsSlow.addTable({
        name: 'SlowServices',
        ref: 'A1',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [ { name: 'Service' }, { name: 'Category' }, { name: 'Last Service' } ],
        rows: (slowRows || [])
      });
      styleHeaderRow(wsSlow, 1, 1, 3);
      setBorders(wsSlow, 1, 1, Math.max(1, 1 + (slowRows || []).length), 3);
      wsSlow.getColumn(3).numFmt = 'yyyy-mm-dd';
      [28,22,20].forEach((w,i)=> { if (!wsSlow.getColumn(i+1).width || wsSlow.getColumn(i+1).width < w) wsSlow.getColumn(i+1).width = w; });

      const tag = (serviceCategoryId && mongoose.Types.ObjectId.isValid(serviceCategoryId)) ? '_SelectedSvcCategory' : '_AllSvcCategories';
      const fileName = `SalesReport_Services${tag}_${new Date().toISOString().slice(0,10)}.xlsx`;
      res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      await wb.xlsx.write(res); res.end();
      return;
    }

    // ===========================
    // Branch: PRODUCTS-ONLY
    // ===========================
    if (mode === 'products') {
      const {
        invCategories, catPLRows, totals,
        expiredByCat, expiredDetail, perProductByCat,
        slowProducts
      } = await buildProductsData();

      // Sheet 1: Category P&L + per-product
      const wsPL = wb.addWorksheet('Category P&L', { views: [{ state:'frozen', ySplit: 3 }] });
      wsPL.mergeCells('A1:E1');
      const titleTagP = productCategory ? `Products — Category: ${productCategory}` : 'Products — All Categories';
      wsPL.getCell('A1').value = `${titleTagP} • ${fmtDateLong(s)} → ${fmtDateLong(e)}`;
      wsPL.getCell('A1').font = { bold:true, size:14 };
      wsPL.getCell('A1').alignment = { horizontal:'center' };

      wsPL.addTable({
        name: 'CategoryPL',
        ref: 'A3',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [
          { name: 'Category' },
          { name: 'Units Sold' },
          { name: 'Sales (PHP)' },
          { name: 'Loss (PHP)' },
          { name: 'Profit (PHP)' }
        ],
        rows: catPLRows.map(r => [ r.category, r.unitsSold, r.sales, r.loss, r.profit ])
      });
      [24,14,18,18,18].forEach((w,i)=> wsPL.getColumn(i+1).width = w);
      wsPL.getColumn(2).numFmt = fmtIntPosNeg;
      [3,4,5].forEach(c => wsPL.getColumn(c).numFmt = fmtPesoPosNeg);
      styleHeaderRow(wsPL, 3, 1, 5);
      const catDataEnd = 3 + catPLRows.length;
      setBorders(wsPL, 3, 1, Math.max(3, catDataEnd), 5);

      wsPL.addRow([]);
      const totalRowPL = wsPL.addRow(['TOTAL', totals.unitsSold, totals.sales, totals.loss, totals.profit]);
      totalRowPL.font = { bold: true };
      totalRowPL.getCell(2).numFmt = fmtIntPosNeg;
      ['C','D','E'].forEach(c => totalRowPL.getCell(c).numFmt = fmtPesoPosNeg);
      for (let c = 1; c <= 5; c++) {
        const cell = totalRowPL.getCell(c);
        cell.border = {
          top:    { style:'thin', color:{ argb: COLORS.grid } },
          bottom: { style:'thin', color:{ argb: COLORS.grid } },
          left:   { style:'thin', color:{ argb: COLORS.grid } },
          right:  { style:'thin', color:{ argb: COLORS.grid } },
        };
        cell.fill = { type:'pattern', pattern:'solid', fgColor:{ argb: TOTAL_FILL } };
      }

      wsPL.addRow([]);
      wsPL.addRow(['Per-Product P&L by Category']).font = { bold:true };
      wsPL.addRow([]);

      let blockCountProd = 0;
      let currentRowProd = wsPL.lastRow.number + 1;
      for (const cat of invCategories) {
        const rows = (perProductByCat.get(cat) || []);
        if (!rows.length) continue;
        if (blockCountProd > 0) { wsPL.addRow([]); currentRowProd = wsPL.lastRow.number + 1; }
        blockCountProd++;

        const headerRowIdx = currentRowProd;
        wsPL.addTable({
          name: `ProductPL_${sanitize(cat)}`,
          ref: `A${headerRowIdx}`,
          headerRow: true,
          style: { theme: 'TableStyleLight15', showRowStripes: true },
          columns: [
            { name: 'Category' },
            { name: 'Product' },
            { name: 'Units Sold' },
            { name: 'Price (PHP)' },
            { name: 'Markup (PHP)' },
            { name: 'Total Sales (PHP)' },
            { name: 'Profit (PHP)' }
          ],
          rows
        });
        const dataEnd   = headerRowIdx + rows.length;
        styleHeaderRow(wsPL, headerRowIdx, 1, 7);
        setBorders(wsPL, headerRowIdx, 1, Math.max(headerRowIdx, dataEnd), 7);
        for (let r = headerRowIdx + 1; r <= dataEnd; r++) {
          wsPL.getCell(r, 3).numFmt = fmtIntPosNeg;
          [4,5,6,7].forEach(c => wsPL.getCell(r, c).numFmt = fmtPesoPosNeg);
        }
        [22,28,12,16,16,16,16].forEach((w,i)=> {
          if (!wsPL.getColumn(i+1).width || wsPL.getColumn(i+1).width < w) wsPL.getColumn(i+1).width = w;
        });

        currentRowProd = dataEnd + 2;
      }

      // Sheet 2: Expired by Category
      const expiredTotalsRows = invCategories.map(cat => {
        const v = (expiredByCat || []).find(x => (x._id || 'Uncategorized') === cat) || {};
        return [cat, (v.expiredCount || 0), Math.round(v.fullLoss || 0), Math.round(v.baseLoss || 0), Math.round(v.markupLoss || 0)];
      });

      const wsExp = wb.addWorksheet('Expired by Category', { views: [{ state:'frozen', ySplit: 3 }] });
      wsExp.mergeCells('A1:E1');
      const expTitleTag = productCategory ? `Expired Products — Category: ${productCategory}` : 'Expired Products by Category';
      wsExp.getCell('A1').value = `${expTitleTag} • ${fmtDateLong(s)} → ${fmtDateLong(e)}`;
      wsExp.getCell('A1').font = { bold:true, size:14 };
      wsExp.getCell('A1').alignment = { horizontal:'center' };

      wsExp.addTable({
        name: 'LossByCategory',
        ref: 'A3',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [
          { name: 'Category' }, { name: 'Expired Count' },
          { name: 'Full Loss (PHP)' }, { name: 'Base Loss (PHP)' }, { name: 'Markup Loss (PHP)' }
        ],
        rows: expiredTotalsRows
      });
      styleHeaderRow(wsExp, 3, 1, 5);
      const expEnd = 3 + expiredTotalsRows.length;
      setBorders(wsExp, 3, 1, Math.max(3, expEnd), 5);
      wsExp.getColumn(2).numFmt = fmtIntPosNeg;
      [3,4,5].forEach(c => wsExp.getColumn(c).numFmt = fmtPesoPosNeg);
      [22,16,18,18,18].forEach((w,i)=> { if (!wsExp.getColumn(i+1).width || wsExp.getColumn(i+1).width < w) wsExp.getColumn(i+1).width = w; });

      // Sheet 3: Slow Movers (Products)
      const wsSlowP = wb.addWorksheet('Slow Movers (Products)', { views: [{ state:'frozen', ySplit:1 }] });
      wsSlowP.addTable({
        name: 'SlowMoversProducts',
        ref: 'A1',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [ { name: 'Product' }, { name: 'Category' }, { name: 'Last Sold' } ],
        rows: (slowProducts || []).map(r => [ r.name, r.category, r.lastSoldAt ? new Date(r.lastSoldAt) : 'Never' ])
      });
      styleHeaderRow(wsSlowP, 1, 1, 3);
      const slowEndP = 1 + (slowProducts || []).length;
      setBorders(wsSlowP, 1, 1, Math.max(1, slowEndP), 3);
      wsSlowP.getColumn(3).numFmt = 'yyyy-mm-dd';
      [28,22,20].forEach((w,i)=> { if (!wsSlowP.getColumn(i+1).width || wsSlowP.getColumn(i+1).width < w) wsSlowP.getColumn(i+1).width = w; });

      const catTag = productCategory ? `_${sanitize(productCategory)}` : '';
      const fileName = `SalesReport${catTag}_${new Date().toISOString().slice(0,10)}.xlsx`;
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      await wb.xlsx.write(res);
      res.end();
      return;
    }

    // ===========================
    // Branch: BOTH (Products + Services combined)
    // ===========================
    if (mode === 'both') {
      const {
        invCategories, catPLRows, totals: totalsProd,
        expiredByCat, expiredDetail, perProductByCat,
        slowProducts
      } = await buildProductsData();

      const {
        svcCategories, svcSalesMap, perServiceByCat, slowRows, totals: totalsSvc
      } = await buildServicesData();

      // ---- OVERALL totals
      const overallUnitsSold = totalsProd.unitsSold;
      const overallServiceCounts = totalsSvc.count;
      const overallSales = (totalsProd.sales || 0) + (totalsSvc.sales || 0); // products SALES (base+markup) + services SALES
      const overallLoss  = totalsProd.loss || 0;                              // product expired full loss only
      const overallProfit = (totalsProd.profit || 0) + (totalsSvc.sales || 0); // products (markup - loss) + services (sales)

      // ===== Sheet 1: Overall (combined)
      const wsOverall = wb.addWorksheet('Overall', { views: [{ state:'frozen', ySplit: 3 }] });
      wsOverall.mergeCells('A1:F1');
      wsOverall.getCell('A1').value = `Overall — Products + Services • ${fmtDateLong(s)} → ${fmtDateLong(e)}`;
      wsOverall.getCell('A1').font = { bold:true, size:14 };
      wsOverall.getCell('A1').alignment = { horizontal:'center' };

      // Table: Type | Units Sold | Service Counts | Sales | Loss | Profit
      const overallRows = [
        ['Products', overallUnitsSold, '', totalsProd.sales || 0, totalsProd.loss || 0, totalsProd.profit || 0],
        ['Services', '', overallServiceCounts, totalsSvc.sales || 0, 0, totalsSvc.sales || 0],
      ];
      wsOverall.addTable({
        name: 'OverallPL',
        ref: 'A3',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [
          { name: 'Type' },
          { name: 'Units Sold' },
          { name: 'Service Counts' },
          { name: 'Sales (PHP)' },
          { name: 'Loss (PHP)' },
          { name: 'Profit (PHP)' }
        ],
        rows: overallRows
      });
      styleHeaderRow(wsOverall, 3, 1, 6);
      setBorders(wsOverall, 3, 1, 3 + overallRows.length, 6);
      [16,14,16,18,18,18].forEach((w,i)=> wsOverall.getColumn(i+1).width = w);
      wsOverall.getColumn(2).numFmt = fmtIntPosNeg;
      wsOverall.getColumn(3).numFmt = fmtIntPosNeg;
      [4,5,6].forEach(c => wsOverall.getColumn(c).numFmt = fmtPesoPosNeg);

      // TOTAL row (color-coded)
      wsOverall.addRow([]);
      const totalRowAll = wsOverall.addRow([
        'TOTAL',
        overallUnitsSold,
        overallServiceCounts,
        overallSales,
        overallLoss,
        overallProfit
      ]);
      totalRowAll.font = { bold: true };
      [2,3].forEach(c => totalRowAll.getCell(c).numFmt = fmtIntPosNeg);
      [4,5,6].forEach(c => totalRowAll.getCell(c).numFmt = fmtPesoPosNeg);
      for (let c = 1; c <= 6; c++) {
        const cell = totalRowAll.getCell(c);
        cell.border = {
          top:    { style:'thin', color:{ argb: COLORS.grid } },
          bottom: { style:'thin', color:{ argb: COLORS.grid } },
          left:   { style:'thin', color:{ argb: COLORS.grid } },
          right:  { style:'thin', color:{ argb: COLORS.grid } },
        };
        cell.fill = { type:'pattern', pattern:'solid', fgColor:{ argb: TOTAL_FILL } };
      }

      // ===== Sheet 2: Products (same as products-only sheet)
      const wsPL = wb.addWorksheet('Products', { views: [{ state:'frozen', ySplit: 3 }] });
      wsPL.mergeCells('A1:E1');
      wsPL.getCell('A1').value = `Products — All Categories • ${fmtDateLong(s)} → ${fmtDateLong(e)}`;
      wsPL.getCell('A1').font = { bold:true, size:14 };
      wsPL.getCell('A1').alignment = { horizontal:'center' };

      wsPL.addTable({
        name: 'CategoryPL',
        ref: 'A3',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [
          { name: 'Category' }, { name: 'Units Sold' },
          { name: 'Sales (PHP)' }, { name: 'Loss (PHP)' }, { name: 'Profit (PHP)' }
        ],
        rows: catPLRows.map(r => [ r.category, r.unitsSold, r.sales, r.loss, r.profit ])
      });
      [24,14,18,18,18].forEach((w,i)=> wsPL.getColumn(i+1).width = w);
      wsPL.getColumn(2).numFmt = fmtIntPosNeg;
      [3,4,5].forEach(c => wsPL.getColumn(c).numFmt = fmtPesoPosNeg);
      styleHeaderRow(wsPL, 3, 1, 5);
      const catDataEnd = 3 + catPLRows.length;
      setBorders(wsPL, 3, 1, Math.max(3, catDataEnd), 5);

      wsPL.addRow([]);
      const totalRowPL = wsPL.addRow(['TOTAL', totalsProd.unitsSold, totalsProd.sales, totalsProd.loss, totalsProd.profit]);
      totalRowPL.font = { bold: true };
      totalRowPL.getCell(2).numFmt = fmtIntPosNeg;
      ['C','D','E'].forEach(c => totalRowPL.getCell(c).numFmt = fmtPesoPosNeg);
      for (let c = 1; c <= 5; c++) {
        const cell = totalRowPL.getCell(c);
        cell.border = {
          top:    { style:'thin', color:{ argb: COLORS.grid } },
          bottom: { style:'thin', color:{ argb: COLORS.grid } },
          left:   { style:'thin', color:{ argb: COLORS.grid } },
          right:  { style:'thin', color:{ argb: COLORS.grid } },
        };
        cell.fill = { type:'pattern', pattern:'solid', fgColor:{ argb: TOTAL_FILL } };
      }

      wsPL.addRow([]);
      wsPL.addRow(['Per-Product P&L by Category']).font = { bold:true };
      wsPL.addRow([]);

      let blockCountProd = 0;
      let currentRowProd = wsPL.lastRow.number + 1;
      for (const cat of invCategories) {
        const rows = (perProductByCat.get(cat) || []);
        if (!rows.length) continue;
        if (blockCountProd > 0) { wsPL.addRow([]); currentRowProd = wsPL.lastRow.number + 1; }
        blockCountProd++;

        const headerRowIdx = currentRowProd;
        wsPL.addTable({
          name: `ProductPL_${sanitize(cat)}`,
          ref: `A${headerRowIdx}`,
          headerRow: true,
          style: { theme: 'TableStyleLight15', showRowStripes: true },
          columns: [
            { name: 'Category' }, { name: 'Product' }, { name: 'Units Sold' },
            { name: 'Price (PHP)' }, { name: 'Markup (PHP)' },
            { name: 'Total Sales (PHP)' }, { name: 'Profit (PHP)' }
          ],
          rows
        });
        const dataEnd   = headerRowIdx + rows.length;
        styleHeaderRow(wsPL, headerRowIdx, 1, 7);
        setBorders(wsPL, headerRowIdx, 1, Math.max(headerRowIdx, dataEnd), 7);
        for (let r = headerRowIdx + 1; r <= dataEnd; r++) {
          wsPL.getCell(r, 3).numFmt = fmtIntPosNeg;
          [4,5,6,7].forEach(c => wsPL.getCell(r, c).numFmt = fmtPesoPosNeg);
        }
        [22,28,12,16,16,16,16].forEach((w,i)=> {
          if (!wsPL.getColumn(i+1).width || wsPL.getColumn(i+1).width < w) wsPL.getColumn(i+1).width = w;
        });

        currentRowProd = dataEnd + 2;
      }

      // ===== Sheet 3: Services
      const wsSvc = wb.addWorksheet('Services', { views: [{ state:'frozen', ySplit: 3 }] });
      wsSvc.mergeCells('A1:D1');
      wsSvc.getCell('A1').value = `Services — All Categories • ${fmtDateLong(s)} → ${fmtDateLong(e)}`;
      wsSvc.getCell('A1').font = { bold:true, size:14 };
      wsSvc.getCell('A1').alignment = { horizontal:'center' };

      const catRowsSvc = svcCategories.map(cat => {
        const v = svcSalesMap.get(cat) || { serviceCounts: 0, sales: 0 };
        return [cat, Math.round(v.serviceCounts || 0), Math.round(v.sales || 0)];
      });
      wsSvc.addTable({
        name: 'SvcCategorySales',
        ref: 'A3',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [ { name: 'Category' }, { name: 'Service Counts' }, { name: 'Sales (PHP)' } ],
        rows: catRowsSvc
      });
      styleHeaderRow(wsSvc, 3, 1, 3);
      setBorders(wsSvc, 3, 1, Math.max(3, 3 + catRowsSvc.length), 3);
      [24,18,18].forEach((w,i)=> wsSvc.getColumn(i+1).width = w);
      wsSvc.getColumn(2).numFmt = fmtIntPosNeg;
      wsSvc.getColumn(3).numFmt = fmtPesoPosNeg;

      wsSvc.addRow([]);
      const totalsSvcRow = wsSvc.addRow(['TOTAL', totalsSvc.count, totalsSvc.sales]);
      totalsSvcRow.font = { bold: true };
      totalsSvcRow.getCell(2).numFmt = fmtIntPosNeg;
      totalsSvcRow.getCell(3).numFmt = fmtPesoPosNeg;
      for (let c = 1; c <= 3; c++) {
        const cell = totalsSvcRow.getCell(c);
        cell.border = {
          top:    { style:'thin', color:{ argb: COLORS.grid } },
          bottom: { style:'thin', color:{ argb: COLORS.grid } },
          left:   { style:'thin', color:{ argb: COLORS.grid } },
          right:  { style:'thin', color:{ argb: COLORS.grid } },
        };
        cell.fill = { type:'pattern', pattern:'solid', fgColor:{ argb: TOTAL_FILL } };
      }

      wsSvc.addRow([]);
      wsSvc.addRow(['Per-Service by Category']).font = { bold:true };
      wsSvc.addRow([]);

      let blockCountSvc = 0;
      let currentRowSvc = wsSvc.lastRow.number + 1;
      for (const cat of svcCategories) {
        const rows = perServiceByCat.get(cat) || [];
        if (!rows.length) continue;
        if (blockCountSvc > 0) { wsSvc.addRow([]); currentRowSvc = wsSvc.lastRow.number + 1; }
        blockCountSvc++;

        const headerRowIdx = currentRowSvc;
        wsSvc.addTable({
          name: `PerService_${sanitize(cat)}`,
          ref: `A${headerRowIdx}`,
          headerRow: true,
          style: { theme: 'TableStyleLight15', showRowStripes: true },
          columns: [
            { name: 'Category' },
            { name: 'Service' },
            { name: 'Service Counts' },
            { name: 'Total Sales (PHP)' }
          ],
          rows
        });
        const dataEnd = headerRowIdx + rows.length;
        styleHeaderRow(wsSvc, headerRowIdx, 1, 4);
        setBorders(wsSvc, headerRowIdx, 1, Math.max(headerRowIdx, dataEnd), 4);
        wsSvc.getColumn(3).numFmt = fmtIntPosNeg;
        wsSvc.getColumn(4).numFmt = fmtPesoPosNeg;
        [22,28,16,18].forEach((w,i)=> {
          if (!wsSvc.getColumn(i+1).width || wsSvc.getColumn(i+1).width < w) wsSvc.getColumn(i+1).width = w;
        });

        currentRowSvc = dataEnd + 2;
      }

      // ===== Sheet 4: Expired by Category (Products)
      const expiredTotalsRows = invCategories.map(cat => {
        const v = (expiredByCat || []).find(x => (x._id || 'Uncategorized') === cat) || {};
        return [cat, (v.expiredCount || 0), Math.round(v.fullLoss || 0), Math.round(v.baseLoss || 0), Math.round(v.markupLoss || 0)];
      });

      const wsExp = wb.addWorksheet('Expired by Category', { views: [{ state:'frozen', ySplit: 3 }] });
      wsExp.mergeCells('A1:E1');
      wsExp.getCell('A1').value = `Expired Products by Category • ${fmtDateLong(s)} → ${fmtDateLong(e)}`;
      wsExp.getCell('A1').font = { bold:true, size:14 };
      wsExp.getCell('A1').alignment = { horizontal:'center' };

      wsExp.addTable({
        name: 'LossByCategory',
        ref: 'A3',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [
          { name: 'Category' }, { name: 'Expired Count' },
          { name: 'Full Loss (PHP)' }, { name: 'Base Loss (PHP)' }, { name: 'Markup Loss (PHP)' }
        ],
        rows: expiredTotalsRows
      });
      styleHeaderRow(wsExp, 3, 1, 5);
      const expEnd = 3 + expiredTotalsRows.length;
      setBorders(wsExp, 3, 1, Math.max(3, expEnd), 5);
      wsExp.getColumn(2).numFmt = fmtIntPosNeg;
      [3,4,5].forEach(c => wsExp.getColumn(c).numFmt = fmtPesoPosNeg);
      [22,16,18,18,18].forEach((w,i)=> { if (!wsExp.getColumn(i+1).width || wsExp.getColumn(i+1).width < w) wsExp.getColumn(i+1).width = w; });

      // ===== Sheet 5: Slow Movers (Products)
      const wsSlowP = wb.addWorksheet('Slow Movers (Products)', { views: [{ state:'frozen', ySplit:1 }] });
      wsSlowP.addTable({
        name: 'SlowMoversProducts',
        ref: 'A1',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [ { name: 'Product' }, { name: 'Category' }, { name: 'Last Sold' } ],
        rows: (slowProducts || []).map(r => [ r.name, r.category, r.lastSoldAt ? new Date(r.lastSoldAt) : 'Never' ])
      });
      styleHeaderRow(wsSlowP, 1, 1, 3);
      const slowEndP = 1 + (slowProducts || []).length;
      setBorders(wsSlowP, 1, 1, Math.max(1, slowEndP), 3);
      wsSlowP.getColumn(3).numFmt = 'yyyy-mm-dd';
      [28,22,20].forEach((w,i)=> { if (!wsSlowP.getColumn(i+1).width || wsSlowP.getColumn(i+1).width < w) wsSlowP.getColumn(i+1).width = w; });

      // ===== Sheet 6: Slow Movers (Services)
      const wsSlowS = wb.addWorksheet('Slow Movers (Services)', { views: [{ state:'frozen', ySplit: 1 }] });
      wsSlowS.addTable({
        name: 'SlowServices',
        ref: 'A1',
        headerRow: true,
        style: { theme: 'TableStyleLight15', showRowStripes: true },
        columns: [ { name: 'Service' }, { name: 'Category' }, { name: 'Last Service' } ],
        rows: (slowRows || [])
      });
      styleHeaderRow(wsSlowS, 1, 1, 3);
      setBorders(wsSlowS, 1, 1, Math.max(1, 1 + (slowRows || []).length), 3);
      wsSlowS.getColumn(3).numFmt = 'yyyy-mm-dd';
      [28,22,20].forEach((w,i)=> { if (!wsSlowS.getColumn(i+1).width || wsSlowS.getColumn(i+1).width < w) wsSlowS.getColumn(i+1).width = w; });

      const fileName = `SalesReport_All_${new Date().toISOString().slice(0,10)}.xlsx`;
      res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      await wb.xlsx.write(res); res.end();
      return;
    }

  } catch (err) {
    console.error('exportExcel error:', err);
    res.status(500).send('Failed to generate Excel.');
  }
};
