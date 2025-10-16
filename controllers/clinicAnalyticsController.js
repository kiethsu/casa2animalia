// controllers/clinicAnalyticsController.js
const mongoose = require('mongoose');
const Reservation = require('../models/reservation');
const Consultation = require('../models/consultation');

/** helper: compute [start, end] from range */
function windowFromRange(range = '30d') {
  const now = new Date(); now.setHours(23,59,59,999);
  let start = new Date(now);
  switch (String(range)) {
    case 'day':
      start.setHours(0,0,0,0);
      break;
    case '7d':
    case 'week': // ← treat “week” as last 7 days
      start.setDate(now.getDate() - 6);
      start.setHours(0,0,0,0);
      break;
    case '30d':
      start.setDate(now.getDate() - 29);
      start.setHours(0,0,0,0);
      break;
    case 'month':
      start = new Date(now.getFullYear(), now.getMonth(), 1);
      break;
    case 'year':
      start = new Date(now.getFullYear(), 0, 1);
      break;
    default:
      start.setDate(now.getDate() - 29);
      start.setHours(0,0,0,0);
  }
  return { start, end: now };
}
/** helper: compute [start, end] from explicit year/month */
function windowFromYearMonth(year, month) {
  const y = Number(year);
  const m = Number(month);
  if (Number.isInteger(y) && y >= 1970 && y <= 9999) {
    if (Number.isInteger(m) && m >= 1 && m <= 12) {
      const start = new Date(y, m - 1, 1, 0, 0, 0, 0);
      const end   = new Date(y, m, 0, 23, 59, 59, 999); // last day of that month
      return { start, end };
    }
    // whole year
    const start = new Date(y, 0, 1, 0, 0, 0, 0);
    const end   = new Date(y, 11, 31, 23, 59, 59, 999);
    return { start, end };
  }
  return null;
}

/** GET /admin/peak-day-of-week?range=7d|30d|month|year */
exports.getPeakDayOfWeek = async (req, res) => {
  try {
    const r = String(req.query.range || '30d');
    const { start, end } = windowFromRange(r);

    const reservations = await Reservation.find({
      createdAt: { $gte: start, $lte: end }
    }).lean();

    const dayNames = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
    const counts = [0,0,0,0,0,0,0];

    reservations.forEach(rv => {
      const d = new Date(rv.createdAt);
      if (!isNaN(d)) counts[d.getDay()]++;
    });

    const days = dayNames.map((label, i) => ({ dayLabel: label, count: counts[i] }));
    res.json({ days });
  } catch (err) {
    console.error('getPeakDayOfWeek error:', err);
    res.status(500).json({ error: 'Server error analyzing day-of-week.' });
  }
};

/** GET /admin/predict-appointments  (kept for compatibility) */
exports.predictAppointments = async (req, res) => {
  try {
    const today = new Date(); today.setHours(23,59,59,999);

    // build last 7 days of counts
    const dayCounts = [];
    for (let i = 6; i >= 0; i--) {
      const day = new Date(today); day.setDate(today.getDate() - i);
      const start = new Date(day);  start.setHours(0,0,0,0);
      const end   = new Date(day);  end.setHours(23,59,59,999);

      // if you prefer "date of appointment" instead of "createdAt", change field here
      // eslint-disable-next-line no-await-in-loop
      const c = await Reservation.countDocuments({ createdAt: { $gte: start, $lte: end } });
      dayCounts.push({ date: day.toISOString().slice(0,10), count: c });
    }

    const allZero = dayCounts.every(d => d.count === 0);
    if (allZero) {
      const predictions = [];
      for (let i = 1; i <= 3; i++) {
        const future = new Date(today); future.setDate(today.getDate() + i);
        predictions.push({ date: future.toISOString().slice(0,10), predictedCount: 0 });
      }
      return res.json({ last7days: dayCounts, method: 'fallbackAllZero', predictions });
    }

    // naïve ratio/diff forecast
    const ratios = [], diffs = [];
    for (let i = 1; i < dayCounts.length; i++) {
      const prev = dayCounts[i-1].count;
      const curr = dayCounts[i].count;
      if (prev > 0) ratios.push(curr / prev);
      diffs.push(curr - prev);
    }

    let method = 'averageDiff';
    let avgGrowth = 1;
    let avgDiff = 0;

    if (ratios.length >= 3) {
      avgGrowth = ratios.reduce((a,b)=>a+b,0) / ratios.length;
      method = 'averageRatio';
    } else if (diffs.length) {
      avgDiff = Math.round(diffs.reduce((a,b)=>a+b,0) / diffs.length);
    }

    const predictions = [];
    let last = dayCounts[dayCounts.length - 1].count;
    for (let i = 1; i <= 3; i++) {
      const nextDate = new Date(today); nextDate.setDate(today.getDate() + i);
      const next = method === 'averageRatio' ? Math.round(last * avgGrowth) : last + avgDiff;
      predictions.push({ date: nextDate.toISOString().slice(0,10), predictedCount: Math.max(0, next) });
      last = Math.max(0, next);
    }

    res.json({ last7days: dayCounts, method, averageGrowth: avgGrowth, averageDiff: avgDiff, predictions });
  } catch (err) {
    console.error('predictAppointments error:', err);
    res.status(500).json({ error: 'Server error predicting appointments.' });
  }
};

/**
 * GET /admin/top-diseases?range=day|week|month|year
 * Counts most common conditions from Reservation.{disease|diseases[]} within the window.
 * Output fits your new "Top Conditions" card: { labels[], counts[], top[] }
 */
/**
 * GET /admin/top-diseases?range=day|week|month|year
 * Source of truth: Consultation.{diseases[] | disease}
 * Returns: { labels[], counts[], top[], total }
 */

exports.getTopDiseases = async (req, res) => {
  try {
    const range   = String(req.query.range || 'month');
    const species = String(req.query.species || '').trim(); // empty = all
    const year    = req.query.year ? Number(req.query.year) : null;
    const month   = req.query.month ? Number(req.query.month) : null;

    // Prefer explicit year/month if provided and valid; else fallback to range window
    const ym = windowFromYearMonth(year, month);
    const { start, end } = ym || windowFromRange(range);

    const pipeline = [
      { $match: { createdAt: { $gte: start, $lte: end } } }
    ];

    if (species) {
      pipeline.push(
        {
          $lookup: {
            from: 'reservations',
            localField: 'reservation',
            foreignField: '_id',
            as: 'resv'
          }
        },
        { $unwind: '$resv' },
        { $match: { 'resv.species': species } }
      );
    }

    pipeline.push(
      {
        $addFields: {
          ds: {
            $cond: [
              { $gt: [ { $size: { $ifNull: ['$diseases', []] } }, 0 ] },
              '$diseases',
              {
                $cond: [
                  { $and: [ { $ne: ['$disease', null] }, { $ne: ['$disease', ''] } ] },
                  ['$disease'],
                  []
                ]
              }
            ]
          }
        }
      },
      { $unwind: '$ds' },
      {
        $project: {
          dsNorm: { $toLower: { $trim: { input: { $toString: '$ds' } } } },
          dsOrig: { $trim: { input: { $toString: '$ds' } } }
        }
      },
      { $match: { dsNorm: { $ne: '' } } },
      { $group: { _id: '$dsNorm', count: { $sum: 1 }, sample: { $first: '$dsOrig' } } },
      { $sort: { count: -1 } },
      { $limit: 20 }
    );

    const rows   = await Consultation.aggregate(pipeline);
    const labels = rows.map(r => r.sample);
    const counts = rows.map(r => r.count);
    const top    = rows.map((r,i)=>({ rank:i+1, name:r.sample, count:r.count }));

    res.json({ labels, counts, top, total: counts.reduce((a,b)=>a+b,0) });
  } catch (err) {
    console.error('getTopDiseases error:', err);
    res.status(500).json({ error: 'Server error fetching top diseases.' });
  }
};


