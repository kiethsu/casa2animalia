// routes/adminActivityRoutes.js
const express = require('express');
const router  = express.Router();
const ActivityLog = require('../models/activityLog');

// These routes are already protected by app.use(['/admin',...], authMiddleware).
// Add an extra guard: only Admins can view.
function ensureAdmin(req, res, next){
  if (req.user?.role !== 'Admin') return res.status(403).send('Forbidden');
  next();
}

/**
 * Page (EJS). You said you already have: views/admin/activityhistory.ejs
 * This renders that page; the page should fetch data from /admin/api/activity-logs
 */
router.get('/activity-history', ensureAdmin, (req, res) => {
  res.render('admin/activityhistory'); // points to views/admin/activityhistory.ejs
});

/**
 * JSON API with filters for your table/search on the page.
 * Query params:
 *  q           : string (matches action, actorName, target.name)
 *  role        : 'Admin'|'Doctor'|'HR'|'Customer'
 *  action      : exact action string or prefix (prefix match if ends with '.*')
 *  targetType  : e.g. 'Reservation'|'Consultation'|'Payment'|'User'
 *  actorId     : ObjectId string
 *  dateFrom    : ISO date string (inclusive)
 *  dateTo      : ISO date string (exclusive or end-of-day handled below)
 *  page        : default 1
 *  limit       : default 20
 */
router.get('/api/activity-logs', ensureAdmin, async (req, res) => {
  try {
    const {
      q, role, action, targetType, actorId, dateFrom, dateTo,
      page = 1, limit = 20
    } = req.query;

    const filter = {};

    // Free-text search
    if (q && q.trim()) {
      const rx = new RegExp(q.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [
        { actorName: rx },
        { action:   rx },
        { 'target.name': rx }
      ];
    }

    if (role)       filter.actorRole   = role;
    if (targetType) filter['target.type'] = targetType;
    if (actorId)    filter.actor       = actorId;

    if (action) {
      if (action.endsWith('.*')) {
        // prefix match e.g. 'reservation.*'
        const prefix = '^' + action.slice(0, -2).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        filter.action = { $regex: new RegExp(prefix) };
      } else {
        filter.action = action;
      }
    }

    if (dateFrom || dateTo) {
      filter.createdAt = {};
      if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
      if (dateTo)   filter.createdAt.$lte = new Date(dateTo);
    }

    const p = Math.max(parseInt(page, 10) || 1, 1);
    const n = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 200);

    const [items, total] = await Promise.all([
      ActivityLog
        .find(filter)
        .sort({ createdAt: -1 })
        .skip((p - 1) * n)
        .limit(n)
        .lean(),
      ActivityLog.countDocuments(filter)
    ]);

    res.json({
      page: p,
      limit: n,
      total,
      items
    });
  } catch (e) {
    console.error('/admin/api/activity-logs error', e);
    res.status(500).json({ error: 'Server error' });
  }
});
// ADD this alias to match your SPA routeMap (no authMiddleware needed)
router.get('/activityhistory', ensureAdmin, (req, res) => {
  res.render('admin/activityhistory');
});

module.exports = router;
