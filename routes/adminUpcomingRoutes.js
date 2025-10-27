// routes/adminUpcomingRoutes.js
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const Joi = require('joi');
const nodemailer = require('nodemailer');

const Reservation = require('../models/reservation');
const AppointmentSetting = require('../models/appointmentSetting');
const User = require('../models/user');

const { addClient, removeClient, broadcast } = require('../utils/hrSse');

/* =========================
   Helpers
   ========================= */

// local YYYY-MM-DD from a Date/string
function ymdLocal(d) {
  const x = (d instanceof Date) ? d : new Date(d);
  if (isNaN(x)) return '';
  const yyyy = x.getFullYear();
  const mm = String(x.getMonth() + 1).padStart(2, '0');
  const dd = String(x.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

// start/end of a local day for querying
function dayBoundsLocal(iso) {
  if (!iso || !/^\d{4}-\d{2}-\d{2}$/.test(iso)) {
    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const end   = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    return { start, end };
  }
  const [y, m, d] = iso.split('-').map(n => parseInt(n, 10));
  const start = new Date(y, m - 1, d);
  const end   = new Date(y, m - 1, d + 1);
  return { start, end };
}

function esc(s = '') {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

function buildTransport() {
  const host = process.env.SMTP_HOST || 'smtp-relay.brevo.com';
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_EMAIL;
  const pass = process.env.SMTP_PASS;
  if (!user || !pass) return null;
  return nodemailer.createTransport({ host, port, secure: port === 465, auth: { user, pass } });
}

// Earliest pet schedule becomes the reservation-level mirror
function deriveReservationScheduleFromPets(doc) {
  const pets = Array.isArray(doc.pets) ? doc.pets : [];
  const slots = pets
    .map(p => p?.schedule && p.schedule.scheduleDate ? ({
      date: new Date(p.schedule.scheduleDate),
      time: p.schedule.time || '',
      schedule: p.schedule
    }) : null)
    .filter(Boolean);

  if (!slots.length) return;

  slots.sort((a, b) => {
    const da = a.date.getTime(), db = b.date.getTime();
    if (da !== db) return da - db;
    // naive time ordering HH:MM AM/PM (if you store as strings)
    const tk = t => {
      if (!t) return 0;
      const m = /^(\d{1,2}):(\d{2})\s*(AM|PM)$/i.exec(t);
      if (!m) return 0;
      let hh = parseInt(m[1], 10) % 12;
      const mm = parseInt(m[2], 10);
      const ap = (m[3] || '').toUpperCase() === 'PM' ? 12 : 0;
      return (hh + ap) * 60 + mm;
    };
    return tk(a.time) - tk(b.time);
  });

  const first = slots[0].schedule;
  doc.schedule = doc.schedule || {};
  doc.schedule.scheduleDate = first.scheduleDate;
  doc.schedule.time = first.time || doc.schedule.time || '';
  doc.schedule.scheduleDetails = doc.schedule.scheduleDetails || first.scheduleDetails || undefined;
  doc.schedule.service = doc.schedule.service || first.service || undefined;
}

// Build a UI row from a schedule (reservation-level or pet-level)
function rowFromSchedule(r, sched, pet) {
  if (!sched || !sched.scheduleDate) return null;
  const iso = ymdLocal(sched.scheduleDate);
  const service =
    (sched.service && (sched.service.name || sched.service.serviceName)) ||
    sched.scheduleDetails || r.service || '—';

  return {
    reservationId: String(r._id),
    petId: pet?.petId ? String(pet.petId) : null,
    petName: pet?.petName || pet?.name || '—',
    ownerName: r.ownerName || '—',
    doctor: r?.doctor?.username || '—',
    dateISO: iso,
    service,
    time: sched.time || '',
    status: 'Scheduled'
  };
}

// Collect entries for the calendar/table (both reservation-level & per-pet; de-duped)
async function collectUpcomingEntries() {
  const reservations = await Reservation.find({
    status: { $ne: 'Canceled' },
    $or: [
      { 'schedule.scheduleDate': { $exists: true } },
      { 'pets.schedule.scheduleDate': { $exists: true } }
    ]
  })
  .populate('doctor', 'username')
  .lean();

  const entries = [];
  const counts = Object.create(null);

  for (const r of reservations) {
    // reservation-level mirror (if present)
    const rowRoot = rowFromSchedule(r, r.schedule, null);
    if (rowRoot) {
      entries.push(rowRoot);
      counts[rowRoot.dateISO] = (counts[rowRoot.dateISO] || 0) + 1;
    }

    // pet-level schedules
    for (const p of (r.pets || [])) {
      const rowPet = rowFromSchedule(r, p.schedule, p);
      if (rowPet) {
        entries.push(rowPet);
        counts[rowPet.dateISO] = (counts[rowPet.dateISO] || 0) + 1;
      }
    }
  }

  // de-dup (reservationId + pet key + date)
  const uniq = [];
  const seen = new Set();
  for (const e of entries) {
    const key = `${e.reservationId}::${e.petId || (e.petName || '').toLowerCase()}::${e.dateISO}`;
    if (seen.has(key)) continue;
    seen.add(key);
    uniq.push(e);
  }

  uniq.sort((a, b) => new Date(a.dateISO) - new Date(b.dateISO) || a.ownerName.localeCompare(b.ownerName));
  return { entries: uniq, dateCounts: counts };
}

// Count how many bookings are at a given date+time (dedupe root/pet)
async function countAt(dateISO, time) {
  const { start, end } = dayBoundsLocal(dateISO);

  // reservations that match on root schedule
  const rootIds = await Reservation.find({
    status: { $ne: 'Canceled' },
    'schedule.scheduleDate': { $gte: start, $lt: end },
    'schedule.time': time
  }).distinct('_id');

  // reservations that have ANY pet with that schedule
  const petIds = await Reservation.aggregate([
    { $match: { status: { $ne: 'Canceled' }, 'pets.schedule.scheduleDate': { $gte: start, $lt: end } } },
    { $unwind: '$pets' },
    { $match: { 'pets.schedule.scheduleDate': { $gte: start, $lt: end }, 'pets.schedule.time': time } },
    { $group: { _id: '$_id' } }
  ]).then(rows => rows.map(x => String(x._id)));

  const set = new Set([...rootIds.map(String), ...petIds]);
  return set.size;
}

/* =========================
   RENDER: /admin/upcoming
   ========================= */
router.get('/upcoming', async (req, res) => {
  try {
    // Provide a short-lived token to the client (used by SSE)
    const fromHeader = (req.headers.authorization || '').replace(/^Bearer\s+/, '');
    let authToken = fromHeader;
    if (!authToken && process.env.JWT_SECRET) {
      authToken = jwt.sign(
        { userId: req.user.userId, role: req.user.role || 'Admin' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
      );
    }

    const { entries, dateCounts } = await collectUpcomingEntries();
    res.render('admin/upcoming', {
      entries,
      upcomingDateCounts: dateCounts,
      authToken: authToken || ''
    });
  } catch (e) {
    console.error('[Admin Upcoming] render failed:', e);
    res.status(500).send('Server error');
  }
});

/* =========================
   SSE: /admin/stream  (?token= allowed)
   ========================= */
router.get('/stream', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    let token = auth.replace(/^Bearer\s+/, '');
    if (!token && req.query && req.query.token) token = String(req.query.token);
    if (!token || !process.env.JWT_SECRET) return res.status(401).end();
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;

    res.set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    res.flushHeaders?.();
    res.write('retry: 3000\n\n');

    addClient(res);
    res.write(`data: ${JSON.stringify({ type: 'hello', scope: 'admin', t: Date.now() })}\n\n`);

    req.on('close', () => {
      removeClient(res);
      try { res.end(); } catch (_) {}
    });
  } catch (e) {
    console.error('[Admin /stream] auth failed:', e?.message || e);
    return res.status(401).end();
  }
});

/* =========================
   API: /admin/api/upcoming
   ========================= */
router.get('/api/upcoming', async (_req, res) => {
  try {
    const { entries } = await collectUpcomingEntries();
    return res.json({ success: true, entries });
  } catch (e) {
    console.error('[Admin api/upcoming] failed:', e);
    return res.json({ success: false, entries: [] });
  }
});

/* =========================
   FOLLOW-UP LIMIT (Admin UI)
   ========================= */
router.get('/followup-limit', async (_req, res) => {
  try {
    const s = await AppointmentSetting.findOne().lean();
    return res.json({ success: true, limit: Number(s?.limitPerHour || 0) });
  } catch {
    return res.json({ success: true, limit: 0 });
  }
});

const limitSchema = Joi.object({ limit: Joi.number().integer().min(0).required() });
router.post('/followup-limit', async (req, res) => {
  try {
    const { error, value } = limitSchema.validate(req.body);
    if (error) return res.json({ success: false, message: error.details[0].message });

    let s = await AppointmentSetting.findOne();
    if (!s) s = new AppointmentSetting({ limitPerHour: value.limit });
    else s.limitPerHour = value.limit;
    await s.save();
    return res.json({ success: true, limit: s.limitPerHour });
  } catch (e) {
    console.error('[Admin followup-limit] failed:', e);
    return res.json({ success: false, message: 'Server error' });
  }
});

/* =========================
   SLOT LIMIT/COUNT for grid
   ========================= */
router.get('/followup/appointmentLimit', async (_req, res) => {
  try {
    const s = await AppointmentSetting.findOne().lean();
    return res.json({ limit: Number(s?.limitPerHour || 0) });
  } catch { return res.json({ limit: 0 }); }
});

router.get('/followup/appointmentCount', async (req, res) => {
  try {
    const iso = String(req.query.date || '').slice(0, 10);
    const time = String(req.query.time || '').trim();
    if (!iso || !time) return res.json({ count: 0 });

    const count = await countAt(iso, time);
    return res.json({ count });
  } catch (e) {
    console.error('[Admin appointmentCount] failed:', e);
    return res.json({ count: 0 });
  }
});

/* =========================
   RESCHEDULE (capacity + email)
   ========================= */
const reschedSchema = Joi.object({
  reservationId: Joi.string().required(),
  petId:         Joi.string().optional().allow(''),
  petName:       Joi.string().optional().allow(''),
  newDateISO:    Joi.string().required(),     // 'YYYY-MM-DD'
  time:          Joi.string().optional().allow(''),
  note:          Joi.string().optional().allow(''),
  notify:        Joi.boolean().truthy('true').falsy('false').default(true)
});

router.post('/followup/reschedule', async (req, res) => {
  try {
    const { error, value } = reschedSchema.validate(req.body);
    if (error) return res.json({ success: false, message: error.details[0].message });

    const { reservationId, petId, petName, newDateISO, time, note, notify } = value;

    // capacity check (if per-hour limit is set and a time is selected)
    const s = await AppointmentSetting.findOne().lean();
    const limitPerHour = Number(s?.limitPerHour || 0);
    if (limitPerHour > 0 && time) {
      const taken = await countAt(newDateISO, time);
      if (taken >= limitPerHour) {
        return res.json({ success: false, message: 'Time slot is full.' });
      }
    }

    // Load doc to update
    const doc = await Reservation.findById(reservationId).populate('doctor', 'username');
    if (!doc) return res.json({ success: false, message: 'Reservation not found.' });

    // Find pet entry (ID wins, else by name; otherwise fallback index 0 if exists)
    let idx = -1;
    if (petId && mongoose.isValidObjectId(petId)) {
      idx = (doc.pets || []).findIndex(p => String(p.petId) === String(petId));
    } else if (petName) {
      const want = String(petName).trim().toLowerCase();
      idx = (doc.pets || []).findIndex(p =>
        String(p?.petName || '').trim().toLowerCase() === want
      );
    }
    if (idx < 0 && Array.isArray(doc.pets) && doc.pets.length) idx = 0;

    // Build schedule object
    const localDate = (() => {
      const [y, m, d] = newDateISO.split('-').map(n => parseInt(n, 10));
      return new Date(y, m - 1, d);
    })();

    const serviceText =
      (doc.pets?.[idx]?.schedule?.service?.name) ||
      (doc.schedule?.service?.name) ||
      (typeof doc.service === 'string' ? doc.service : (doc.service?.serviceName || 'Follow-up')) ||
      'Follow-up';

    const newSched = {
      scheduleDate: localDate,
      time: time || '',
      scheduleDetails: serviceText,
      service: { name: serviceText },
      rescheduled: {
        fromDate: (idx >= 0 ? doc.pets?.[idx]?.schedule?.scheduleDate : doc.schedule?.scheduleDate) || undefined,
        fromTime: (idx >= 0 ? doc.pets?.[idx]?.schedule?.time         : doc.schedule?.time)         || '',
        toDate: localDate,
        toTime: time || '',
        at: new Date(),
        by: req.user?.userId ? new mongoose.Types.ObjectId(req.user.userId) : undefined
      }
    };

    if (idx >= 0) {
      doc.pets[idx] = doc.pets[idx] || {};
      doc.pets[idx].schedule = newSched;
      // keep mirror as earliest pet follow-up
      deriveReservationScheduleFromPets(doc);
    } else {
      // fallback to root if no pets array
      doc.schedule = newSched;
    }
    doc.isFollowUp = true;
    await doc.save();

    // Broadcast for live UIs (Admin + HR pages)
    broadcast({
      type: 'followup:scheduled',
      payload: {
        reservationId: String(doc._id),
        ownerName: doc.ownerName || '',
        petName: (idx >= 0 ? (doc.pets?.[idx]?.petName || '—') : null),
        schedule: {
          scheduleDate: doc.schedule?.scheduleDate || localDate,
          scheduleDetails: doc.schedule?.scheduleDetails || serviceText,
          time: doc.schedule?.time || time || '',
          service: doc.schedule?.service || { name: serviceText }
        },
        doctor: doc.doctor ? { username: doc.doctor.username } : null,
        status: doc.status || ''
      }
    });

    // Optional email to owner/contact
    let mailed = false;
    if (notify) {
      // resolve recipient
      let toEmail = doc.contactEmail || null;
      if (!toEmail && doc.owner) {
        const owner = await User.findById(doc.owner).select('email username').lean();
        if (owner?.email) toEmail = owner.email;
      }

      const transport = toEmail ? buildTransport() : null;
      if (transport) {
        const fromEmail = process.env.SENDER_EMAIL || process.env.SMTP_EMAIL;
        const fromName  = process.env.SENDER_NAME  || 'SmartVet Clinic';
        const niceDate  = localDate.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });

        const body =
`Hello ${doc.ownerName || 'there'},

Your follow-up${idx >= 0 ? ` for ${doc.pets?.[idx]?.petName || 'your pet'}` : ''} has been rescheduled.

• Service: ${serviceText}
• New date: ${niceDate}${time ? ` at ${time}` : ''}${note ? `

Note from clinic: ${note}` : ''}

If you need to make changes, please contact the clinic.

Thank you,
SmartVet Clinic`;

        await transport.sendMail({
          from: `${fromName} <${fromEmail}>`,
          to: toEmail,
          subject: 'Your follow-up has been rescheduled',
          text: body,
          html: `<p>${esc(body).replace(/\n/g, '<br>')}</p>`
        });
        mailed = true;
      }
    }

    return res.json({
      success: true,
      mailed,
      updated: { dateISO: ymdLocal(doc.schedule?.scheduleDate || localDate), time: doc.schedule?.time || time || '' }
    });
  } catch (e) {
    console.error('[Admin followup/reschedule] failed:', e);
    return res.json({ success: false, message: 'Server error' });
  }
});

/* =========================
   EMAIL-ONLY (optional)
   ========================= */
const emailOnlySchema = Joi.object({
  reservationId: Joi.string().required(),
  emailMessage:  Joi.string().required(),
  subject:       Joi.string().optional().allow('')
});
router.post('/notify-reservation-email-only', async (req, res) => {
  try {
    const { error, value } = emailOnlySchema.validate(req.body);
    if (error) return res.json({ success:false, message: error.details[0].message });

    const r = await Reservation.findById(value.reservationId)
      .populate('owner','_id username email')
      .lean();
    if (!r) return res.json({ success:false, message:'Reservation not found.' });

    const toEmail = r.owner?.email || r.contactEmail || null;
    if (!toEmail) return res.json({ success:false, message:'No email on file.' });

    const transport = buildTransport();
    if (!transport) return res.json({ success:false, message:'SMTP not configured.' });

    const fromEmail = process.env.SENDER_EMAIL || process.env.SMTP_EMAIL;
    const fromName  = process.env.SENDER_NAME  || 'SmartVet Clinic';

    await transport.sendMail({
      from: `${fromName} <${fromEmail}>`,
      to: toEmail,
      subject: value.subject || 'Appointment Rescheduled',
      text: value.emailMessage,
      html: `<p>${esc(value.emailMessage).replace(/\n/g,'<br>')}</p>`
    });

    return res.json({ success:true, emailed:true });
  } catch (e) {
    console.error('[Admin email-only] failed:', e);
    return res.json({ success:false, message:'Server error' });
  }
});

module.exports = router;
