// doctorRoutes.js

const express = require("express");
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const Reservation = require('../models/reservation');
const Pet = require('../models/pet'); // needed to update pet details
const Joi = require('joi');
const Service = require('../models/service');
const ServiceCategory = require('../models/serviceCategory');
const Inventory = require('../models/inventory');  // NEW: Inventory model
const Consultation = require('../models/consultation');
const mongoose = require('mongoose');
const PetDetailsSetting = require('../models/petDetailsSetting');
const { broadcast, addClient, removeClient } = require('../utils/hrSse');
const PetDetailsSettings = require('../models/petDetailsSettings');
const AppointmentSetting = require('../models/appointmentSetting'); // for hourly limit
// Reservation is already imported above in your file
// const Reservation = require('../models/reservation');
// at the top with your other models
const User = require('../models/user'); // <-- add this if missing
const nodemailer = require('nodemailer');           // email
const MessageTemplate = require('../models/messageTemplate');
const ReservationMessage = require('../models/ReservationMessage');


// ----------------- Multer Setup -----------------
// Updated storage: files will be stored in public/consultation/
const multer = require('multer');

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/consultation/'); // Ensure this folder exists in your project
  },
  filename: function (req, file, cb) {
    const ext = file.originalname.split('.').pop();
    cb(null, file.fieldname + '-' + Date.now() + '.' + ext);
  }
});
const upload = multer({ storage: storage });
// ===== AUTO CREATE CUSTOMER RESERVATION FOR FOLLOW-UPS =====
const roleOf = req => String(req?.user?.role || '').toLowerCase();
const allow = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).send('Login required');
  const ok = roles.map(r => String(r).toLowerCase()).includes(roleOf(req));
  if (!ok) return res.status(403).send('Forbidden');
  next();
};

// Time labels your customer UI uses (8am–5pm, 1 per hour)
const TIME_SLOTS = [
  '08:00 AM','09:00 AM','10:00 AM','11:00 AM',
  '12:00 PM','01:00 PM','02:00 PM','03:00 PM','04:00 PM','05:00 PM'
];
function getBrevoTransport() {
  const host = process.env.SMTP_HOST || 'smtp-relay.brevo.com';
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_EMAIL;
  const pass = process.env.SMTP_PASS;

  if (!user || !pass) return null;

  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass }
  });
}

function esc(s=''){
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

function toISODateKeyUTC(d) {
  const x = new Date(d);
  // store/query by day (UTC), same pattern customer side uses
  return x.toISOString().slice(0, 10); // YYYY-MM-DD
}

function dayBoundsUTC(iso /* YYYY-MM-DD */) {
  return {
    start: new Date(iso + 'T00:00:00.000Z'),
    end  : new Date(iso + 'T23:59:59.999Z')
  };
}

// Count how many pets are already booked for date+time (Pending/Approved)
async function countPetsBookedForSlot(iso, timeLabel) {
  const { start, end } = dayBoundsUTC(iso);
  const hits = await Reservation.find({
    date : { $gte: start, $lte: end },
    time : timeLabel,
    status: { $nin: ['Canceled', 'Rejected'] }
  }).select('petRequests').lean();

  let count = 0;
  for (const r of hits) {
    // most of your code uses petRequests length as capacity unit
    count += Array.isArray(r.petRequests) && r.petRequests.length ? r.petRequests.length : 1;
  }
  return count;
}

async function getPerHourLimit() {
  try {
    const s = await AppointmentSetting.findOne().lean();
    // 0 = unlimited
    return Number(s?.limitPerHour ?? 0);
  } catch {
    return 0; // fail-open
  }
}

/**
 * Ensures a customer Reservation exists for the follow-up (idempotent).
 * - resvDoc: Reservation (lean) of the current visit
 * - petObj:  the specific pet subdoc (from resvDoc.pets[{...}])
 * - dateVal: Date | string for follow-up day
 * - details: label of follow-up service/details (string)
 * - doctorId: ObjectId of the current doctor (preferredDoctor)
 */
// add "preferredTime" as a param
async function autoCreateReservationFromFollowUp(resvDoc, petObj, dateVal, details, doctorId, preferredTime) {
  if (!resvDoc || !petObj || !dateVal) return;

  const ownerId   = resvDoc.owner || null;
  const ownerName = resvDoc.ownerName || '';
  const iso       = toISODateKeyUTC(dateVal);
  const limit     = await getPerHourLimit();

  // prefer the doctor-selected time first
  const candidateOrder = (preferredTime && TIME_SLOTS.includes(preferredTime))
    ? [preferredTime, ...TIME_SLOTS.filter(t => t !== preferredTime)]
    : TIME_SLOTS.slice();

  let chosen = null;
  for (const t of candidateOrder) {
    const used = await countPetsBookedForSlot(iso, t);
    if (limit === 0 || used < limit) { chosen = t; break; }
  }
  if (!chosen) {
    console.warn('[followup] All slots full for', iso, '— skipping auto reservation');
    return;
  }

  const petId   = petObj?.petId || null;
  const petName = petObj?.petName || (petObj?.petId?.petName) || '';

  const serviceLabel =
    (petObj?.schedule?.service?.name) ||
    (petObj?.schedule?.scheduleDetails) ||
    (details || '') ||
    'Follow-up';

  const idemKey = [
    'AUTO_FOLLOWUP',
    String(resvDoc._id),
    String(petId || petName || 'pet'),
    iso,
    chosen
  ].join('::');

  await Reservation.updateOne(
    { idemKey },
    {
      $setOnInsert: {
        owner    : ownerId,
        ownerName: ownerName,
        date     : new Date(iso),        // day-only; time kept separately
        time     : chosen,               // <-- reflect selected time
        status   : 'Pending',
        preferredDoctor: doctorId || null,
        petRequests: [{
          petId  : petId || undefined,
          petName: petName,
          service: serviceLabel
        }],
        pets: [{
          petId  : petId || undefined,
          petName: petName,
          done   : false,
          hasConsult: false
        }],
        idemKey,
        source  : 'doctor_auto_followup',
        createdAt: new Date()
      }
    },
    { upsert: true }
  );
}

function findServiceForPet(res, pet) {
  // Prefer per-pet requests (new flow)
  if (Array.isArray(res.petRequests) && res.petRequests.length) {
    // First try by ObjectId string
    const pid = pet?.petId ? String(pet.petId) : null;
    let pr = null;
    if (pid) pr = res.petRequests.find(x => String(x.petId) === pid);
    // Fallback: match by name (for walk-ins / legacy)
    if (!pr) pr = res.petRequests.find(x => x.petName === pet.petName);
    if (pr && pr.service) return pr.service;
  }
  // Legacy single-service fallback
  return res.service || '—';
}
// Validation middleware helper
function validateRequest(schema, property = 'body') {
  return (req, res, next) => {
    const { error } = schema.validate(req[property]);
    if (error) {
      console.error("Validation error:", error.details[0].message);
      return res.status(400).json({ message: error.details[0].message });
    }
    next();
  };
}

// Schema for routes that require reservationId (in either body or query)
const reservationIdSchema = Joi.object({
  reservationId: Joi.string().required()
});

const addConsultationSchema = Joi.object({
  reservationId: Joi.string().required(),
  consultationNotes: Joi.string().optional().allow(""),
  examWeight: Joi.string().optional().allow(""),
  examTemperature: Joi.string().optional().allow(""),
  examOthers: Joi.string().optional().allow(""),
  diagnosis: Joi.string().optional().allow(""),
  disease: Joi.string().optional().allow(""),
  diseasesData: Joi.string().optional().allow(""),   // <-- add this
  notes: Joi.string().optional().allow(""),
  medicationsData: Joi.string().optional().allow(""),
  servicesData: Joi.string().optional().allow("")
}).unknown(true);


// Schema for adding a follow-up schedule
// addScheduleSchema
const addScheduleSchema = Joi.object({
  reservationId: Joi.string().required(),
  scheduleDate: Joi.date().required(),
  scheduleDetails: Joi.string().required(),
  scheduleTime: Joi.string().optional().allow('') // 'HH:MM AM/PM'
});
// (A) Per-hour limit for the UI (used to label options as "Full")
// FINAL PATH AT RUNTIME: /doctor/settings/appointmentLimit
router.get('/settings/appointmentLimit', authMiddleware, async (req, res) => {
  try {
    const s = await AppointmentSetting.findOne().lean();
    res.json({ limit: Number(s?.limitPerHour ?? 0) });
  } catch {
    res.json({ limit: 0 }); // 0 = unlimited
  }
});

// (B) Count pets already booked for a specific date+time
// FINAL PATH AT RUNTIME: /doctor/consult/appointmentCount
router.get('/consult/appointmentCount', authMiddleware, async (req, res) => {
  try {
    const { date, time } = req.query;
    if (!date || !time) return res.json({ count: 0 });

    const { start, end } = dayBoundsUTC(date);
    const hits = await Reservation.find({
      date  : { $gte: start, $lte: end },
      time  : time,
      status: { $nin: ['Canceled', 'Rejected'] }
    }).select('petRequests').lean();

    let count = 0;
    for (const r of hits) {
      count += Array.isArray(r.petRequests) && r.petRequests.length
        ? r.petRequests.length
        : 1;
    }
    res.json({ count });
  } catch {
    res.json({ count: 0 });
  }
});

// -------------------------
// Existing Routes (dashboard, patient, history, profile, etc.)
// -------------------------

// Render Doctor Dashboard with Appointments and Follow-Ups
router.get("/d-dashboard", authMiddleware, async (req, res) => {
  try {
    const now = new Date();
    const totalAppointments = await Reservation.countDocuments({ doctor: req.user.userId });
    const doneAppointments = await Reservation.countDocuments({ doctor: req.user.userId, status: 'Done' });
    const upcomingAppointments = await Reservation.find({
      doctor: req.user.userId,
      status: { $ne: 'Done' },
      "schedule.scheduleDate": { $gte: now }
    }).lean();
    const followUps = await Reservation.find({
      doctor: req.user.userId,
      status: 'Done',
      "schedule.scheduleDate": { $gte: now }
    }).lean();
    const appointmentsOverTime = await buildAppointmentsOverTimeData(req.user.userId);
    res.render("doctor/d-dashboard", {
      doctor: { userId: req.user.userId, username: req.user.username },
      totalAppointments,
      doneAppointments,
      upcomingAppointments,
      followUps,
      appointmentsOverTime
    });
  } catch (error) {
    console.error("Error rendering doctor dashboard:", error);
    res.status(500).send("Server error");
  }
});

// Helper function for appointments data
async function buildAppointmentsOverTimeData(doctorId) {
  const today = new Date();
  today.setHours(23, 59, 59, 999);
  const past7Days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    past7Days.push(d);
  }
  const data = [];
  for (let d of past7Days) {
    const start = new Date(d);
    start.setHours(0, 0, 0, 0);
    const end = new Date(d);
    end.setHours(23, 59, 59, 999);
    const count = await Reservation.countDocuments({
      doctor: doctorId,
      createdAt: { $gte: start, $lte: end }
    });
    data.push({ label: d.toISOString().slice(0, 10), count });
  }
  return data;
}
// doctors subscribe here for real-time updates
router.get('/stream', authMiddleware, (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no' // if behind nginx
  });

  // some Node/Express versions expose flushHeaders; call if present
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  // let EventSource know to retry after 1s if disconnected
  res.write('retry: 1000\n\n');

  // register this open connection in hrSse.js
  addClient(res);

  // clean up on disconnect
  req.on('close', () => removeClient(res));
});

// GET /doctor/d-patient
// GET /doctor/d-patient  (REPLACED)
// GET /doctor/d-patient
// GET /doctor/d-patient  (UPDATED: show services from Consultation in table)
// GET /doctor/d-patient  (SHOW service from Consultation; fallback to per-pet schedule; then to requested service)
// GET /doctor/d-patient  — supports admin "view as" via ?doctorId=...
router.get('/d-patient', authMiddleware, async (req, res) => {
  try {
    const role    = String(req.user?.role || '').toLowerCase();
    const isAdmin = role === 'admin';

    // Decide which doctor's list to show
    const qDoctorId = String(req.query.doctorId || '').trim();
    let effectiveDoctorId = isAdmin
      ? (qDoctorId || '')
      : String(req.user?._id || req.user?.userId || '');

    // Fallback for admin with no doctorId: pick the first doctor
    if (isAdmin && !effectiveDoctorId) {
      const firstDoc = await User.findOne({ role: /doctor/i })
        .select('_id username')
        .lean();
      if (firstDoc) effectiveDoctorId = String(firstDoc._id);
    }

    // Resolve effective doctor name
    let effectiveDoctorName = String(req.user?.username || '');
    if (isAdmin && effectiveDoctorId) {
      const picked = await User.findById(effectiveDoctorId).select('username').lean();
      if (picked) effectiveDoctorName = picked.username;
    }

    // Query reservations for that doctor (support ObjectId or string) & skip canceled
    const docObjId = mongoose.Types.ObjectId.isValid(effectiveDoctorId)
      ? new mongoose.Types.ObjectId(effectiveDoctorId)
      : null;

    const reservations = await Reservation.find({
      status: { $ne: 'Canceled' },
      $or: [{ doctor: docObjId }, { doctor: String(effectiveDoctorId) }]
    })
      .populate('pets.petId', 'petName birthday')
      .lean();

    const resvIds = reservations.map(r => String(r._id));

    // Consultations to mark hasConsultation & derive service names from consult
    const consults = await Consultation.find({
      reservation: { $in: resvIds }
    })
      .select('reservation targetPetId targetPetName services')
      .lean();

    const serviceByKey = new Map(); // `${resId}::id::${petId}` or `...::name::${petNameLower}`
    const consultedKey = new Set();

    const extractNames = arr =>
      Array.isArray(arr)
        ? arr
            .map(s => (s?.serviceName || s?.name || s?.service?.name || s?.service?.serviceName || '').trim())
            .filter(Boolean)
        : [];

    for (const c of (consults || [])) {
      const resId = String(c.reservation);
      const label = [...new Set(extractNames(c.services))].join(', ');
      if (c.targetPetId) {
        const k = `${resId}::id::${String(c.targetPetId)}`;
        consultedKey.add(k);
        if (label) serviceByKey.set(k, label);
      }
      if (c.targetPetName) {
        const k = `${resId}::name::${String(c.targetPetName).toLowerCase()}`;
        consultedKey.add(k);
        if (label) serviceByKey.set(k, label);
      }
    }

    // Build table rows
    const rows = [];
    for (const r of reservations) {
      for (const p of (r.pets || [])) {
        if (p?.done) continue; // skip completed pets

        const petObj   = p.petId || p;
        const pid      = petObj?._id ? String(petObj._id) : '';
        const petName  = petObj?.petName || p.petName || '';
        const nameKey  = petName.toLowerCase();
        const keyById  = `${String(r._id)}::id::${pid}`;
        const keyByNm  = `${String(r._id)}::name::${nameKey}`;

        // 1) Service from consultation (most specific)
        const consultedSvc =
          serviceByKey.get(keyById) || serviceByKey.get(keyByNm) || null;

        // 2) Service from schedule (if any)
        const scheduledSvc =
          p?.schedule?.service?.name || p?.schedule?.scheduleDetails || '';

        // 3) Requested service as last fallback
        let requestedSvc = r.service || '—';
        if (Array.isArray(r.petRequests) && r.petRequests.length) {
          const pidStr = p?.petId ? String(p.petId) : null;
          let pr = null;
          if (pidStr) pr = r.petRequests.find(x => String(x.petId) === pidStr);
          if (!pr)    pr = r.petRequests.find(x => x.petName === p.petName);
          if (pr?.service) requestedSvc = pr.service;
        }

        const finalService =
          consultedSvc || scheduledSvc || requestedSvc || '—';

        const hasConsultation =
          p.hasConsult === true ||
          consultedKey.has(keyById) ||
          consultedKey.has(keyByNm);

        rows.push({
          reservationId   : String(r._id),
          ownerName       : r.ownerName || '',
          petId           : pid,
          petName         : petName || '—',
          service         : finalService,
          petSchedule     : p.schedule || null,
          hasConsultation,
          resStatus       : r.status || '',
          petDone         : !!p.done
        });
      }
    }

    // Data for modals (services/diseases)
    const serviceCategories = await ServiceCategory.find({}).lean();
    const settings = await PetDetailsSetting.findOne().lean();

    let simpleServices = [];
    if (Array.isArray(settings?.services) && settings.services.length) {
      simpleServices = settings.services
        .map(s => (typeof s === 'string'
          ? s
          : (s?.name || s?.serviceName || s?.title || s?.label || s?.value || '').toString()))
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b));
    } else {
      simpleServices = (await Service.distinct('serviceName'))
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b));
    }

    const diseases = Array.isArray(settings?.diseases)
      ? [...settings.diseases].filter(Boolean).sort((a,b)=>a.localeCompare(b))
      : [];

    // JSON mode (used by admin "Load" button)
    if (String(req.query.format || '').toLowerCase() === 'json') {
      return res.json({
        success: true,
        rows,
        serviceCategories,
        simpleServices,
        diseases,
        doctor: { userId: String(effectiveDoctorId), username: effectiveDoctorName }
      });
    }

    // EJS mode
    let doctors = [];
    if (isAdmin) {
      doctors = await User.find({ role: /doctor/i })
        .select('_id username')
        .sort({ username: 1 })
        .lean();
    }

    return res.render('doctor/d-patient', {
      rows,
      serviceCategories,
      simpleServices,
      diseases,
      doctor: { userId: String(effectiveDoctorId), username: effectiveDoctorName },
      isAdminView   : isAdmin,
      activeDoctorId: String(effectiveDoctorId),
      doctors
    });

  } catch (err) {
    console.error('Error fetching assigned patients:', err);
    res.status(500).send('Server error');
  }
});


// Render Doctor History Page
router.get("/d-history", authMiddleware, async (req, res) => {
  try {
    const history = await Reservation.find({
      doctor: req.user.userId,
      status: 'Done'
    }).populate('doctor', 'username').lean();
    res.render("doctor/d-history", { history });
  } catch (error) {
    console.error("Error fetching history:", error);
    res.status(500).send("Server error");
  }
});

// Render Doctor Profile Page
router.get("/d-profile", authMiddleware, (req, res) => {
  res.render("doctor/d-profile", {
    doctor: { userId: req.user.userId, username: req.user.username }
  });
});

// Mark a Reservation as Done and Update Pet Details
// POST /doctor/mark-done
// expects: reservationId, petId
// POST /doctor/mark-done  (per-pet; supports petId OR petName; auto-finish reservation if all pets done)
// POST /doctor/mark-done
// POST /doctor/mark-done  (per-pet; supports petId OR petName; auto-creates/keeps follow-up without time flipping)
router.post('/mark-done', authMiddleware, async (req, res) => {
  try {
    const { reservationId, petId, petName } = req.body;
    if (!reservationId || (!petId && !petName)) {
      return res.status(400).json({
        success: false,
        message: 'reservationId + (petId or petName) are required'
      });
    }

    // --- mark the specific pet as done ---
    let selector;
    if (petId) {
      const rid = mongoose.Types.ObjectId.isValid(reservationId)
        ? new mongoose.Types.ObjectId(reservationId)
        : reservationId;
      const pid = mongoose.Types.ObjectId.isValid(petId)
        ? new mongoose.Types.ObjectId(petId)
        : petId;
      selector = { _id: rid, 'pets.petId': pid };
    } else {
      selector = { _id: reservationId, 'pets.petName': petName };
    }

    const result = await Reservation.updateOne(selector, { $set: { 'pets.$.done': true } });
    if ((result.matchedCount ?? result.n) === 0) {
      return res.status(404).json({ success: false, message: 'Reservation or pet not found' });
    }

    // --- re-fetch to compute allDone, and to access pet schedule ---
    const updated = await Reservation.findById(reservationId).lean();
    const allDone = (updated?.pets || []).every(p => !!p.done);

    broadcast({ type: 'reservation:pet-done', reservationId, petId, petName, allDone });

    // ====== helpers for auto-creating the customer follow-up ======
    const TIME_SLOTS = [
      '08:00 AM','09:00 AM','10:00 AM','11:00 AM',
      '12:00 PM','01:00 PM','02:00 PM','03:00 PM','04:00 PM','05:00 PM'
    ];

    // "1:00 pm" -> "01:00 PM"
    function canonTime(label) {
      if (!label) return null;
      const m = String(label).trim().match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
      if (!m) return null;
      let h = parseInt(m[1], 10);
      if (h < 1 || h > 12) return null;
      const mm = m[2];
      const ap = m[3].toUpperCase();
      return String(h).padStart(2,'0') + ':' + mm + ' ' + ap;
    }

    const toISODateKeyUTC = (d) => {
      const z = new Date(d);
      return isNaN(z) ? null : z.toISOString().slice(0,10);
    };
    const dayBoundsUTC = (isoKey) => ({
      start: new Date(isoKey + 'T00:00:00.000Z'),
      end  : new Date(isoKey + 'T23:59:59.999Z')
    });

    async function getPerHourLimit() {
      try {
        const AppointmentSetting = require('../models/appointmentSetting');
        const s = await AppointmentSetting.findOne().lean();
        return Number(s?.limitPerHour || 0); // 0 = unlimited
      } catch { return 0; }
    }

    // ⬇️ UPDATED: can exclude an existing auto-follow-up doc from the count
    async function countPetsBookedForSlot(isoKey, timeLabel, excludeId = null) {
      const { start, end } = dayBoundsUTC(isoKey);
      const q = {
        date  : { $gte: start, $lte: end },
        time  : timeLabel,
        status: { $nin: ['Canceled', 'Rejected'] }
      };
      if (excludeId) q._id = { $ne: excludeId };

      const hits = await Reservation.find(q).select('petRequests').lean();
      let count = 0;
      for (const r of hits) {
        count += (Array.isArray(r.petRequests) && r.petRequests.length) ? r.petRequests.length : 1;
      }
      return count;
    }

    // Create/ensure ONE auto follow-up Reservation for this (reservation, pet, day).
    // - Preserves previously chosen time if it already exists (prevents 8AM fallback).
    // - EXCLUDES existing auto-follow-up doc from capacity counting.
    async function ensureOneAutoFollowup(resvDoc, petObj, dateVal, details, doctorId, preferredTimeRaw) {
      if (!resvDoc || !petObj || !dateVal) return { created: false, time: null };

      const iso = toISODateKeyUTC(dateVal);
      if (!iso) return { created: false, time: null };

      const petIdInner   = petObj?.petId || null;
      const petNameInner = petObj?.petName || (petObj?.petId?.petName) || '';

      const serviceLabel =
        (petObj?.schedule?.service?.name) ||
        (petObj?.schedule?.scheduleDetails) ||
        (details || '') ||
        'Follow-up';

      // timeless key (res + pet + day)
      const baseKey = [
        'AUTO_FOLLOWUP',
        String(resvDoc._id),
        String(petIdInner || petNameInner || 'pet'),
        iso
      ].join('::');

      // Try to find an existing doc by timeless key…
      let existing = await Reservation.findOne({ idemKey: baseKey }).lean();

      // …otherwise fall back to any doctor_auto_followup on the same day for this pet
      if (!existing) {
        const { start, end } = dayBoundsUTC(iso);
        const petMatch = petIdInner
          ? { $or: [{ 'petRequests.petId': petIdInner }, { 'pets.petId': petIdInner }] }
          : { $or: [{ 'petRequests.petName': petNameInner }, { 'pets.petName': petNameInner }] };

        existing = await Reservation.findOne({
          source: 'doctor_auto_followup',
          date: { $gte: start, $lte: end },
          status: { $nin: ['Canceled', 'Rejected'] },
          ...petMatch
        }).lean();
      }

      // Normalize incoming time
      const preferredCanon = (function canonTime(label) {
        if (!label) return null;
        const m = String(label).trim().match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
        if (!m) return null;
        const h = String(parseInt(m[1],10)).padStart(2,'0');
        return `${h}:${m[2]} ${m[3].toUpperCase()}`;
      })(preferredTimeRaw);

      const carryOverCanon =
        (existing && existing.time && TIME_SLOTS.includes(existing.time))
          ? existing.time
          : null;

      const perHour   = await getPerHourLimit();
      const excludeId = existing?._id || null; // ⬅️ exclude self from capacity checks

      // Pick a time
      let chosen = null;
      if (perHour === 0) {
        // unlimited -> keep doctor pick, else keep existing, else unset
        chosen = preferredCanon || carryOverCanon || null;
      } else {
        // limited -> prefer doctor pick, else keep existing, else first available
        const ok = async (t) => (await countPetsBookedForSlot(iso, t, excludeId)) < perHour;

        if (preferredCanon && TIME_SLOTS.includes(preferredCanon) && await ok(preferredCanon)) {
          chosen = preferredCanon;
        } else if (carryOverCanon && await ok(carryOverCanon)) {
          chosen = carryOverCanon;
        } else {
          for (const t of TIME_SLOTS) {
            if (await ok(t)) { chosen = t; break; }
          }
        }
      }

      // Build the write
      const setOnInsert = {
        owner    : resvDoc.owner || null,
        ownerName: resvDoc.ownerName || '',
        date     : new Date(iso),
        status   : 'Pending',
        preferredDoctor: doctorId || null,
        petRequests: [{
          petId  : petIdInner || undefined,
          petName: petNameInner,
          service: serviceLabel
        }],
        pets: [{
          petId  : petIdInner || undefined,
          petName: petNameInner,
          done   : false,
          hasConsult: false
        }],
        idemKey : baseKey,
        source  : 'doctor_auto_followup',
        createdAt: new Date()
      };

      const set = {};
      if (chosen) set.time = chosen; // only overwrite if we actually picked a time

      // Upsert by timeless key
      await Reservation.updateOne(
        { idemKey: baseKey },
        { $set: set, $setOnInsert: setOnInsert },
        { upsert: true }
      );

      // Keep the timeless one, remove other same-day follow-ups for this pet
      try {
        const keeper = await Reservation.findOne({ idemKey: baseKey }).select('_id').lean();
        const { start, end } = dayBoundsUTC(iso);
        const petMatch = petIdInner
          ? { $or: [{ 'petRequests.petId': petIdInner }, { 'pets.petId': petIdInner }] }
          : { $or: [{ 'petRequests.petName': petNameInner }, { 'pets.petName': petNameInner }] };

        await Reservation.deleteMany({
          _id: { $ne: keeper?._id },
          source: 'doctor_auto_followup',
          date: { $gte: start, $lte: end },
          ...petMatch
        });
      } catch (e) {
        console.warn('auto-followup dedupe skipped:', e.message);
      }

      return { created: !existing, time: chosen || carryOverCanon || existing?.time || null };
    }

    // --- if this pet already has a follow-up date, ensure a single customer reservation for it ---
    try {
      const pet = (updated?.pets || []).find(p =>
        (petId && String(p.petId) === String(petId)) ||
        (!petId && petName && String((p.petName || p.petId?.petName || '')).trim().toLowerCase() === String(petName).trim().toLowerCase())
      );

      const hasFollow = pet && pet.schedule && pet.schedule.scheduleDate;
      if (hasFollow) {
           const actingDoctorId =
           String(req.user?.role || '').toLowerCase() === 'admin'
             ? updated.doctor || req.user.userId
            : req.user.userId;
         await ensureOneAutoFollowup(
          updated,
          pet,
          pet.schedule.scheduleDate,
          (pet.schedule.scheduleDetails ||
            (pet.schedule.service && pet.schedule.service.name) || ''),
            actingDoctorId,
          pet.schedule.time // raw -> canon inside
        );
      }
    } catch (e) {
      console.error('auto follow-up booking (mark-done) failed:', e);
    }

    // --- finalize reservation status if all pets done ---
    let finalStatus = updated?.status || '';

    if (allDone) {
      const consults = await Consultation.find({ reservation: reservationId }).lean();

      const isNonEmpty = (c) => {
        const hasMeds   = Array.isArray(c.medications) && c.medications.length > 0;
        const hasSvcs   = Array.isArray(c.services)    && c.services.length > 0;
        const hasDiag   = !!(c.diagnosis && String(c.diagnosis).trim());
        const hasNotes  = !!(c.notes && String(c.notes).trim());
        const hasExam   = !!(c.physicalExam && (c.physicalExam.weight || c.physicalExam.temperature || c.physicalExam.observations));
        const hasFollow = !!(c.scheduleDate || (c.schedule && c.schedule.scheduleDate));
        return hasMeds || hasSvcs || hasDiag || hasNotes || hasExam || hasFollow;
      };

      const nonEmptyCount = consults.filter(isNonEmpty).length;

      if (nonEmptyCount > 0) {
        if (updated.status !== 'Done') {
          await Reservation.updateOne({ _id: reservationId }, { $set: { status: 'Done' } });
          finalStatus = 'Done';
          broadcast({ type: 'reservation:done', reservation: { _id: reservationId } });
        }
      } else {
        if (updated.status !== 'Paid' && updated.status !== 'Canceled') {
          await Reservation.updateOne({ _id: reservationId }, { $set: { status: 'Canceled' } });
          finalStatus = 'Canceled';
          await Consultation.deleteMany({ reservation: reservationId });
          broadcast({ type: 'reservation:canceled', reservation: { _id: reservationId } });
        } else {
          finalStatus = updated.status;
        }
      }
    }

    return res.json({ success: true, allDone, finalStatus });
  } catch (err) {
    console.error('mark-done error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});


// Get Consultation Details for a Reservation
router.get("/get-consultation", authMiddleware, validateRequest(reservationIdSchema, 'query'), async (req, res) => {
  try {
    const { reservationId } = req.query;
    const reservation = await Reservation.findById(reservationId)
      .populate('pets.petId', 'petName birthday')
      .lean();
    if (!reservation) {
      return res.status(404).json({ success: false, message: 'Reservation not found.' });
    }
    res.json({ success: true, reservation });
  } catch (error) {
    console.error("Error fetching consultation details:", error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Updated Add Consultation Details Endpoint
// Using upload.any() with diskStorage to allow file uploads.
// Updated Add Consultation Details Endpoint
// Using upload.any() with diskStorage to allow file uploads.
// POST /doctor/add-consultation  (REPLACED)
router.post(
  "/add-consultation",
  authMiddleware,
  upload.any(),
  validateRequest(addConsultationSchema),
  async (req, res) => {
    try {
   const {
  reservationId,
  consultationNotes,
  examWeight,
  examTemperature,
  examOthers,
  diagnosis,
  disease,            // NEW
  notes,
  medicationsData,
  servicesData,
  // NEW (pass these from your form):
  targetPetId,
  targetPetName,
  // Optional follow-up for THIS pet:
  scheduleDate,
  scheduleDetails
} = req.body;

      const reservation = await Reservation.findById(reservationId);
      if (!reservation) {
        return res.status(404).json({ success: false, message: 'Reservation not found.' });
      }
     const isAdmin = String(req.user?.role || '').toLowerCase() === 'admin';
 if (!isAdmin && reservation.doctor?.toString() !== String(req.user.userId)) {
   return res.status(403).json({ success: false, message: 'Not authorized.' });
 }

      // --- Map uploaded files to serviceId ---
      let fileMap = {};
      if (req.files?.length) {
        req.files.forEach(file => {
          if (file.fieldname.startsWith("serviceFile_")) {
            const serviceId = file.fieldname.split("_")[1];
            fileMap[serviceId] = file.path; // saved under public/consultation/...
          }
        });
      }

      // --- Parse payloads ---
      const medications = medicationsData ? JSON.parse(medicationsData) : [];
      let services = servicesData ? JSON.parse(servicesData) : [];
// NEW: parse diseases array
let diseasesArr = [];
try {
  diseasesArr = req.body.diseasesData ? JSON.parse(req.body.diseasesData) : [];
  if (!Array.isArray(diseasesArr)) diseasesArr = [];
  diseasesArr = diseasesArr.map(s => String(s || '').trim()).filter(Boolean);
} catch (_) {
  diseasesArr = [];
}
      // Enrich services with real category name + file path
      services = await Promise.all(services.map(async svc => {
        const full = await Service.findById(svc.serviceId)
                                  .populate('category', 'name')
                                  .lean();
        return {
          category:    full?.category?.name || 'Uncategorized',
          serviceName: full?.serviceName    || svc.serviceName,
          details:     svc.details || '',
          file:        fileMap[svc.serviceId] || null
        };
      }));

      // --- Resolve target pet (id or name) ---
      const isValidId   = (s) => mongoose.Types.ObjectId.isValid(String(s));
      let finalPetId    = isValidId(targetPetId) ? new mongoose.Types.ObjectId(targetPetId) : null;
      let finalPetName  = targetPetName || '';

      if (!finalPetId && !finalPetName) {
        // try to derive from reservation.pets if your form only posts the pet name field used in the table
        const firstPet = (reservation.pets || [])[0];
        finalPetName   = (firstPet?.petId?.petName) || firstPet?.petName || '';
      }

      if (!finalPetId && finalPetName) {
        // try to find this pet's ObjectId by name within the reservation
        const match = (reservation.pets || []).find(pp => {
          const name = (pp.petId?.petName) || pp.petName || '';
          return name.toLowerCase() === finalPetName.toLowerCase();
        });
        if (match?.petId && isValidId(match.petId)) {
          finalPetId = new mongoose.Types.ObjectId(match.petId);
        }
      }

      // --- Create Consultation ---
      // --- UPSERT (replace) Consultation for this reservation + pet ---
const keyQuery = { reservation: reservationId };
if (finalPetId) keyQuery.targetPetId = finalPetId;
else            keyQuery.targetPetName = finalPetName;

const payload = {
  reservation:       reservationId,
  targetPetId:       finalPetId || null,
  targetPetName:     finalPetName || '',
  consultationNotes,
  physicalExam: { weight: examWeight, temperature: examTemperature, observations: examOthers },
  diagnosis,
  disease: (diseasesArr[0] || disease || ''),  // back-compat
  diseases: diseasesArr,       
  notes,
  medications,
  services,
  confinementStatus: req.body.confinementStatus || []
};

const updatedConsult = await Consultation.findOneAndUpdate(
  keyQuery,
  { $set: payload },
  { new: true, upsert: true, setDefaultsOnInsert: true }
);

// OPTIONAL: clean up any older duplicates for the same reservation+pet
await Consultation.deleteMany({ ...keyQuery, _id: { $ne: updatedConsult._id } });


      // --- Mirror meds/services on Reservation (your existing behavior) ---
reservation.medications = (updatedConsult.medications || []).map(med => ({
  productId:      med.productId,
  medicationName: med.name,
  dosage:         med.dosage,
  remarks:        med.remarks,
  quantity:       med.quantity
}));

reservation.services = services.map(srv => ({
  category:    srv.category,
  serviceName: srv.serviceName,
  details:     srv.details,
  file:        srv.file
}));


      // --- FLAG the exact pet as having a consult + optionally write a per-pet schedule ---
      // Helper: normalize "1:00 pm" -> "01:00 PM"
function canonTime(label) {
  if (!label) return null;
  const m = String(label).trim().match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
  if (!m) return null;
  let h = parseInt(m[1], 10);
  if (h < 1 || h > 12) return null;
  return String(h).padStart(2, '0') + ':' + m[2] + ' ' + m[3].toUpperCase();
}

      let selector;
      if (finalPetId) {
        selector = { _id: reservationId, 'pets.petId': finalPetId };
      } else if (finalPetName) {
        selector = { _id: reservationId, 'pets.petName': finalPetName };
      }

      if (selector) {
        const setObj = { 'pets.$.hasConsult': true };
 if (scheduleDate) {
  const svcName = (req.body.scheduleServiceName || '').trim();
  const tCanon  = canonTime(req.body.scheduleTime);

  setObj['pets.$.schedule'] = {
    scheduleDate:    new Date(scheduleDate),
    scheduleDetails: (scheduleDetails && scheduleDetails.trim()) || svcName || ''
    // (Optionally attach a service object here too, like in /add-schedule)
  };
  if (tCanon) setObj['pets.$.schedule'].time = tCanon;
}


        await Reservation.updateOne(selector, { $set: setObj });
      }

      // (keep legacy reservation-level follow-up if you still use it elsewhere)
      if (scheduleDate && scheduleDetails) {
        reservation.schedule = {
          scheduleDate:   new Date(scheduleDate),
          scheduleDetails
        };
      }

      await reservation.save();
broadcast({ type: 'consultation:upserted', reservationId });
return res.json({ success: true, consultation: updatedConsult });


    } catch (error) {
      console.error("Error adding consultation details:", error);
      res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);




// POST /doctor/add-schedule
// expects: reservationId, petId, scheduleDate (YYYY-MM-DD), scheduleDetails
// POST /doctor/add-schedule  (per-pet; supports petId OR petName)
// Make sure these are at the top of the file (if not already):
// const mongoose = require('mongoose');
// const Reservation = require('../models/reservation');
// POST /doctor/add-schedule
// ADD / REPLACE THIS WHOLE HANDLER
// ADD / UPDATE FOLLOW-UP SCHEDULE (per pet)
// - Persists per-pet schedule { scheduleDate, scheduleDetails, time?, service? }
// - Auto-creates a customer-facing Reservation on the same day/time (if available)
// - Honors the doctor's chosen time first; falls back to next available hour
// ADD / UPDATE FOLLOW-UP SCHEDULE (per pet)
// - Persists per-pet schedule { scheduleDate, scheduleDetails, time?, service? }
// - Auto-creates a customer-facing Reservation on the same day/time (if available)
// - Honors the doctor's chosen time first; falls back to next available hour
// - IMPORTANT: capacity checks EXCLUDE the existing auto-follow-up doc (prevents time flipping)
// ADD / UPDATE FOLLOW-UP SCHEDULE (per pet)
// - Enforces per-hour limit on the EXACT picked time (409 if full)
// - Upserts ONE customer-facing auto follow-up for that pet/day with that time
// - Frees old day’s slot when the date changes
router.post('/add-schedule', authMiddleware, async (req, res) => {
  try {
    const {
      reservationId,
      petId,
      petName,
      scheduleDate,
      scheduleTime,
      scheduleDetails,
      scheduleServiceId,
      scheduleServiceName,
      scheduleCategoryId,
      scheduleCategoryName
    } = req.body;

    if (!reservationId || !scheduleDate || (!petId && !petName)) {
      return res.status(400).json({
        success: false,
        message: 'reservationId + (petId or petName) + scheduleDate are required'
      });
    }

    // ---------- helpers ----------
    const TIME_SLOTS = [
      '08:00 AM','09:00 AM','10:00 AM','11:00 AM',
      '12:00 PM','01:00 PM','02:00 PM','03:00 PM','04:00 PM','05:00 PM'
    ];

    function canonTime(label) {
      if (!label) return null;
      const m = String(label).trim().match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
      if (!m) return null;
      const h = String(parseInt(m[1],10)).padStart(2,'0');
      return `${h}:${m[2]} ${m[3].toUpperCase()}`;
    }

    const toISODateKeyUTC = (d) => {
      const z = new Date(d);
      return isNaN(z) ? null : z.toISOString().slice(0,10);
    };
    const dayBoundsUTC = (isoKey) => ({
      start: new Date(isoKey + 'T00:00:00.000Z'),
      end  : new Date(isoKey + 'T23:59:59.999Z')
    });

    async function getFollowupLimit() {
      try {
        const PetDetailsSettings = require('../models/petDetailsSettings');
        const s = await PetDetailsSettings.findOne().lean();
        return Number(s?.followUpDailyLimit || 0);  // 0 = no cap
      } catch { return 0; }
    }
    async function getPerHourLimit() {
      try {
        const AppointmentSetting = require('../models/appointmentSetting');
        const s = await AppointmentSetting.findOne().lean();
        return Number(s?.limitPerHour || 0); // 0 = unlimited
      } catch { return 0; }
    }
    async function countPetsBookedForSlot(isoKey, timeLabel, excludeId = null) {
      const { start, end } = dayBoundsUTC(isoKey);
      const q = {
        date  : { $gte: start, $lte: end },
        time  : timeLabel,
        status: { $nin: ['Canceled', 'Rejected'] }
      };
      if (excludeId) q._id = { $ne: excludeId };

      const hits = await Reservation.find(q).select('petRequests').lean();
      let count = 0;
      for (const r of hits) {
        count += (Array.isArray(r.petRequests) && r.petRequests.length) ? r.petRequests.length : 1;
      }
      return count;
    }

    // ONE auto follow-up per (resv, pet, day) — time can change on reschedule
    async function ensureOneAutoFollowup(resvDoc, petObj, dateVal, details, doctorId, preferredTimeRaw) {
      if (!resvDoc || !petObj || !dateVal) return { created: false, time: null };

      const iso = toISODateKeyUTC(dateVal);
      if (!iso) return { created: false, time: null };

      const petIdInner   = petObj?.petId || null;
      const petNameInner = petObj?.petName || (petObj?.petId?.petName) || '';

      const serviceLabel =
        (petObj?.schedule?.service?.name) ||
        (petObj?.schedule?.scheduleDetails) ||
        (details || '') ||
        'Follow-up';

      const baseKey = [
        'AUTO_FOLLOWUP',
        String(resvDoc._id),
        String(petIdInner || petNameInner || 'pet'),
        iso
      ].join('::');

      let existing = await Reservation.findOne({ idemKey: baseKey }).lean();

      // Normalize incoming time
      const preferredCanon = canonTime(preferredTimeRaw);
      const carryOverCanon =
        (existing && existing.time && TIME_SLOTS.includes(existing.time))
          ? existing.time
          : null;

      const perHour   = await getPerHourLimit();
      const excludeId = existing?._id || null;

      // Pick a time
      let chosen = null;
      if (perHour === 0) {
        chosen = preferredCanon || carryOverCanon || null;
      } else {
        const ok = async (t) => (await countPetsBookedForSlot(iso, t, excludeId)) < perHour;
        if (preferredCanon && TIME_SLOTS.includes(preferredCanon) && await ok(preferredCanon)) {
          chosen = preferredCanon;
        } else if (carryOverCanon && await ok(carryOverCanon)) {
          chosen = carryOverCanon;
        } else {
          for (const t of TIME_SLOTS) {
            if (await ok(t)) { chosen = t; break; }
          }
        }
      }

      const setOnInsert = {
        owner    : resvDoc.owner || null,
        ownerName: resvDoc.ownerName || '',
        date     : new Date(iso),
        status   : 'Pending',
        preferredDoctor: doctorId || null,
        petRequests: [{
          petId  : petIdInner || undefined,
          petName: petNameInner,
          service: serviceLabel
        }],
        pets: [{
          petId  : petIdInner || undefined,
          petName: petNameInner,
          done   : false,
          hasConsult: false
        }],
        idemKey : baseKey,
        source  : 'doctor_auto_followup',
        createdAt: new Date()
      };

      const set = {};
      if (chosen) set.time = chosen;

      await Reservation.updateOne(
        { idemKey: baseKey },
        { $set: set, $setOnInsert: setOnInsert },
        { upsert: true }
      );

      // Deduplicate same-day extras
      try {
        const keeper = await Reservation.findOne({ idemKey: baseKey }).select('_id').lean();
        const { start, end } = dayBoundsUTC(iso);
        const petMatch = petIdInner
          ? { $or: [{ 'petRequests.petId': petIdInner }, { 'pets.petId': petIdInner }] }
          : { $or: [{ 'petRequests.petName': petNameInner }, { 'pets.petName': petNameInner }] };

        await Reservation.deleteMany({
          _id: { $ne: keeper?._id },
          source: 'doctor_auto_followup',
          date: { $gte: start, $lte: end },
          ...petMatch
        });
      } catch { /* ignore */ }

      return { created: !existing, time: chosen || carryOverCanon || existing?.time || null };
    }

    // ---------- load reservation + pet ----------
    const fresh = await Reservation.findById(reservationId).lean();
    if (!fresh) return res.status(404).json({ success: false, message: 'Reservation not found.' });

    const pet = (fresh.pets || []).find(p =>
      (petId && String(p.petId) === String(petId)) ||
      (!petId && petName && String(p.petName || '').trim().toLowerCase() === String(petName || '').trim().toLowerCase())
    );
    if (!pet) return res.status(404).json({ success: false, message: 'Pet not found in reservation.' });

    const newISO = toISODateKeyUTC(scheduleDate);
    if (!newISO) return res.status(400).json({ success: false, message: 'Invalid scheduleDate.' });

    const prevISO  = pet.schedule?.scheduleDate ? toISODateKeyUTC(pet.schedule.scheduleDate) : null;
    const prevTime = pet.schedule?.time || pet.schedule?.scheduleTime || null;
    const tCanon   = canonTime(scheduleTime);

    // ---------- daily follow-up limit (only if switching day) ----------
    const dayLimit = await getFollowupLimit();
    if (dayLimit > 0 && newISO !== prevISO) {
      const { start, end } = dayBoundsUTC(newISO);
      const agg = await Reservation.aggregate([
        { $unwind: '$pets' },
        { $match: { 'pets.schedule.scheduleDate': { $gte: start, $lte: end } } },
        { $count: 'n' }
      ]);
      const dayCount = agg.length ? Number(agg[0].n || 0) : 0;
      if (dayCount >= dayLimit) {
        return res.status(409).json({ success: false, message: 'Selected date is full (daily limit reached).' });
      }
    }

    // ---------- per-hour limit on EXACT picked time ----------
    const perHour = await getPerHourLimit();
    if (perHour > 0 && tCanon && TIME_SLOTS.includes(tCanon)) {
      // compute baseKey to find existing auto follow-up (exclude it from the count)
      const petIdInner   = pet?.petId || null;
      const petNameInner = pet?.petName || (pet?.petId?.petName) || '';
      const baseKey = [
        'AUTO_FOLLOWUP',
        String(fresh._id),
        String(petIdInner || petNameInner || 'pet'),
        newISO
      ].join('::');
      const existingAuto = await Reservation.findOne({ idemKey: baseKey }).select('_id').lean();
      const used = await countPetsBookedForSlot(newISO, tCanon, existingAuto?._id || null);
      if (used >= perHour) {
        return res.status(409).json({ success: false, message: `Selected time (${tCanon}) is full. Pick another slot.` });
      }
    }

    // ---------- build per-pet schedule payload ----------
    const chosenName = (scheduleServiceName || '').trim();
    const schedulePayload = {
      scheduleDate   : new Date(scheduleDate),
      scheduleDetails: (scheduleDetails && scheduleDetails.trim()) || chosenName || ''
    };
    if (tCanon) {
      schedulePayload.time = tCanon;
      schedulePayload.scheduleTime = tCanon; // back-compat alias
    }
    if (scheduleServiceId || chosenName) {
      schedulePayload.service = {
        id          : scheduleServiceId || null,
        name        : chosenName || '',
        categoryId  : scheduleCategoryId || null,
        categoryName: scheduleCategoryName || ''
      };
    }

    // reschedule metadata
    const changedDate = !!(prevISO && prevISO !== newISO);
    const changedTime = (tCanon || '') !== (prevTime || '');
    if (changedDate || changedTime) {
      schedulePayload.rescheduled = {
        fromDate: pet?.schedule?.scheduleDate || null,
        fromTime: prevTime || null,
        toDate  : schedulePayload.scheduleDate,
        toTime  : tCanon || null,
        at      : new Date(),
        by      : req.user?.userId || req.user?._id || null
      };
    }

    const selector = petId
      ? { _id: reservationId, 'pets.petId': petId }
      : { _id: reservationId, 'pets.petName': petName };

    const result = await Reservation.updateOne(
      selector,
      { $set: { 'pets.$.schedule': schedulePayload } }
    );
    if ((result.matchedCount ?? result.n) === 0) {
      return res.status(404).json({ success: false, message: 'Pet not found in reservation.' });
    }

    // If date changed, free old day’s slot (remove that day’s auto follow-up)
    if (prevISO && prevISO !== newISO) {
      const { start: prevStart, end: prevEnd } = dayBoundsUTC(prevISO);
      const petMatch = petId
        ? { $or: [{ 'petRequests.petId': petId }, { 'pets.petId': petId }] }
        : { $or: [{ 'petRequests.petName': petName }, { 'pets.petName': petName }] };
      await Reservation.deleteMany({
        source: 'doctor_auto_followup',
        date: { $gte: prevStart, $lte: prevEnd },
        status: { $nin: ['Canceled', 'Rejected'] },
        ...petMatch
      });
    }

    // maintain reservation.schedule (earliest per-pet)
    const after = await Reservation.findById(reservationId).lean();
    const petSchedules = (after?.pets || []).map(p => p.schedule).filter(s => s && s.scheduleDate);
    if (petSchedules.length) {
      petSchedules.sort((a, b) => new Date(a.scheduleDate) - new Date(b.scheduleDate));
      await Reservation.updateOne({ _id: reservationId }, { $set: { schedule: petSchedules[0] } });
    } else {
      await Reservation.updateOne({ _id: reservationId }, { $unset: { schedule: '' } });
    }

    // Ensure ONE customer reservation for that day/time
    let autoBooked = { date: newISO, time: null };
    try {
      const targetPetForAuto = (after.pets || []).find(p =>
        (petId && String(p.petId) === String(petId)) ||
        (!petId && petName && String((p.petName || p.petId?.petName || '')).trim().toLowerCase() === String(petName).trim().toLowerCase())
      );
      const actingDoctorId =
        String(req.user?.role || '').toLowerCase() === 'admin'
          ? after.doctor || req.user.userId
          : req.user.userId;

      const { created, time } = await ensureOneAutoFollowup(
        after,
        targetPetForAuto,
        schedulePayload.scheduleDate,
        schedulePayload.scheduleDetails || (schedulePayload.service && schedulePayload.service.name) || '',
        actingDoctorId,
        schedulePayload.time // raw; normalized inside
      );
      if (created || time) autoBooked.time = time || null;
    } catch (e) {
      console.error('auto follow-up booking (add-schedule) failed:', e);
    }

    // SSE: repaint doctor calendar right away
    try {
      const iso = newISO;
      const payload = {
        type: 'followup:scheduled',
        payload: {
          iso,
          time: schedulePayload?.time || null,
          service: (schedulePayload?.service?.name) || schedulePayload?.scheduleDetails || null
        }
      };
      // Broadcast to connected doctor UIs
      try { broadcast(payload); } catch {}
      // If you also have an admin stream, keep your existing admin event if needed:
      if (global.sendAdminEvent) global.sendAdminEvent(payload);
    } catch (e) {
      console.warn('SSE broadcast failed (non-fatal):', e);
    }

    return res.json({ success: true, saved: schedulePayload, autoBooked });

  } catch (err) {
    console.error('add-schedule error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});



// List Services by Category
router.get("/services/listByCategory", authMiddleware, async (req, res) => {
  try {
    const { categoryId } = req.query;
    if (!categoryId) {
      return res.json({ success: false, message: "Category ID is required." });
    }
    const services = await Service.find({ category: categoryId }).lean();
    res.json({ success: true, services });
  } catch (error) {
    console.error("Error fetching services by category:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// List Inventory Categories
router.get("/inventory/categories", authMiddleware, async (req, res) => {
  try {
    const categories = await Inventory.distinct("category");
    res.json({ success: true, categories });
  } catch (error) {
    console.error("Error fetching inventory categories:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// List Inventory Items by Category
router.get("/inventory/listByCategory", authMiddleware, async (req, res) => {
  try {
    const { category } = req.query;
    if (!category) {
      return res.json({ success: false, message: "Category is required." });
    }
    const products = await Inventory.find({ category: category }).lean();
    res.json({ success: true, products });
  } catch (error) {
    console.error("Error fetching inventory items by category:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// NEW: Endpoint to Check Inventory Quantity for a Product
router.get("/inventory/checkQuantity", authMiddleware, async (req, res) => {
  try {
    const { product } = req.query;
    if (!product) {
      return res.status(400).json({ success: false, message: "Product is required." });
    }
    // Find the inventory item by product name
    const inventoryItem = await Inventory.findOne({ name: product }).lean();
    if (!inventoryItem) {
      return res.status(404).json({ success: false, message: "Product not found in inventory." });
    }
    res.json({ success: true, availableQty: inventoryItem.quantity });
  } catch (error) {
    console.error("Error checking inventory quantity:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
// GET /doctor/consultation/one?reservationId=...&petId=...&petName=...
// GET /doctor/consultation/one?reservationId=...&petId=...&petName=...
router.get('/consultation/one', authMiddleware, async (req, res) => {
  try {
    const { reservationId, petId, petName } = req.query;
    if (!reservationId) {
      return res.status(400).json({ success: false, message: 'reservationId required' });
    }

    // Try to resolve a petId from the name if needed
    let targetPetId = petId || null;
    if (!targetPetId && petName) {
      const r = await Reservation.findById(reservationId)
        .populate('pets.petId','petName')
        .lean();
      const m = r?.pets?.find(p => (p.petId?.petName || p.petName) === petName);
      if (m?.petId?._id) targetPetId = String(m.petId._id);
    }

    // First try id
    let q = { reservation: reservationId };
    if (targetPetId) q.targetPetId = targetPetId;

    let c = await Consultation.findOne(q).sort({ updatedAt: -1, _id: -1 }).lean();

    // Fallback: try by name if nothing found
    if (!c && petName) {
      c = await Consultation.findOne({
        reservation: reservationId,
        targetPetName: petName
      }).sort({ updatedAt: -1, _id: -1 }).lean();
    }

    return res.json({ success: true, consultation: c || null });
  } catch (e) {
    console.error('consultation/one error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
// --- Utilities ---
// --- Utilities ---
function escapeRegExp(s = '') { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// GET /doctor/get-pet-history?petId=... OR ?petName=...&ownerName=...
router.get('/get-pet-history', authMiddleware, async (req, res) => {
  try {
    const { petId, petName, ownerName, reservationId } = req.query;


    if (!petId && !petName) {
      return res.status(400).json({ success: false, message: 'petId or petName required' });
    }

    const isOid = s => mongoose.Types.ObjectId.isValid(String(s));
    const asOid = s => new mongoose.Types.ObjectId(String(s));
    const nameRx = petName ? new RegExp('^' + escapeRegExp(petName) + '$', 'i') : null;
function pickConcerns(resv, consultDoc){
  try{
    if (Array.isArray(resv?.petRequests) && resv.petRequests.length){
      const pid   = consultDoc?.targetPetId || consultDoc?.petId;
      const pname = String(consultDoc?.targetPetName || consultDoc?.petName || '')
                      .trim().toLowerCase();

      let pr = null;
      if (pid)   pr = resv.petRequests.find(x => String(x.petId) === String(pid));
      if (!pr && pname) pr = resv.petRequests.find(
        x => String(x.petName || '').trim().toLowerCase() === pname
      );
      return pr?.concerns || '';
    }
    return resv?.concerns || '';
  }catch(_){ 
    return resv?.concerns || ''; 
  }
}

    let consults = [];

    // ---------- CASE A: lookup by petId (supports legacy + new fields) ----------
    if (petId && isOid(petId)) {
      const oid = asOid(petId);
      consults = await Consultation.find({
        $or: [
          { targetPetId: oid }, // new field
          { petId: oid }        // legacy field
        ]
      })
      .sort({ updatedAt: -1, _id: -1 })
      .lean();
    } else {
      // ---------- CASE B: lookup by petName ----------
      // 1) Find reservations that contain this pet name (and match ownerName if provided)
      const resvs = await Reservation.find({
        ...(ownerName ? { ownerName } : {}),
        'pets.petName': nameRx
      })
      .select('_id pets')
      .lean();

      if (!resvs.length) {
        return res.json({ success: true, history: [] });
      }

      const resvIds = resvs.map(r => r._id);

      // 2) Collect the ObjectIds of pets whose name matches, for id-based consult docs
      const matchingPetIds = [];
      for (const r of resvs) {
        for (const p of (r.pets || [])) {
          const n = (p.petId?.petName || p.petName || '');
          if (nameRx.test(n) && p.petId && isOid(p.petId)) {
            matchingPetIds.push(asOid(p.petId));
          }
        }
      }

      // 3) Pull consultations for those reservations, matching by:
      //    - targetPetName (new)
      //    - petName (legacy)
      //    - targetPetId (new) in the matched ids
      //    - petId (legacy) in the matched ids
      const orParts = [{ targetPetName: nameRx }, { petName: nameRx }];
      if (matchingPetIds.length) {
        orParts.push({ targetPetId: { $in: matchingPetIds } });
        orParts.push({ petId: { $in: matchingPetIds } });
      }

      consults = await Consultation.find({
        reservation: { $in: resvIds },
        $or: orParts
      })
      .sort({ updatedAt: -1, _id: -1 })
      .lean();
    }

    // ---------- Build response records (+doctor + per-pet next schedule) ----------
    const resCache = new Map();
    async function loadReservation(id) {
      const key = String(id);
      if (resCache.has(key)) return resCache.get(key);
      const r = await Reservation.findById(id)
        .populate('doctor', 'username')
        .lean();
      resCache.set(key, r);
      return r;
    }

    const history = [];
    for (const c of consults) {
      const r = await loadReservation(c.reservation);

    const record = {
  date: c.updatedAt || c.createdAt,
  doctor: r?.doctor || null,
  notes: c.notes || c.consultationNotes || '',
  physical: {
    weight:       c.physicalExam?.weight || '',
    temperature:  c.physicalExam?.temperature || '',
    observations: c.physicalExam?.observations || ''
  },
  // ✅ include diseases (array) with back-compat to single `disease`
  diseases: (
    Array.isArray(c.diseases) ? c.diseases
    : (c.disease ? [c.disease] : [])
  ).map(s => String(s || '').trim()).filter(Boolean),
  services: (Array.isArray(c.services) ? c.services : []).map(s => ({
    category:    s.category || 'Uncategorized',
    serviceName: s.serviceName || '',
    details:     s.details || '',
    file:        s.file || null
  })),
  medications: (Array.isArray(c.medications) ? c.medications : []).map(m => ({
    name:     m.name || m.medicationName || '',
    quantity: typeof m.quantity === 'undefined' ? '' : m.quantity,
    dosage:   m.dosage || '',
    remarks:  m.remarks || ''
  })),
  confinement: Array.isArray(c.confinementStatus) ? c.confinementStatus : [],
  nextSchedule: null,

  // ⬇️ new fields
  reservationId: r?._id || null,
  concerns: pickConcerns(r, c)
};

      // Match per-pet schedule by id or (when not present) by name
      if (r && Array.isArray(r.pets)) {
        const match = r.pets.find(p =>
          (c.targetPetId && String(p.petId) === String(c.targetPetId)) ||
          (!c.targetPetId && (
            // name from consult
            (c.targetPetName && (p.petName || p.petId?.petName || '').toLowerCase() === String(c.targetPetName).toLowerCase()) ||
            // or name filter if we came via petName
            (nameRx && nameRx.test(p.petId?.petName || p.petName || ''))
          ))
        );
        if (match && match.schedule) {
          record.nextSchedule = {
            date:    match.schedule.scheduleDate,
            details: (match.schedule.service && match.schedule.service.name) ||
                     match.schedule.scheduleDetails || ''
          };
        }
      }

      history.push(record);
    }

 // newest first
history.sort((a, b) => new Date(b.date) - new Date(a.date));

// pick a header concern for THIS visit (if reservationId was provided)
// pick a header concern for THIS visit (if reservationId was provided)
let headerConcerns = '';
if (reservationId) {
  const h = history.find(h => String(h.reservationId) === String(reservationId));
  if (h && h.concerns) headerConcerns = h.concerns;

  // Fallback: no history yet → derive concern from this reservation's petRequests
  if (!headerConcerns) {
    try {
      const resv = await Reservation.findById(reservationId).lean();
      if (resv) {
        const isOid = s => mongoose.Types.ObjectId.isValid(String(s));
        const asOid = s => new mongoose.Types.ObjectId(String(s));
        const qPetId   = req.query.petId && isOid(req.query.petId) ? String(asOid(req.query.petId)) : null;
        const qPetName = (req.query.petName || '').trim().toLowerCase();

        let pr = null;
        if (Array.isArray(resv.petRequests)) {
          if (qPetId) {
            pr = resv.petRequests.find(x => String(x.petId) === qPetId);
          }
          if (!pr && qPetName) {
            pr = resv.petRequests.find(x => String((x.petName || '')).trim().toLowerCase() === qPetName);
          }
        }

        headerConcerns = (pr?.concerns || resv.concerns || '').trim();
      }
    } catch (_e) { /* noop, keep empty */ }
  }
}

return res.json({ success: true, history, headerConcerns });

  } catch (err) {
    console.error('get-pet-history error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// POST /doctor/save-consult-flag  (sets pets.$.hasConsult = true)
router.post('/save-consult-flag', authMiddleware, async (req, res) => {
  try {
    const { reservationId, petId, petName } = req.body;
    if (!reservationId || (!petId && !petName)) {
      return res.status(400).json({ success: false, message: 'reservationId + (petId or petName) required' });
    }
    let selector;
    if (petId) {
      const rid = mongoose.Types.ObjectId.isValid(reservationId) ? new mongoose.Types.ObjectId(reservationId) : reservationId;
      const pid = mongoose.Types.ObjectId.isValid(petId) ? new mongoose.Types.ObjectId(petId) : petId;
      selector = { _id: rid, 'pets.petId': pid };
    } else {
      selector = { _id: reservationId, 'pets.petName': petName };
    }
    const upd = await Reservation.updateOne(selector, { $set: { 'pets.$.hasConsult': true } });
    if ((upd.matchedCount ?? upd.n) === 0) return res.status(404).json({ success: false, message: 'Pet not found' });
    res.json({ success: true });
  } catch (e) {
    console.error('save-consult-flag error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
// GET /doctor/settings/diseasesBySpecies?reservationId=...&petId=...&petName=...
router.get('/settings/diseasesBySpecies', authMiddleware, async (req, res) => {
  try {
    const { reservationId, petId, petName } = req.query;
    if (!reservationId) {
      return res.status(400).json({ success: false, message: 'reservationId required' });
    }

    // Load reservation with pets populated enough to see names/species if available
    const reservation = await Reservation.findById(reservationId)
      .populate('pets.petId', 'petName species')
      .lean();

    if (!reservation) {
      return res.status(404).json({ success: false, message: 'Reservation not found' });
    }

    // Resolve species: prefer the specific pet’s species; fall back to reservation.species (walk-in new pet)
    let species = null;

    if (petId) {
      const entry = (reservation.pets || []).find(p => String(p.petId?._id || '') === String(petId));
      species = entry?.petId?.species || null;
    } else if (petName) {
      const entry = (reservation.pets || []).find(p => {
        const n = p.petId?.petName || p.petName || '';
        return n.trim().toLowerCase() === petName.trim().toLowerCase();
      });
      species = entry?.petId?.species || null;
    }

    // Walk-in new pet case (no petId): reservation-level species
    if (!species && reservation.isExistingPet === false) {
      species = reservation.species || null;
    }

    // Pull settings and pick per-species list or fallback global
    const settings = await PetDetailsSetting.findOne().lean();
    let list = [];

    if (settings) {
      if (species && settings.speciesDiseases && Array.isArray(settings.speciesDiseases[species])) {
        list = settings.speciesDiseases[species];
      } else if (Array.isArray(settings.diseases)) {
        list = settings.diseases; // global fallback
      }
    }

    // Clean + sort
    const diseases = [...new Set((list || [])
      .map(s => (typeof s === 'string' ? s.trim() : ''))
      .filter(Boolean))].sort((a,b) => a.localeCompare(b));

    return res.json({ success: true, species: species || null, diseases });
  } catch (e) {
    console.error('diseasesBySpecies error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET /doctor/followup/stats?year=YYYY&month=1..12
// (C) Month stats for calendar (drives red "Full" days)
// FINAL PATH AT RUNTIME: /doctor/followup/stats
// GET /doctor/followup/stats?year=YYYY&month=1..12
// GET /doctor/followup/stats?year=YYYY&month=1..12
router.get('/followup/stats', authMiddleware, async (req, res) => {
  try {
    const year  = parseInt(req.query.year, 10);
    const month = parseInt(req.query.month, 10); // 1..12
    if (!year || !month) return res.json({ limit: 0, counts: {} });

    // Month bounds in UTC
    const start = new Date(Date.UTC(year, month - 1, 1, 0, 0, 0, 0));
    const end   = new Date(Date.UTC(year, month,     0, 23, 59, 59, 999));

    // Doctor filter (accepts ObjectId or string stored in doc)
    const docIdStr = String(req.user?._id || req.user?.userId || '');
    const docObjId = mongoose.Types.ObjectId.isValid(docIdStr)
      ? new mongoose.Types.ObjectId(docIdStr)
      : null;

    // Count each PET that has a follow-up day within the month, for THIS doctor
    const pipeline = [
      {
        $match: {
          status: { $ne: 'Canceled' },
          $or: [{ doctor: docObjId }, { doctor: docIdStr }],
          'pets.schedule.scheduleDate': { $gte: start, $lte: end }
        }
      },
      { $unwind: '$pets' },
      {
        $match: {
          'pets.schedule.scheduleDate': { $gte: start, $lte: end }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: {
              date: '$pets.schedule.scheduleDate',
              format: '%Y-%m-%d',
              timezone: 'UTC'
            }
          },
          cnt: { $sum: 1 }
        }
      }
    ];

    const rows = await Reservation.aggregate(pipeline);
    const counts = {};
    rows.forEach(r => { counts[r._id] = r.cnt; });

    // Optional daily capacity (0 = unlimited).
    // Uses AppointmentSetting.limitPerHour * TIME_SLOTS.length if you want it.
    let limitPerHour = 0;
    try {
      const s = await AppointmentSetting.findOne().lean();
      limitPerHour = Number(s?.limitPerHour ?? 0);
    } catch { /* ignore */ }
    const dailyLimit = limitPerHour > 0 ? limitPerHour * TIME_SLOTS.length : 0;

    return res.json({ limit: dailyLimit, counts });
  } catch (e) {
    console.error('followup/stats error:', e);
    return res.json({ limit: 0, counts: {} });
  }
});

// === Follow-up day list (table rows) ===
// GET /doctor/followup/list?date=YYYY-MM-DD
// === Follow-up day list (table rows) ===
// GET /doctor/followup/list?date=YYYY-MM-DD
router.get('/followup/list', authMiddleware, async (req, res) => {
  try {
    const iso = String(req.query.date || '').slice(0, 10);
    if (!iso) return res.json({ items: [], dayCount: 0 });

    // doctor filter (supports ObjectId or string id stored in doc field)
    const docIdStr = String(req.user?._id || req.user?.userId || '');
    const docObjId = mongoose.Types.ObjectId.isValid(docIdStr)
      ? new mongoose.Types.ObjectId(docIdStr)
      : null;

    const dayStart = new Date(iso + 'T00:00:00.000Z');
    const dayEnd   = new Date(iso + 'T23:59:59.999Z');

    // Pull reservations assigned to this doctor with any pet scheduled on this date
    const reservations = await Reservation.find({
      status: { $ne: 'Canceled' },
      $or: [{ doctor: docObjId }, { doctor: docIdStr }],
      'pets.schedule.scheduleDate': { $gte: dayStart, $lte: dayEnd }
    })
      .populate('pets.petId', 'petName')   // so we can emit real petName + petId
      .select('ownerName pets')            // only the fields we need
      .lean();

    const items = [];

    for (const r of reservations || []) {
      for (const p of (r.pets || [])) {
        const sch = p?.schedule;
        if (!sch?.scheduleDate) continue;

        // keep only rows that land exactly on the requested UTC day
        const schISO = new Date(sch.scheduleDate).toISOString().slice(0, 10);
        if (schISO !== iso) continue;

        const time = sch.scheduleTime || sch.time || ''; // allow empty -> '—' in UI
        const service =
          (sch.service && (sch.service.name || sch.service.serviceName)) ||
          sch.scheduleDetails || '—';

        items.push({
          reservationId: String(r._id),
          petId: p?.petId?._id ? String(p.petId._id) : null,
          petName: (p?.petId?.petName || p?.petName || '—'),
          ownerName: r.ownerName || '—',
          dateISO: iso,
          time,
          service,
          status: 'Scheduled'
        });
      }
    }

    // sort by time, empty times last
    function toMinutes(t) {
      if (!t) return Number.POSITIVE_INFINITY;
      const m = t.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
      if (!m) return Number.POSITIVE_INFINITY;
      let h = parseInt(m[1], 10);
      const min = parseInt(m[2], 10) || 0;
      const ap = m[3].toUpperCase();
      if (ap === 'PM' && h !== 12) h += 12;
      if (ap === 'AM' && h === 12) h = 0;
      return h * 60 + min;
    }
    items.sort((a, b) => toMinutes(a.time) - toMinutes(b.time));

    return res.json({ items, dayCount: items.length });
  } catch (e) {
    console.error('followup/list error:', e);
    return res.json({ items: [], dayCount: 0 });
  }
});


// Render Doctor Upcoming Page (shell loads this partial)
router.get("/d-upcoming", authMiddleware, async (req, res) => {
  try {
    res.render("doctor/d-upcoming", {
      doctor: { userId: req.user.userId, username: req.user.username }
    });
  } catch (e) {
    console.error("Error rendering d-upcoming:", e);
    res.status(500).send("Server error");
  }
});
// POST /doctor/notify-reservation
// EXPECTS: { reservationId, templateId?, message?, emailMessage?, interactive?, reason? }
router.post('/notify-reservation', authMiddleware, async (req, res) => {
  try {
    const { reservationId, templateId, message, emailMessage, interactive, reason, emailOnly } = req.body;

    if (!reservationId || (!templateId && !message)) {
      return res.json({ success: false, message: 'Missing inputs.' });
    }

    const reservation = await Reservation.findById(reservationId)
      .populate('owner', '_id username email')
      .lean();
    if (!reservation) {
      return res.json({ success: false, message: 'Reservation not found.' });
    }

    let inAppText = (message || '').trim();
    if (!inAppText && templateId) {
      const tmpl = await MessageTemplate.findById(templateId).lean();
      if (!tmpl) return res.json({ success: false, message: 'Template not found.' });
      inAppText = String(tmpl.body || '').trim();
    }
    if (!inAppText) {
      return res.json({ success: false, message: 'No message text.' });
    }

    const emailText = (emailMessage && String(emailMessage).trim()) || inAppText;

    const isEmailOnly =
      String(reason || '').toLowerCase() === 'resched' ||
      emailOnly === true ||
      String(emailOnly).toLowerCase() === 'true';

    const subject =
      String(reason || '').toLowerCase() === 'doctor_unavailable'
        ? 'Doctor unavailable — quick action'
        : 'Appointment Update';

    let msgDocId = null;
    if (!isEmailOnly) {
      const msgDoc = await ReservationMessage.create({
        reservation: reservation._id,
        toOwner: reservation.owner?._id || undefined,
        ownerName: reservation.ownerName || reservation.owner?.username || '',
        body: inAppText,
        templateId: templateId || undefined,
        status: 'sent'
      });
      msgDocId = String(msgDoc._id);

      const io = req.app.get('io');
      if (io) {
        io.to(`reservation:${reservation._id}`).emit('reservation:notify', {
          id: msgDocId,
          reservationId: String(reservation._id),
          text: inAppText,
          interactive: !!interactive,
          reason: reason || null
        });
      }
    }

    const toEmail =
      (reservation.owner && reservation.owner.email) ||
      reservation.contactEmail ||
      null;

    let emailSent = false, emailError = null;
    if (toEmail) {
      try {
        const transport = getBrevoTransport();
        if (transport) {
          const fromEmail = process.env.SENDER_EMAIL || process.env.SMTP_EMAIL;
          const fromName  = process.env.SENDER_NAME  || 'SmartVet Clinic';
          await transport.sendMail({
            from: `${fromName} <${fromEmail}>`,
            to: toEmail,
            subject,
            text: emailText,
            html: `<p>${esc(emailText).replace(/\n/g,'<br>')}</p>`
          });
          emailSent = true;
        } else {
          emailError = 'SMTP not configured';
        }
      } catch (err) {
        console.error('[Doctor notify] email failed:', err);
        emailError = err.message || 'sendMail failed';
      }
    }

    return res.json({
      success: true,
      message: 'Sent.',
      id: msgDocId,                        // null when emailOnly
      inApp: { skipped: isEmailOnly },
      email: { attempted: !!toEmail, sent: emailSent, error: emailError }
    });
  } catch (e) {
    console.error('doctor/notify-reservation error:', e);
    return res.status(500).json({ success: false, message: 'Failed to send.' });
  }
});


module.exports = router;
