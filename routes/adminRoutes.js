// adminRoutes.js
const express = require("express");
const path = require("path");
const multer = require("multer");
const adminController = require("../controllers/adminController");
const DashboardSetting = require('../models/dashboardSetting');
const Joi = require('joi');
const Inventory = require("../models/inventory");
const router = express.Router();
const Service = require("../models/service");
const ServiceCategory = require("../models/serviceCategory");
const mongoose = require("mongoose");
const Payment = require('../models/Payment');
const PetList = require('../models/petlist');
const salesReportController = require("../controllers/salesReportController");
// ⬇️ Add this line near the top of adminRoutes.js with other requires
const PetDetailsSetting = require('../models/petDetailsSetting'); 
// <-- use the ACTUAL filename/casing
const Pet = require('../models/pet');
const clinicAnalytics = require('../controllers/clinicAnalyticsController');
// ⬇️ add these
const Reservation = require('../models/reservation');
const { addClient, removeClient } = require('../utils/hrSse'); // reuse your SSE hub
const PetDetailsSettings = require('../models/petDetailsSettings');
const Consultation = require('../models/consultation');
const StaffWeeklyShift = require('../models/staffWeeklyShift');
const MessageTemplate = require('../models/messageTemplate');
const User               = require('../models/user'); // for doctor picker
// ⬇️ add this (use the same path/name you use elsewhere)
const authMiddleware = require('../middleware/authMiddleware');
const { getPetHistory } = require('../controllers/petHistory');
const AppointmentSetting = require('../models/appointmentSetting');
const Operating = require('../models/operating'); // <— ADD THIS
const fs = require('fs');             // add if not present
const archiver = require('archiver'); // <-- add this

// ⬇️ add under: const authMiddleware = require('../middleware/authMiddleware');
const roleOf = req => String(req?.user?.role || '').toLowerCase();
const allow = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).send('Login required');
  const ok = roles.map(r => String(r).toLowerCase()).includes(roleOf(req));
  if (!ok) return res.status(403).send('Forbidden');
  next();
};

// If a doctor opens /admin/patient, send them to their page instead of 403
const adminOrRedirectDoctor = (req, res, next) => {
  const role = roleOf(req);
  if (role === 'doctor') return res.redirect('/doctor/d-patient');
  if (role !== 'admin')  return res.status(403).send('Forbidden');
  next();
};
// ADD after your profile image multer config (or near top, once `multer` is available)
// Receipts upload storage (make sure folder exists: /public/receipts)
const receiptsStorage = multer.diskStorage({
  destination: function (_req, _file, cb) {
    cb(null, path.join(__dirname, '../public/receipts'));
  },
  filename: function (_req, file, cb) {
    const safe = file.originalname.replace(/\s+/g, '_');
    cb(null, Date.now() + '-' + safe);
  }
});
const uploadReceipts = multer({
  storage: receiptsStorage,
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB per file, adjust as needed
  fileFilter: (_req, file, cb) => {
    const ok = /^(image\/(png|jpe?g|gif|webp)|application\/pdf)$/.test(file.mimetype);
    cb(ok ? null : new Error('Only images or PDF are allowed'), ok);
  }
});

// Consultation files go to /public/consultation
const consultStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/consultation/');
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + Date.now() + ext);
  }
});
const consultUpload = multer({ storage: consultStorage });

// ---- Inventory expiry helpers ----
function splitByToday(dates) {
  const arr = Array.isArray(dates) ? dates.map(d => new Date(d)) : [];
  const today = new Date(); today.setHours(0,0,0,0);
  const stillGood = [], newlyExpired = [];
  for (const d of arr) (d <= today ? newlyExpired : stillGood).push(d);
  return { stillGood, newlyExpired };
}
const notifTemplateSchema = Joi.object({
  type: Joi.string().valid('notif', 'notify', 'declined').required(),
  title: Joi.string().trim().min(2).required(),
  body: Joi.string().trim().min(2).required(),
  isDefault: Joi.boolean().optional()
});

const notifTemplateUpdateSchema = Joi.object({
  type: Joi.string().valid('notif', 'notify', 'declined').optional(),
  title: Joi.string().trim().min(2).optional(),
  body: Joi.string().trim().min(2).optional(),
  isDefault: Joi.boolean().optional()
});

// Moves expired per-unit dates into expiredDates[], bumps expiredCount,
// and DECREASES quantity by newlyExpired.length (never below 0).
async function rollExpiredAndDeductOne(doc) {
  if (!doc) return null;
  const { stillGood, newlyExpired } = splitByToday(doc.expirationDates);
  if (!newlyExpired.length) return doc; // nothing to roll

  const updated = await Inventory.findByIdAndUpdate(
    doc._id,
    {
      $set: {
        expirationDates: stillGood,
        quantity: Math.max(0, Number(doc.quantity || 0) - newlyExpired.length),
      },
      $push: { expiredDates: { $each: newlyExpired } },
      $inc: { expiredCount: newlyExpired.length }
    },
    { new: true }
  ).lean();

  return updated;
}

// Helper middleware for validating request bodies
function validateRequest(schema) {
  return (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    next();
  };
}
// === Upcoming helper: flatten pet-level schedules WITH status (past 30d..next 60d) ===
// === Upcoming helper: flatten pet-level schedules WITH status (past 30d..next 60d) ===
async function getUpcomingFollowUps() {
  const now = new Date();
  const todayStart = new Date(now); todayStart.setHours(0,0,0,0);

  // helper: YYYY-MM-DD in LOCAL time
  function ymdLocal(d) {
    const x = new Date(d);
    const y = x.getFullYear();
    const m = String(x.getMonth() + 1).padStart(2, '0');
    const dd = String(x.getDate()).padStart(2, '0');
    return `${y}-${m}-${dd}`;
  }

  // Window you can tweak:
  const start = new Date(todayStart); start.setDate(start.getDate() - 30);
  const end   = new Date(todayStart); end.setDate(end.getDate() + 60);

  // Pull reservations that have a pet-level schedule within the window
  const resvs = await Reservation.find({
    status: { $ne: 'Canceled' },
    'pets.schedule.scheduleDate': { $exists: true, $gte: start, $lte: end }
  })
    .populate('doctor', 'username')
    .populate('pets.petId', 'petName')
    .lean();

  // Flatten entries
  const entries = [];
  const resvIds = new Set();

  for (const r of (resvs || [])) {
    resvIds.add(String(r._id));
    for (const p of (r.pets || [])) {
      const s = p?.schedule;
      if (!s || !s.scheduleDate) continue;

      const d = new Date(s.scheduleDate);
      if (isNaN(d)) continue;
      if (d < start || d > end) continue;

      const isoLocal = ymdLocal(d);
      const petName = p?.petId?.petName || p?.petName || '';
      const svc = (s.service && s.service.name) || s.scheduleDetails || '—';

      entries.push({
        dateISO: isoLocal,          // LOCAL day key
        date: d,                    // Date object
        ownerName: r.ownerName || '',
        petName,
        service: svc,
        doctor: r?.doctor?.username || '—',
        reservationId: String(r._id),
        petId: p?.petId?._id ? String(p.petId._id) : null,
        status: 'Scheduled'         // will finalize below
      });
    }
  }

  if (!entries.length) return { entries: [], counts: {} };

  // ===== Build "consult happened that (local) day" index =====
  const consults = await Consultation.find({
    reservation: { $in: Array.from(resvIds) },
    $or: [
      { createdAt: { $gte: start, $lte: new Date(end.getTime() + 24*60*60*1000) } },
      { updatedAt: { $gte: start, $lte: new Date(end.getTime() + 24*60*60*1000) } }
    ]
  })
  .select('reservation targetPetId targetPetName createdAt updatedAt')
  .lean();

  const consultedKey = new Set();
  for (const c of (consults || [])) {
    const rid = String(c.reservation);
    const when = c.createdAt || c.updatedAt || new Date();
    const dayISO = ymdLocal(when);

    const idKey   = c.targetPetId ? String(c.targetPetId) : null;
    const nameKey = (c.targetPetName || '').trim().toLowerCase();

    if (idKey)   consultedKey.add(`${rid}::id::${idKey}::${dayISO}`);
    if (nameKey) consultedKey.add(`${rid}::name::${nameKey}::${dayISO}`);
  }

  // ===== Compute status per entry (Done immediately; Not Attended after noon local) =====
  for (const e of entries) {
    const idKey   = e.petId ? `${e.reservationId}::id::${e.petId}::${e.dateISO}` : null;
    const nameKey = `${e.reservationId}::name::${(e.petName||'').trim().toLowerCase()}::${e.dateISO}`;

    const done =
      (idKey   && consultedKey.has(idKey)) ||
      (nameKey && consultedKey.has(nameKey));

    if (done) {
      e.status = 'Done';
    } else {
      const entryDayStart = new Date(e.date); entryDayStart.setHours(0,0,0,0);
      const entryNoon     = new Date(e.date); entryNoon.setHours(12,0,0,0);

      if (entryDayStart < todayStart) {
        // any past day with no consult → Not Attended
        e.status = 'Not Attended';
      } else if (ymdLocal(now) === e.dateISO && now >= entryNoon) {
        // today and already past 12:00 local → Not Attended
        e.status = 'Not Attended';
      } else {
        e.status = 'Scheduled';
      }
    }
  }

  // counts per date (for calendar heat)
  const counts = {};
  for (const e of entries) counts[e.dateISO] = (counts[e.dateISO] || 0) + 1;

  // Sort by date then owner
  entries.sort((a,b) => a.date - b.date || a.ownerName.localeCompare(b.ownerName));

  return { entries, counts };
}

// Define schemas for input validation
const createAccountSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  role: Joi.string().valid("Doctor", "HR").required(),
});

const resetAccountSchema = Joi.object({
  userId: Joi.string().required(),
  newEmail: Joi.string().email().optional().allow(''),
  newPassword: Joi.string().min(8).optional().allow(''),
});

const deleteAccountSchema = Joi.object({
  userId: Joi.string().required()
});

const updateOtpSettingSchema = Joi.object({
  userId: Joi.string().required(),
  otpEnabled: Joi.boolean().required()
});

// Configure Multer storage for profile image uploads.
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Make sure "public/uploads" folder exists
    cb(null, path.join(__dirname, "../public/uploads"));
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, "profile-" + Date.now() + ext);
  }
});
const upload = multer({ storage });

// -------------------- Admin API Endpoints --------------------

// Create Account route with input validation
router.post(
  "/create-account",
  validateRequest(createAccountSchema),
  adminController.createAccount
);

// Get accounts, reset account, delete account
router.get("/api/accounts", adminController.getAccounts);
router.put("/reset-account", validateRequest(resetAccountSchema), adminController.resetAccount);
router.delete("/delete-account", validateRequest(deleteAccountSchema), adminController.deleteAccount);
router.get("/profile/:userId", adminController.getAccountProfile);

// Update OTP Verification Setting for Admin
router.post(
  "/update-otp-setting",
  validateRequest(updateOtpSettingSchema),
  adminController.updateOTPSetting
);

// -------------------- Admin View Routes --------------------
router.get("/dashboard", (req, res) => {
  res.render("dashboard");
});
router.get("/accounts-view", (req, res) => {
  res.render("accounts");
});
// In adminRoutes.js, update the profile view route:
router.get("/profile", async (req, res) => {
  try {
    // For example, if the admin's email is known:
    const adminUser = await require("../models/user").findOne({ email: "smartvetclinic17@gmail.com" }).lean();
    if (!adminUser) {
      return res.status(404).send("Admin user not found.");
    }
    res.render("profile", { user: adminUser });
  } catch (error) {
    console.error("Error fetching admin profile:", error);
    res.status(500).send("Server error");
  }
});

// Replace your current /petlist route with:
router.get("/petlist", async (req, res) => {
  try {
   const entries = await PetList.find()
  .populate('owner', 'username email cellphone') // <-- add these fields
  .lean();

    res.render("petlist", { entries });
  } catch (err) {
    console.error("Error fetching pet list:", err);
    res.status(500).send("Server error");
  }
});

// REPLACE: /admin/get-pet-history with doctor-compatible version
// /admin/get-pet-history
router.get('/get-pet-history', authMiddleware, allow('admin','doctor','hr'), async (req, res) => {
  try {
    const { petId, petName, ownerName, ownerId, reservationId } = req.query;

    if (!petId && !petName) {
      return res.status(400).json({ success: false, message: 'petId or petName required' });
    }

    const isOid = s => mongoose.Types.ObjectId.isValid(String(s));
    const asOid = s => new mongoose.Types.ObjectId(String(s));
    const esc   = s => String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const nameRx = petName ? new RegExp('^' + esc(petName) + '$', 'i') : null;

    // ---- helper to pick concerns from the reservation/petRequests ----
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
      }catch(_){ return resv?.concerns || ''; }
    }

    // ---- Owner filter for reservations ----
    const ownerQ = {};
    if (ownerId && isOid(ownerId)) {
      ownerQ.$or = [
        { owner: asOid(ownerId) },
        { user:  asOid(ownerId) }
      ];
      if (ownerName) ownerQ.$or.push({ ownerName: new RegExp('^' + esc(ownerName) + '$', 'i') });
    } else if (ownerName) {
      ownerQ.ownerName = new RegExp('^' + esc(ownerName) + '$', 'i');
    }

    // ---- Fast path: explicit petId (a real Pet _id) ----
    let consults = [];
    if (petId && isOid(petId)) {
      consults = await Consultation.find({
        $or: [{ targetPetId: asOid(petId) }, { petId: asOid(petId) }]
      }).sort({ updatedAt: -1, _id: -1 }).lean();
    } else {
      // ---- Name-based search (robust) ----

      // A) Reservations of this owner (don’t filter by petName here)
      const resvsOfOwner = Object.keys(ownerQ).length
        ? await Reservation.find(ownerQ).select('_id').lean()
        : [];
      const resvIds = resvsOfOwner.map(r => r._id);

      // B) Pet ids matching this name (optionally scoped to owner)
      const petFilter = nameRx ? { petName: nameRx } : {};
      if (ownerId && isOid(ownerId)) petFilter.owner = asOid(ownerId);
      const pets = await Pet.find(petFilter).select('_id').lean();
      const matchingPetIds = pets.map(p => p._id);

      // C) Build consult query
      const orParts = [];
      if (nameRx) {
        orParts.push({ targetPetName: nameRx }, { petName: nameRx });
      }
      if (matchingPetIds.length) {
        orParts.push({ targetPetId: { $in: matchingPetIds } });
        orParts.push({ petId:      { $in: matchingPetIds } });
      }

      const q = { $or: orParts };
      if (resvIds.length) q.reservation = { $in: resvIds }; // restrict to this owner's consults if we can

      consults = await Consultation.find(q).sort({ updatedAt: -1, _id: -1 }).lean();
    }

    // ---- Load reservations (to show doctor + nextSchedule + concerns) ----
    const resCache = new Map();
    async function loadReservation(id) {
      const k = String(id);
      if (resCache.has(k)) return resCache.get(k);
      const r = await Reservation.findById(id).populate('doctor','username').lean();
      resCache.set(k, r);
      return r;
    }

    // (optional) small pet payload for header species
    let petDoc = null;
    if (petId && isOid(petId)) {
      petDoc = await Pet.findById(petId).select('petName species').lean();
    }

    const history = [];
    for (const c of consults) {
      const r = await loadReservation(c.reservation);

      // ⬇️ Normalize diagnosis from several possible fields
      const diagnosis = (() => {
        const v = c.diagnosis;
        if (typeof v === 'string' && v.trim()) return v.trim();
        if (Array.isArray(v) && v.length) return v.filter(Boolean).join(', ');
        if (typeof c.provisionalDiagnosis === 'string' && c.provisionalDiagnosis.trim()) return c.provisionalDiagnosis.trim();
        if (typeof c.assessment === 'string' && c.assessment.trim()) return c.assessment.trim();
        if (typeof c.impression === 'string' && c.impression.trim()) return c.impression.trim();
        if (typeof c.dx === 'string' && c.dx.trim()) return c.dx.trim();
        return '';
      })();

      const record = {
        date: c.updatedAt || c.createdAt,
        doctor: r?.doctor || null,
        notes: c.notes || c.consultationNotes || '',
        physical: {
          weight:       c.physicalExam?.weight || '',
          temperature:  c.physicalExam?.temperature || '',
          observations: c.physicalExam?.observations || ''
        },
        diagnosis, // ⬅️ now included
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
        reservationId: r?._id || null,
        concerns: pickConcerns(r, c)
      };

      // next follow-up from that reservation's matching pet (by id or name)
      if (r && Array.isArray(r.pets)) {
        const match = r.pets.find(p =>
          (c.targetPetId && String(p.petId) === String(c.targetPetId)) ||
          (!c.targetPetId && (
            (c.targetPetName && (p.petName || p.petId?.petName || '').toLowerCase() === String(c.targetPetName).toLowerCase()) ||
            (nameRx && nameRx.test(p.petId?.petName || p.petName || ''))
          ))
        );
        if (match?.schedule) {
          record.nextSchedule = {
            date:    match.schedule.scheduleDate,
            details: (match.schedule.service && match.schedule.service.name) ||
                     match.schedule.scheduleDetails || ''
          };
        }
      }

      history.push(record);
    }

    history.sort((a, b) => new Date(b.date) - new Date(a.date));

    // Optional: header concerns from a specific reservation
    let headerConcerns = '';
    if (reservationId) {
      const h = history.find(h => String(h.reservationId) === String(reservationId));
      if (h?.concerns) headerConcerns = h.concerns;
    }

    return res.json({ success: true, pet: petDoc, history, headerConcerns });
  } catch (err) {
    console.error('admin /get-pet-history error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.get("/generate-report", adminController.generateReport);
 router.get("/peak-day-of-week", clinicAnalytics.getPeakDayOfWeek);
router.get("/predict-appointments", clinicAnalytics.predictAppointments);
router.post("/update-profile", upload.single("profilePic"), adminController.updateProfile);

// Dashboard stats
router.get("/get-dashboard-stats", adminController.getDashboardStats);

// Render the Inventory view
router.get("/inventory", (req, res) => {
  res.render("inventory"); // Ensure views/inventory.ejs exists.
});

// API route to list all inventory items
// API route to list all inventory items (auto-roll newly expired first)
router.get("/inventory/list", async (req, res) => {
  try {
    const items = await Inventory.find().lean();

    // Roll expiries in parallel so the result you return is already “deducted”.
    const rolled = await Promise.all(
      items.map(async (i) => {
        const today = new Date(); today.setHours(0,0,0,0);
        const hasNewExpired = (Array.isArray(i.expirationDates) ? i.expirationDates : [])
          .some(d => new Date(d) <= today);
        return hasNewExpired ? await rollExpiredAndDeductOne(i) : i;
      })
    );

    res.json(rolled);
  } catch (error) {
    console.error("Error fetching inventory items", error);
    res.status(500).json({ message: "Error fetching inventory items" });
  }
});


// ─── Add a New Inventory Item ───────────────────────────────────────
router.post("/inventory/add", async (req, res) => {
  try {
    const { name, category, basePrice, markup, quantity, purchaseDate } = req.body;


    const bPrice = parseFloat(basePrice) || 0;
    const mAmt   = parseFloat(markup)    || 0;   // pesos (not percent)
    const qty    = parseInt(quantity, 10) || 0;

    // Selling price = base + markup (both in pesos)
    const finalPrice = Math.round((bPrice + mAmt) * 100) / 100;

    // Parse per-unit expiration dates from the form
    let expirationDates = req.body["expirationDates[]"] || req.body.expirationDates;
    if (expirationDates) {
      if (!Array.isArray(expirationDates)) expirationDates = [expirationDates];
      expirationDates = expirationDates
        .map(s => new Date(s))
        .filter(d => !isNaN(d.getTime()));
    } else {
      expirationDates = [];
    }

    // Split dates into sellable vs already expired (today is considered sellable here;
    // your listing endpoint will auto-roll <= today to expired on next read)
    const today = new Date(); today.setHours(0,0,0,0);
    const validDates = [];
    const alreadyExpired = [];
    for (const d of expirationDates) {
      (d < today ? alreadyExpired : validDates).push(d);
    }

    // Persist SELLABLE quantity only:
    // - if per-unit dates are provided, trust them (count future-dated units)
    // - otherwise, fall back to the entered qty
    const nonExpiredCount = validDates.length > 0
      ? validDates.length
      : Math.max(0, qty - alreadyExpired.length); // usually same as qty if no dates

const newItem = new Inventory({
  name,
  category,
  basePrice:  bPrice,
  markup:     mAmt,
  price:      finalPrice,
  quantity:   nonExpiredCount,
  expirationDates: validDates,
  expiredDates:    alreadyExpired,
  expiredCount:    alreadyExpired.length,
  purchaseDate: purchaseDate ? new Date(purchaseDate) : undefined  // NEW
});


    await newItem.save();
    res.json({ message: "Inventory item added successfully" });
  } catch (error) {
    console.error("Error adding inventory item:", error);
    res.status(500).json({ message: "Error adding inventory item" });
  }
});

// API route to fetch a single inventory item by ID
router.get("/inventory/item/:id", async (req, res) => {
  try {
    const item = await Inventory.findById(req.params.id).lean();
    res.json(item);
  } catch (error) {
    res.status(500).json({ message: "Error fetching inventory item" });
  }
});

// ─── Edit an Inventory Item ─────────────────────────────────────────
router.post("/inventory/edit", async (req, res) => {
  try {
    const { id, name, category, basePrice, markup, quantity, purchaseDate } = req.body;


    const bPrice = parseFloat(basePrice) || 0;
    const mAmt   = parseFloat(markup)    || 0; // pesos
    const qty    = parseInt(quantity, 10) || 0;

    // NEW: peso-based price
    const finalPrice = Math.round((bPrice + mAmt) * 100) / 100;

    // expiration parsing unchanged ...
    let expirationDates = req.body["expirationDates[]"] || req.body.expirationDates;
    if (expirationDates) {
      if (!Array.isArray(expirationDates)) expirationDates = [expirationDates];
      expirationDates = expirationDates
        .map(s => new Date(s))
        .filter(d => !isNaN(d.getTime()));
    } else {
      expirationDates = [];
    }

    const today = new Date(); today.setHours(0,0,0,0);
    const validDates = [], alreadyExpired = [];
    expirationDates.forEach(d => (d < today ? alreadyExpired : validDates).push(d));

    const existing = await Inventory.findById(id).lean();
    if (!existing) return res.status(404).json({ message: "Item not found" });

    const combinedExpiredDates = [
      ...existing.expiredDates.map(d => new Date(d)),
      ...alreadyExpired
    ];
    const newExpiredCount = combinedExpiredDates.length;
await Inventory.findByIdAndUpdate(id, {
  name,
  category,
  basePrice:       bPrice,
  markup:          mAmt,
  price:           finalPrice,
  quantity:        qty,
  expirationDates: validDates,
  expiredDates:    combinedExpiredDates,
  expiredCount:    newExpiredCount,
  ...(purchaseDate ? { purchaseDate: new Date(purchaseDate) } : {})  // NEW
});


    res.json({ message: "Inventory item updated successfully" });
  } catch (error) {
    console.error("Error updating inventory item:", error);
    res.status(500).json({ message: "Error updating inventory item" });
  }
});


// API route to delete an inventory item
router.post("/inventory/delete", async (req, res) => {
  try {
    const { id, expiredOnly } = req.body;
    const expiredOnlyBool = (expiredOnly === true || expiredOnly === 'true');

    if (!expiredOnlyBool) {
      await Inventory.findByIdAndDelete(id);
      return res.json({ message: "Inventory item deleted successfully" });
    }

    // expiredOnly === true → discard only expired units
    const item = await Inventory.findById(id);
    if (!item) return res.status(404).json({ message: "Item not found" });

    const today = new Date();
    today.setHours(0,0,0,0);

    const expDates = Array.isArray(item.expirationDates) ? item.expirationDates : [];
    const alreadyExpired = Array.isArray(item.expiredDates) ? item.expiredDates : [];

    // Anything in expirationDates that is <= today is expired too.
    const expiredFromFuture = expDates.filter(d => {
      const dt = new Date(d); dt.setHours(0,0,0,0);
      return !isNaN(dt) && dt.getTime() <= today.getTime();
    });

    // Keep only still-sellable future dates
    const keepFuture = expDates.filter(d => {
      const dt = new Date(d); dt.setHours(0,0,0,0);
      return !isNaN(dt) && dt.getTime() > today.getTime();
    });

    const numToRemove = alreadyExpired.length + expiredFromFuture.length;

    // Remove expired: clear expiredDates, drop expired ones from expirationDates
    item.expirationDates = keepFuture;
    item.expiredDates = [];    // we "discarded" them
    item.expiredCount = 0;

    // Keep quantity aligned with live units if you’re tracking per-unit dates,
    // otherwise fallback to subtracting
    if (keepFuture.length > 0) {
      item.quantity = keepFuture.length;
    } else {
      item.quantity = Math.max(0, (item.quantity || 0) - numToRemove);
    }

    await item.save();
    return res.json({
      message: `Removed ${numToRemove} expired unit(s) from "${item.name}".`
    });

  } catch (error) {
    console.error('Error deleting inventory (expiredOnly):', error);
    res.status(500).json({ message: "Error deleting inventory item" });
  }
});

// -------------------- Service Category Routes --------------------
router.get("/services/categories/list", async (req, res) => {
  try {
    const categories = await ServiceCategory.find().lean();
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: "Error fetching categories" });
  }
});
router.post("/services/categories/add", async (req, res) => {
  try {
    const { name } = req.body;
    const newCategory = new ServiceCategory({ name });
    await newCategory.save();
    res.json({ message: "Category added successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error adding category" });
  }
});
router.post("/services/categories/delete", async (req, res) => {
  try {
    await ServiceCategory.findByIdAndDelete(req.body.id);
    res.json({ message: "Category deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting category" });
  }
});

// -------------------- Service Item Routes --------------------
// Render the Services view
router.get("/services", (req, res) => {
  res.render("services");
});
router.get("/services/list", async (req, res) => {
  try {
    const services = await Service.find().lean();
    for (let svc of services) {
      if (mongoose.Types.ObjectId.isValid(svc.category)) {
        const cat = await ServiceCategory.findById(svc.category).lean();
        svc.categoryName = cat ? cat.name : "Unknown";
      } else {
        svc.categoryName = "Invalid Category";
      }
    }
    res.json(services);
  } catch (error) {
    console.error("Error fetching services:", error);
    res.status(500).json({ message: "Error fetching services", error: error.message });
  }
});
router.post("/services/add", async (req, res) => {
  try {
    const { category, serviceName, weight, dosage, basePrice, markup } = req.body;

    const b = Number(basePrice || 0);
    const m = Number(markup || 0);
    const finalPrice = Math.round((b + m) * 100) / 100;

    const newService = new Service({
      category,
      serviceName,
      weight,
      dosage,
      basePrice: b,
      markup: m,
      price: finalPrice
    });

    await newService.save();
    res.json({ message: "Service added successfully" });
  } catch (error) {
    console.error("Error adding service:", error);
    res.status(500).json({ message: "Error adding service" });
  }
});

router.get("/services/item/:id", async (req, res) => {
  try {
    const service = await Service.findById(req.params.id).lean();
    res.json(service);
  } catch (error) {
    res.status(500).json({ message: "Error fetching service item" });
  }
});
router.post("/services/edit", async (req, res) => {
  try {
    const { id, category, serviceName, weight, dosage, basePrice, markup } = req.body;

    const b = Number(basePrice || 0);
    const m = Number(markup || 0);
    const finalPrice = Math.round((b + m) * 100) / 100;

    await Service.findByIdAndUpdate(id, {
      category,
      serviceName,
      weight,
      dosage,
      basePrice: b,
      markup: m,
      price: finalPrice
    });

    res.json({ message: "Service updated successfully" });
  } catch (error) {
    console.error("Error updating service:", error);
    res.status(500).json({ message: "Error updating service" });
  }
});

router.post("/services/delete", async (req, res) => {
  try {
    await Service.findByIdAndDelete(req.body.id);
    res.json({ message: "Service deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting service" });
  }
});

router.get('/inventory-stats', adminController.getInventoryStats);

// Sales Report page
router.get("/sales-report", (req, res) => {
  res.render("sales-report");
});

// ─── Shared (Dashboard) data endpoints (keep these on adminController) ───
router.get('/get-categories', adminController.getCategories);
router.get("/get-sales-by-category", adminController.getSalesByCategory);
router.get("/get-sales-by-product",  adminController.getSalesByProduct);
router.get("/get-sales-by-service",  adminController.getSalesByService);
router.get('/expired-products',       adminController.getExpiredProducts);
router.get("/downloadSalesExcel",     adminController.downloadSalesExcel);

router.get("/download-sales-report.pdf", adminController.downloadSalesPDF);
router.get('/get-top-category',       adminController.getTopCategory);

// ─── Namespaced Sales Report endpoints (NO collisions) ────────────────────
router.get("/report/get-sales-kpis",        salesReportController.getSalesKPIs);
router.get("/report/get-sales-by-product",  salesReportController.getSalesByProduct);
router.get("/report/get-sales-by-service",  salesReportController.getSalesByService);
router.get("/report/get-sales-by-category", salesReportController.getSalesByCategory);
router.get("/report/expired-products",      salesReportController.getExpiredProducts);

// (Optional) if you want separate categories endpoint for report:
// router.get("/report/get-categories",        salesReportController.getProductCategories);
router.get('/report/top-profit-items', salesReportController.getTopProfitItems);
router.get('/report/expiring-soon', salesReportController.getExpiringSoon);

// Slow movers (no sales in range)
router.get('/report/slow-movers', salesReportController.getSlowMovers);
// Excel export (filter-aware)
router.get('/report/export-excel', salesReportController.exportExcel);
// ✅ define it without the extra /admin
router.get('/downloadSalesCSV', salesReportController.downloadSalesCSV);

router.get('/categories', adminController.listCategories);
router.post('/categories', adminController.addCategory);
router.patch('/categories/:id', adminController.renameCategory);
router.delete('/categories/:id', adminController.deleteCategory);
// POST /admin/petlist/update-contact
router.post("/petlist/update-contact", async (req, res) => {
  try {
    const { id, contactMobile = "", contactEmail = "", applyToAllSameWalkin = false } = req.body;

    // Find base entry and ensure it's a walk-in (no linked owner)
    const base = await PetList.findById(id).lean();
    if (!base) return res.status(404).json({ success: false, message: "Pet entry not found." });
    if (base.owner) return res.status(400).json({ success: false, message: "Only walk-in pets can edit contact here." });

    const set = {
      contactMobile: (contactMobile || "").trim(),
      contactEmail:  (contactEmail || "").trim()
    };

    if (applyToAllSameWalkin) {
      const ownerName = base.ownerName || ""; // store a label on walk-ins (used in your HR view)
      const filter = { owner: { $exists: false }, ownerName };
      await PetList.updateMany(filter, { $set: set });
    } else {
      await PetList.findByIdAndUpdate(id, { $set: set });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("update-contact error:", err);
    return res.status(500).json({ success: false, message: "Server error updating contact." });
  }
});
// ===== BEGIN: Per-species Disease Routes =====

// GET diseases for a species
router.get('/settings/species-diseases', /*auth,*/ async (req, res) => {
  try {
    const species = (req.query.species || '').trim();
    if (!species) return res.json({ success: true, diseases: [] });
    const doc = await PetDetailsSetting.findOne().lean();
    const list = (doc && doc.speciesDiseases && Array.isArray(doc.speciesDiseases[species]))
      ? doc.speciesDiseases[species]
      : [];
    return res.json({ success: true, species, diseases: list });
  } catch (e) {
    console.error('GET /settings/species-diseases error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ADD disease to species
router.post('/settings/species-disease/add', async (req, res) => {
  try {
    const species = (req.body.species || '').trim();
    const disease = (req.body.disease || '').trim();
    if (!species || !disease) {
      return res.status(400).json({ success: false, message: 'species and disease required' });
    }

    let doc = await PetDetailsSetting.findOne();
    if (!doc) doc = await PetDetailsSetting.create({});

    if (!doc.speciesDiseases) doc.speciesDiseases = {};
    const curr = Array.isArray(doc.speciesDiseases[species]) ? doc.speciesDiseases[species] : [];

    const set = new Map();
    curr.forEach(d => set.set(d.toLowerCase(), d));
    set.set(disease.toLowerCase(), disease);

    doc.speciesDiseases[species] = Array.from(set.values()).sort((a,b) =>
      a.localeCompare(b, undefined, { sensitivity: 'base' })
    );

    // ⬇️ important for Mixed/Object fields
    doc.markModified('speciesDiseases');

    await doc.save();
    return res.json({ success: true, species, diseases: doc.speciesDiseases[species] });
  } catch (e) {
    console.error('POST /settings/species-disease/add error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// DELETE disease from species
router.post('/settings/species-disease/delete', async (req, res) => {
  try {
    const species = (req.body.species || '').trim();
    const disease = (req.body.disease || '').trim();
    if (!species || !disease) {
      return res.status(400).json({ success: false, message: 'species and disease required' });
    }

    const doc = await PetDetailsSetting.findOne();
    if (!doc || !doc.speciesDiseases || !Array.isArray(doc.speciesDiseases[species])) {
      return res.json({ success: true, species, diseases: [] });
    }

    doc.speciesDiseases[species] =
      doc.speciesDiseases[species].filter(d => d.toLowerCase() !== disease.toLowerCase());

    // ⬇️ important for Mixed/Object fields
    doc.markModified('speciesDiseases');

    await doc.save();
    return res.json({ success: true, species, diseases: doc.speciesDiseases[species] });
  } catch (e) {
    console.error('POST /settings/species-disease/delete error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});
router.get("/top-diseases", clinicAnalytics.getTopDiseases);
// === Upcoming page (table + calendar) ===
// NOTE: if your file is views/upcoming.ejs, change 'admin/upcoming' to 'upcoming'
router.get('/upcoming', async (req, res) => {
  try {
    const { entries, counts } = await getUpcomingFollowUps();
   res.render('upcoming', {
  entries,
  upcomingDateCounts: counts
});

  } catch (e) {
    console.error('render /admin/upcoming failed', e);
    res.status(500).send('Server error');
  }
});

// === JSON (optional; client can refresh data) ===
router.get('/api/upcoming', async (req, res) => {
  try {
    const { entries, counts } = await getUpcomingFollowUps();
    res.json({ success: true, entries, counts });
  } catch (e) {
    console.error('GET /admin/api/upcoming failed', e);
    res.json({ success: false });
  }
});

// === SSE stream for live updates from doctor schedules ===
router.get('/stream', (req, res) => {
  res.set({
    'Content-Type'  : 'text/event-stream',
    'Cache-Control' : 'no-cache',
    'Connection'    : 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  if (typeof res.flushHeaders === 'function') res.flushHeaders();
  res.write('retry: 1000\n\n');

  addClient(res);
  req.on('close', () => removeClient(res));
});

// GET current limit
router.get('/followup-limit', authMiddleware, async (req, res) => {
  try {
    const settings = await PetDetailsSettings.getSingleton();
    const limit = Number(settings.followUpDailyLimit || 0);
    res.json({ success: true, limit });
  } catch (e) {
    console.error(e);
    res.json({ success: false, message: 'Failed to load limit' });
  }
});

// POST update limit
router.post('/followup-limit', authMiddleware, async (req, res) => {
  try {
    let v = parseInt(req.body.limit, 10);
    if (Number.isNaN(v) || v < 0) v = 0;
    if (v > 999) v = 999;

    const settings = await PetDetailsSettings.getSingleton();
    settings.followUpDailyLimit = v;
    await settings.save();

    // optional live update to any SSE listeners
    if (typeof broadcast === 'function') {
      broadcast({ type: 'followup:limit-updated', limit: v });
    }

    res.json({ success: true, limit: v });
  } catch (e) {
    console.error(e);
    res.json({ success: false, message: 'Failed to save limit' });
  }
});
// Pet Details settings page
// ---- Pet Details settings page (partial used by SPA) ----
// Works for both /admin/pet-details and /admin/settings/pet-details
router.get(['/pet-details', '/settings/pet-details'], async (req, res) => {
  try {
    console.log('[admin] GET', req.originalUrl);   // helps on Render logs
    let doc = await PetDetailsSetting.findOne().lean();
    if (!doc) doc = { species: [], speciesBreeds: {}, diseases: [], speciesDiseases: {}, services: [] };

    // Prevent CDN/browser from caching a 404/old version
    res.set('Cache-Control', 'no-store');
    return res.render('petdetails', { petDetails: doc });
  } catch (e) {
    console.error('Error rendering pet-details:', e);
    return res.status(500).send('Server error');
  }
});
// ===== BEGIN: Species / Breeds routes =====
router.post('/settings/update-breeds', async (req, res) => {
  try {
    const speciesRaw = (req.body.species || '').trim();
    if (!speciesRaw) {
      return res.status(400).json({ success: false, message: 'species required' });
    }

    // breeds may arrive as a JSON string (from jQuery $.ajax form-encoded)
    let incoming = req.body.breeds;
    if (typeof incoming === 'string') {
      try { incoming = JSON.parse(incoming); } catch (_) { incoming = []; }
    }
    if (!Array.isArray(incoming)) incoming = [];

    // normalize: trim, drop empties, case-insensitive dedupe, sort (case-insensitive)
    const seen = new Map();
    for (const b of incoming) {
      const t = String(b || '').trim();
      if (!t) continue;
      const key = t.toLowerCase();
      if (!seen.has(key)) seen.set(key, t);
    }
    const cleanBreeds = Array.from(seen.values())
      .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

    // fetch or create the singleton settings doc
    let doc = await PetDetailsSetting.findOne();
    if (!doc) doc = await PetDetailsSetting.create({});

    // ensure structures exist
    if (!doc.speciesBreeds || typeof doc.speciesBreeds !== 'object') doc.speciesBreeds = {};
    if (!Array.isArray(doc.species)) doc.species = [];

    // upsert species into species list (case-insensitive check)
    const exists = doc.species.some(s => String(s).toLowerCase() === speciesRaw.toLowerCase());
    if (!exists) {
      doc.species.push(speciesRaw);
      doc.species.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    }

    // set breeds for species
    doc.speciesBreeds[speciesRaw] = cleanBreeds;
    // needed because speciesBreeds is a Mixed/Object field
    doc.markModified('speciesBreeds');

    await doc.save();

    return res.json({ success: true, species: speciesRaw, breeds: cleanBreeds });
  } catch (e) {
    console.error('POST /settings/update-breeds error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});
// ===== END: Species / Breeds routes =====
// Staff Schedule page (renders views/staff-schedule.ejs)
// Staff Schedule page (renders views/staff-schedule.ejs)
router.get("/staff-schedule", (req, res) => {
  res.set('Cache-Control', 'no-store');
  // req.baseUrl is the mount, e.g. '/admin' or '/adm'
  res.render("staff-schedule", { adminBase: req.baseUrl || '/admin' });
});

// List staff (Doctors + HR) for Staff Schedule dropdowns
router.get('/staff/list', async (req, res) => {
  try {
    const roles = (req.query.roles || 'Doctor,HR')
      .split(',')
      .map(r => r.trim())
      .filter(Boolean);

    const User = require('../models/user');
    const staff = await User.find({ role: { $in: roles } })
      .select('_id username email role profilePic')
      .sort({ role: 1, username: 1 })
      .lean();

    res.set('Cache-Control', 'no-store');
    return res.json({ success: true, staff });
  } catch (e) {
    console.error('GET /admin/staff/list error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET weekly grid for a given month (and optional staff filter)
// GET weekly grid for a given month (and optional staff filter)
router.get('/staff-schedule/week', async (req, res) => {
  try {
    const { yearMonth, staffId } = req.query || {};
    if (!yearMonth || !/^\d{4}-(0[1-9]|1[0-2])$/.test(yearMonth)) {
      return res.status(400).json({ success:false, message:'yearMonth (YYYY-MM) is required.' });
    }

    const filter = { active: true, yearMonth };
    if (staffId && mongoose.Types.ObjectId.isValid(staffId)) filter.staff = staffId;

    const shifts = await StaffWeeklyShift.find(filter)
      .populate('staff', 'username role')
      .lean();

    const byStaff = new Map();
    const mm = m => `${String(Math.floor(m/60)).padStart(2,'0')}:${String(m%60).padStart(2,'0')}`;

    for (const s of shifts) {
      if (!s.staff) continue;
      const key = String(s.staff._id);
      if (!byStaff.has(key)) {
        byStaff.set(key, {
          staff: { _id: s.staff._id, username: s.staff.username, role: s.staff.role },
          days: {1:new Map(),2:new Map(),3:new Map(),4:new Map(),5:new Map(),6:new Map(),7:new Map()}
        });
      }
      const row = byStaff.get(key);
      const label = `${mm(s.startMinutes)}–${mm(s.endMinutes)}`;
      row.days[s.weekday].set(`${s.startMinutes}-${s.endMinutes}`, label); // unique key
    }

    const rows = Array.from(byStaff.values()).map(r => {
      const daysOut = {};
      for (let d=1; d<=7; d++) {
        daysOut[d] = Array.from(r.days[d].entries())
          .map(([k,label]) => ({ sort: parseInt(k.split('-')[0],10), label }))
          .sort((a,b)=>a.sort-b.sort)
          .map(x=>x.label);
      }
      return { staff: r.staff, days: daysOut };
    });

    rows.sort((a,b) => (a.staff.role||'').localeCompare(b.staff.role||'') ||
                       (a.staff.username||'').localeCompare(b.staff.username||''));

    res.json({ success:true, rows });
  } catch (e) {
    console.error('GET /admin/staff-schedule/week error:', e);
    res.status(500).json({ success:false, message:'Server error' });
  }
});

// CREATE weekly shifts (used by /js/staff-schedule.js)
router.post('/staff-schedule/create', async (req, res) => {
  try {
    let { staffId, yearMonth, weekdays, startMinutes, endMinutes, note } = req.body || {};

    // --- validate inputs
    if (!staffId || !mongoose.Types.ObjectId.isValid(staffId)) {
      return res.status(400).json({ success: false, message: 'Valid staffId required' });
    }
    if (!yearMonth || !/^\d{4}-(0[1-9]|1[0-2])$/.test(String(yearMonth))) {
      return res.status(400).json({ success: false, message: 'yearMonth must be YYYY-MM' });
    }

    // weekdays may arrive as ["1","2"] or "1,2" or [1,2]
    if (typeof weekdays === 'string') {
      weekdays = weekdays.split(',').map(x => parseInt(x, 10)).filter(n => Number.isInteger(n));
    }
    if (!Array.isArray(weekdays) || weekdays.length === 0) {
      return res.status(400).json({ success: false, message: 'weekdays array required' });
    }
    weekdays = Array.from(
      new Set(weekdays.map(n => parseInt(n, 10)).filter(n => n >= 1 && n <= 7))
    ).sort((a, b) => a - b);
    if (!weekdays.length) {
      return res.status(400).json({ success: false, message: 'No valid weekdays (1..7).' });
    }

    const sMin = Number(startMinutes);
    const eMin = Number(endMinutes);
    if (!Number.isFinite(sMin) || !Number.isFinite(eMin) || !(sMin < eMin)) {
      return res.status(400).json({ success: false, message: 'Invalid time range.' });
    }

    note = String(note || '').trim();

    // --- create (skip overlaps)
    const created = [];
    const skipped = [];

    for (const wd of weekdays) {
      const overlap = await StaffWeeklyShift.hasOverlap(staffId, wd, sMin, eMin, yearMonth);
      if (overlap) {
        skipped.push({ weekday: wd, startMinutes: sMin, endMinutes: eMin, reason: 'overlap' });
        continue;
      }
      const doc = await StaffWeeklyShift.create({
        staff: staffId,
        yearMonth,
        weekday: wd,
        startMinutes: sMin,
        endMinutes: eMin,
        note,
        active: true,
      });
      created.push({ id: String(doc._id), weekday: wd });
    }

    return res.json({ success: true, created, skipped });
  } catch (err) {
    console.error('POST /admin/staff-schedule/create error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// DELETE specific weekdays for a staff + month
// body: { staffId, yearMonth: "YYYY-MM", weekdays: [1..7] }
router.post('/staff-schedule/delete-weekdays', async (req, res) => {
  try {
    let { staffId, yearMonth, weekdays } = req.body || {};

    if (!staffId || !mongoose.Types.ObjectId.isValid(staffId)) {
      return res.status(400).json({ success: false, message: 'Valid staffId required' });
    }
    if (!yearMonth || !/^\d{4}-(0[1-9]|1[0-2])$/.test(String(yearMonth))) {
      return res.status(400).json({ success: false, message: 'yearMonth must be YYYY-MM' });
    }

    // weekdays may arrive as ["1","3"] or "1,3" or [1,3]
    if (typeof weekdays === 'string') {
      weekdays = weekdays.split(',').map(x => parseInt(x, 10)).filter(Number.isFinite);
    }
    if (!Array.isArray(weekdays) || !weekdays.length) {
      return res.status(400).json({ success: false, message: 'weekdays array required' });
    }
    const wdClean = Array.from(
      new Set(
        weekdays
          .map(n => parseInt(n, 10))
          .filter(n => Number.isInteger(n) && n >= 1 && n <= 7)
      )
    );
    if (!wdClean.length) {
      return res.status(400).json({ success: false, message: 'No valid weekdays (1..7).' });
    }

    const result = await StaffWeeklyShift.deleteMany({
      staff: staffId,
      yearMonth,
      weekday: { $in: wdClean },
      active: true
    });

    return res.json({ success: true, deletedCount: Number(result.deletedCount || 0) });
  } catch (e) {
    console.error('POST /admin/staff-schedule/delete-weekdays error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});
// CREATE per-day weekly shifts (different times per weekday)
router.post('/staff-schedule/create-multi', async (req, res) => {
  try {
    let { staffId, yearMonth, dayTimes, note } = req.body || {};

    if (!staffId || !mongoose.Types.ObjectId.isValid(staffId)) {
      return res.status(400).json({ success: false, message: 'Valid staffId required' });
    }
    if (!yearMonth || !/^\d{4}-(0[1-9]|1[0-2])$/.test(String(yearMonth))) {
      return res.status(400).json({ success: false, message: 'yearMonth must be YYYY-MM' });
    }
    if (!Array.isArray(dayTimes) || !dayTimes.length) {
      return res.status(400).json({ success: false, message: 'dayTimes array required' });
    }

    note = String(note || '').trim();

    const created = [];
    const skipped = [];

    for (const dt of dayTimes) {
      const wd   = parseInt(dt.weekday, 10);
      const sMin = Number(dt.startMinutes);
      const eMin = Number(dt.endMinutes);

      if (!(wd >=1 && wd <=7) || !Number.isFinite(sMin) || !Number.isFinite(eMin) || !(sMin < eMin)) {
        skipped.push({ weekday: wd, reason: 'invalid-range' });
        continue;
      }

      const overlap = await StaffWeeklyShift.hasOverlap(staffId, wd, sMin, eMin, yearMonth);
      if (overlap) {
        skipped.push({ weekday: wd, reason: 'overlap' });
        continue;
      }

      const doc = await StaffWeeklyShift.create({
        staff: staffId,
        yearMonth,
        weekday: wd,
        startMinutes: sMin,
        endMinutes: eMin,
        note,
        active: true
      });
      created.push({ id: String(doc._id), weekday: wd });
    }

    return res.json({ success: true, created, skipped });
  } catch (err) {
    console.error('POST /admin/staff-schedule/create-multi error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});
// Notification Templates (view)
router.get('/notification', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.render('notification');
});
// List templates (optional ?type=notif|declined)
router.get('/notifications/templates', async (req, res) => {
  try {
    const rawType = (req.query.type || '').trim().toLowerCase();
    const type = rawType === 'notify' ? 'notif' : rawType;
    const filter = (type && ['notif','declined'].includes(type)) ? { type } : {};
    const list = await MessageTemplate.find(filter)
      .sort({ type: 1, isDefault: -1, updatedAt: -1 })
      .lean();
    res.json({ success: true, list });
  } catch (e) {
    console.error('GET /admin/notifications/templates error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Create template
router.post('/notifications/templates', validateRequest(notifTemplateSchema), async (req, res) => {
  try {
    const payload = { ...req.body };
    if (payload.type === 'notify') payload.type = 'notif';
    const doc = await MessageTemplate.create(payload);
    res.json({ success: true, template: doc });
  } catch (e) {
    console.error('POST /admin/notifications/templates error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Update template
router.put('/notifications/templates/:id', validateRequest(notifTemplateUpdateSchema), async (req, res) => {
  try {
    const payload = { ...req.body };
    if (payload.type === 'notify') payload.type = 'notif';
    const doc = await MessageTemplate.findById(req.params.id);
    if (!doc) return res.status(404).json({ success: false, message: 'Template not found' });

    // Assign fields if provided
    ['type','title','body','isDefault'].forEach(k => {
      if (payload[k] !== undefined) doc[k] = payload[k];
    });

    await doc.save();
    res.json({ success: true, template: doc });
  } catch (e) {
    console.error('PUT /admin/notifications/templates/:id error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Delete template
router.delete('/notifications/templates/:id', async (req, res) => {
  try {
    const result = await MessageTemplate.findByIdAndDelete(req.params.id);
    if (!result) return res.status(404).json({ success: false, message: 'Template not found' });
    res.json({ success: true });
  } catch (e) {
    console.error('DELETE /admin/notifications/templates/:id error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
// Patient page (renders views/patient.ejs)
// Similar to /petlist, but separate page & table

// GET /admin/patient — identical data to /doctor/d-patient, but rendered for admin
// ✅ /admin/patient — admin only (doctors are redirected to /doctor/d-patient)

router.get('/patient', authMiddleware, adminOrRedirectDoctor, async (req, res) => {
  try {
    // 1) Doctor list (case-insensitive)
    const doctors = await User.find({ role: /doctor/i })
      .select('_id username')
      .sort({ username: 1 })
      .lean();

    // No doctors yet — render empty shell so the page still loads
    if (!doctors.length) {
      return res.render('admin/patient', {
        rows: [],
        serviceCategories: [],
        simpleServices: [],
        diseases: [],
        doctor: { userId: '', username: '' },
        isAdminView: true,
        adminBase: req.baseUrl || '/admin',
        activeDoctorId: '',
        doctors
      });
    }

    // 2) Which doctor to show initially (query ?doctorId=… or first in list)
    const effectiveDoctorId = String(req.query.doctorId || doctors[0]._id);
    const picked = doctors.find(d => String(d._id) === String(effectiveDoctorId));
    const effectiveDoctorName = picked ? picked.username : '';

    // 3) Pull that doctor's open reservations (skip Canceled)
    const docObjId = mongoose.Types.ObjectId.isValid(effectiveDoctorId)
      ? new mongoose.Types.ObjectId(effectiveDoctorId)
      : null;

    const reservations = await Reservation.find({
      status: { $ne: 'Canceled' },
      $or: [{ doctor: docObjId }, { doctor: String(effectiveDoctorId) }]
    })
      .populate('pets.petId', 'petName birthday')
      .lean();

    const reservationIds = reservations.map(r => String(r._id));

    // 4) Consultations (for hasConsultation & final service label)
    const consults = await Consultation.find({
      reservation: { $in: reservationIds }
    })
      .select('reservation targetPetId targetPetName services')
      .lean();

    const serviceByKey = new Map();  // `${resId}::id::${petId}` or `...::name::${petNameLower}`
    const consultedKey = new Set();

    const extractNames = (arr) =>
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

    // 5) Build rows for the table (skip pets already marked done)
    const rows = [];
    for (const r of reservations) {
      for (const p of (r.pets || [])) {
        if (p?.done) continue;

        const petObj   = p.petId || p;
        const pid      = petObj?._id ? String(petObj._id) : '';
        const petName  = petObj?.petName || p.petName || '';
        const nameKey  = petName.toLowerCase();

        const keyById  = `${String(r._id)}::id::${pid}`;
        const keyByNm  = `${String(r._id)}::name::${nameKey}`;

        // a) from consultation
        const svcFromConsult =
          serviceByKey.get(keyById) || serviceByKey.get(keyByNm) || null;

        // b) from schedule
        const svcFromSchedule =
          p?.schedule?.service?.name || p?.schedule?.scheduleDetails || '';

        // c) fallback: requested service
        let svcRequested = r.service || '—';
        if (Array.isArray(r.petRequests) && r.petRequests.length) {
          const pidStr = p?.petId ? String(p.petId) : null;
          let pr = null;
          if (pidStr) pr = r.petRequests.find(x => String(x.petId) === pidStr);
          if (!pr)    pr = r.petRequests.find(x => x.petName === p.petName);
          if (pr?.service) svcRequested = pr.service;
        }

        const finalService = svcFromConsult || svcFromSchedule || svcRequested || '—';

        const hasConsultation =
          p.hasConsult === true ||
          consultedKey.has(keyById) ||
          consultedKey.has(keyByNm);

        rows.push({
          reservationId : String(r._id),
          ownerName     : r.ownerName || '',
          petId         : pid,
          petName       : petName || '—',
          service       : finalService,
          petSchedule   : p.schedule || null,
          hasConsultation,
          resStatus     : r.status || '',
          petDone       : !!p.done
        });
      }
    }

    // 6) Modal data: categories, simple services, diseases
    const serviceCategories = await ServiceCategory.find({}).lean();

    const settings = await PetDetailsSetting.findOne().lean();

    let simpleServices = [];
    if (Array.isArray(settings?.services) && settings.services.length) {
      simpleServices = settings.services
        .map(s => (typeof s === 'string'
          ? s.trim()
          : (s?.name || s?.serviceName || s?.title || s?.label || s?.value || '').toString().trim()))
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b));
    } else {
      simpleServices = (await Service.distinct('serviceName'))
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b));
    }

    const diseases = Array.isArray(settings?.diseases)
      ? [...settings.diseases].filter(Boolean).sort((a, b) => a.localeCompare(b))
      : [];

    // 7) Render admin view (patient.ejs includes doctor/d-patient + admin picker)
    return res.render('admin/patient', {
      rows,
      serviceCategories,
      simpleServices,
      diseases,
      doctor: { userId: String(effectiveDoctorId), username: effectiveDoctorName },
      isAdminView   : true,
      adminBase     : req.baseUrl || '/admin',
      activeDoctorId: String(effectiveDoctorId),
      doctors
    });

  } catch (err) {
    console.error('Error rendering /admin/patient', err);
    res.status(500).send('Server error');
  }
});
// Admin JSON data for the doctor table (used by patient.ejs "Load" button)
router.get('/patient-data', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const effectiveDoctorId = String(req.query.doctorId || '').trim();
    if (!effectiveDoctorId) {
      return res.status(400).json({ success: false, message: 'doctorId is required' });
    }

    // doctor name (optional)
    const doc = await User.findOne({ _id: effectiveDoctorId }).select('username').lean();
    const effectiveDoctorName = doc ? doc.username : '';

    // open reservations for that doctor (skip Canceled; skip done pets later)
    const docObjId = mongoose.Types.ObjectId.isValid(effectiveDoctorId)
      ? new mongoose.Types.ObjectId(effectiveDoctorId)
      : null;

    const reservations = await Reservation.find({
      status: { $ne: 'Canceled' },
      $or: [{ doctor: docObjId }, { doctor: effectiveDoctorId }]
    })
      .populate('pets.petId', 'petName birthday')
      .lean();

    const reservationIds = reservations.map(r => String(r._id));

    // consultations for service labels + hasConsultation
    const consults = await Consultation.find({
      reservation: { $in: reservationIds }
    })
      .select('reservation targetPetId targetPetName services')
      .lean();

    const serviceByKey = new Map(); // `${resId}::id::${petId}` or `...::name::${petNameLower}`
    const consultedKey = new Set();

    const extractNames = (arr) =>
      Array.isArray(arr)
        ? arr.map(s => (s?.serviceName || s?.name || s?.service?.name || s?.service?.serviceName || '').trim())
             .filter(Boolean)
        : [];

    for (const c of consults) {
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

    const rows = [];
    for (const r of reservations) {
      for (const p of (r.pets || [])) {
        if (p?.done) continue;

        const petObj  = p.petId || p;
        const pid     = petObj?._id ? String(petObj._id) : '';
        const petName = petObj?.petName || p.petName || '';
        const nameKey = petName.toLowerCase();

        const keyById   = `${String(r._id)}::id::${pid}`;
        const keyByName = `${String(r._id)}::name::${nameKey}`;

        const svcFromConsult  = serviceByKey.get(keyById) || serviceByKey.get(keyByName) || null;
        const svcFromSchedule = p?.schedule?.service?.name || p?.schedule?.scheduleDetails || '';

        // requested service fallback
        let svcRequested = r.service || '—';
        if (Array.isArray(r.petRequests) && r.petRequests.length) {
          const pidStr = p?.petId ? String(p.petId) : null;
          let pr = null;
          if (pidStr) pr = r.petRequests.find(x => String(x.petId) === pidStr);
          if (!pr)    pr = r.petRequests.find(x => x.petName === p.petName);
          if (pr?.service) svcRequested = pr.service;
        }

        const finalService = svcFromConsult || svcFromSchedule || svcRequested || '—';

        const hasConsultation =
          p.hasConsult === true ||
          consultedKey.has(keyById) ||
          consultedKey.has(keyByName);

        rows.push({
          reservationId : String(r._id),
          ownerName     : r.ownerName || '',
          petId         : pid,
          petName       : petName || '—',
          service       : finalService,
          petSchedule   : p.schedule || null,
          hasConsultation,
          resStatus     : r.status || '',
          petDone       : !!p.done
        });
      }
    }

    // modal dropdown data
    const serviceCategories = await ServiceCategory.find({}).lean();

    const settings = await PetDetailsSetting.findOne().lean();
    let simpleServices = [];
    if (Array.isArray(settings?.services) && settings.services.length) {
      simpleServices = settings.services
        .map(s => (typeof s === 'string'
          ? s.trim()
          : (s?.name || s?.serviceName || s?.title || s?.label || s?.value || '').toString().trim()))
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b));
    } else {
      simpleServices = (await Service.distinct('serviceName'))
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b));
    }

    const diseases = Array.isArray(settings?.diseases)
      ? [...settings.diseases].filter(Boolean).sort((a, b) => a.localeCompare(b))
      : [];

    return res.json({
      success: true,
      rows,
      serviceCategories,
      simpleServices,
      diseases,
      doctor: { userId: effectiveDoctorId, username: effectiveDoctorName }
    });
  } catch (err) {
    console.error('Error in GET /admin/patient-data', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
// ===== Admin mirrors of Doctor JSON endpoints used by admin/patient.ejs =====

// GET /admin/consultation/one?reservationId=...&petId=...&petName=...
router.get('/consultation/one', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { reservationId, petId, petName } = req.query;
    if (!reservationId) {
      return res.status(400).json({ success: false, message: 'reservationId required' });
    }

    // Try resolve petId by name if needed
    let targetPetId = petId || null;
    if (!targetPetId && petName) {
      const r = await Reservation.findById(reservationId)
        .populate('pets.petId','petName')
        .lean();
      const m = r?.pets?.find(p => (p.petId?.petName || p.petName) === petName);
      if (m?.petId?._id) targetPetId = String(m.petId._id);
    }

    // Prefer id; fallback to name
    let q = { reservation: reservationId };
    if (targetPetId) q.targetPetId = targetPetId;

    let c = await Consultation.findOne(q).sort({ updatedAt: -1, _id: -1 }).lean();
    if (!c && petName) {
      c = await Consultation.findOne({
        reservation: reservationId,
        targetPetName: petName
      }).sort({ updatedAt: -1, _id: -1 }).lean();
    }

    return res.json({ success: true, consultation: c || null });
  } catch (e) {
    console.error('admin /consultation/one error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET /admin/services/listByCategory?categoryId=...
router.get('/services/listByCategory', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { categoryId } = req.query;
    if (!categoryId) return res.json({ success:false, message:'categoryId is required' });
    const services = await Service.find({ category: categoryId }).lean();
    res.json({ success:true, services });
  } catch (e) {
    console.error('admin /services/listByCategory', e);
    res.status(500).json({ success:false, message:'Server error' });
  }
});

// GET /admin/consult/appointmentCount?date=YYYY-MM-DD&time=HH:MM%20AM
router.get('/consult/appointmentCount', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { date, time } = req.query;
    if (!date || !time) return res.json({ count: 0 });

    const start = new Date(date + 'T00:00:00.000Z');
    const end   = new Date(date + 'T23:59:59.999Z');

    const hits = await Reservation.find({
      date  : { $gte: start, $lte: end },
      time  : time,
      status: { $nin: ['Canceled','Rejected'] }
    }).select('petRequests').lean();

    let count = 0;
    for (const r of hits) {
      count += (Array.isArray(r.petRequests) && r.petRequests.length) ? r.petRequests.length : 1;
    }
    res.json({ count });
  } catch (e) {
    console.error('admin /consult/appointmentCount', e);
    res.json({ count: 0 });
  }
});

// GET /admin/settings/appointmentLimit
router.get('/settings/appointmentLimit', authMiddleware, allow('admin'), async (_req, res) => {
  try {
    const s = await AppointmentSetting.findOne().lean();
    res.json({ limit: Number(s?.limitPerHour ?? 0) });
  } catch {
    res.json({ limit: 0 });
  }
});

// GET /admin/settings/diseasesBySpecies?reservationId=...&petId=...&petName=...
router.get('/settings/diseasesBySpecies', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { reservationId, petId, petName } = req.query;
    if (!reservationId) {
      return res.status(400).json({ success: false, message: 'reservationId required' });
    }

    const reservation = await Reservation.findById(reservationId)
      .populate('pets.petId', 'petName species')
      .lean();
    if (!reservation) {
      return res.status(404).json({ success: false, message: 'Reservation not found' });
    }

    // Resolve species
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
    if (!species && reservation.isExistingPet === false) {
      species = reservation.species || null;
    }

    const settings = await PetDetailsSetting.findOne().lean();
    let list = [];
    if (settings) {
      if (species && settings.speciesDiseases && Array.isArray(settings.speciesDiseases[species])) {
        list = settings.speciesDiseases[species];
      } else if (Array.isArray(settings.diseases)) {
        list = settings.diseases;
      }
    }

    const diseases = [...new Set((list || [])
      .map(s => (typeof s === 'string' ? s.trim() : ''))
      .filter(Boolean))].sort((a,b) => a.localeCompare(b));

    return res.json({ success: true, species: species || null, diseases });
  } catch (e) {
    console.error('admin /settings/diseasesBySpecies', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET /admin/followup/stats?year=YYYY&month=1..12
router.get('/followup/stats', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const year  = parseInt(req.query.year, 10);
    const month = parseInt(req.query.month, 10);
    if (!year || !month) return res.json({ limit: 0, counts: {} });

    const TIME_SLOTS = ['08:00 AM','09:00 AM','10:00 AM','11:00 AM','12:00 PM','01:00 PM','02:00 PM','03:00 PM','04:00 PM','05:00 PM'];
    const perHour = Number((await AppointmentSetting.findOne().lean())?.limitPerHour ?? 0);
    const perDayLimit = perHour > 0 ? perHour * TIME_SLOTS.length : 0;

    const start = new Date(Date.UTC(year, month - 1, 1, 0, 0, 0, 0));
    const end   = new Date(Date.UTC(year, month,     0, 23, 59, 59, 999));

    const reservations = await Reservation.find({
      date  : { $gte: start, $lte: end },
      status: { $nin: ['Canceled', 'Rejected'] }
    }).select('date petRequests').lean();

    const counts = {};
    for (const r of reservations) {
      if (!r.date) continue;
      const iso = r.date.toISOString().slice(0, 10);
      const inc = (Array.isArray(r.petRequests) && r.petRequests.length) ? r.petRequests.length : 1;
      counts[iso] = (counts[iso] || 0) + inc;
    }

    res.json({ limit: perDayLimit, counts });
  } catch {
    res.json({ limit: 0, counts: {} });
  }
});

// Inventory helpers used in medication picker on consultation modal
router.get('/inventory/categories', authMiddleware, allow('admin'), async (_req, res) => {
  try {
    const cats = await Inventory.distinct('category');
    res.json({ success:true, categories: cats });
  } catch (e) {
    res.json({ success:true, categories: [] });
  }
});

router.get('/inventory/listByCategory', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { category } = req.query;
    const q = category ? { category } : {};
    const products = await Inventory.find(q).select('name').lean();
    res.json({ success:true, products });
  } catch (e) {
    res.json({ success:true, products: [] });
  }
});

router.get('/inventory/checkQuantity', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { product } = req.query;
    const doc = await Inventory.findOne({ name: product }).select('quantity').lean();
    res.json({ success:true, availableQty: Number(doc?.quantity || 0) });
  } catch (e) {
    res.json({ success:true, availableQty: 0 });
  }
});
router.get('/opex', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.render('opex'); // views/opex.ejs
});
// List OPEX
router.get('/opex/list', async (_req, res) => {
  try {
    const list = await Operating.find().sort({ createdAt: -1 }).lean();
    res.json({ success: true, list });
  } catch (e) {
    console.error('GET /admin/opex/list', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// BEFORE:
// router.post('/opex/add', async (req, res) => {

// AFTER — accept many files named "receipts"
router.post('/opex/add', uploadReceipts.array('receipts', 10), async (req, res) => {
  try {
    const type = String(req.body.type || '').trim();
    const amount = Number(req.body.amount);
    if (!type || !Number.isFinite(amount) || amount < 0) {
      return res.status(400).json({ success: false, message: 'type and amount are required' });
    }

    const files = (req.files || []).map(f => ({
      filename:     f.filename,
      originalName: f.originalname,
      mimeType:     f.mimetype,
      size:         f.size,
      url:          '/receipts/' + f.filename
    }));

    const doc = await require('../models/operating').create({
      type, amount, receipts: files
    });

    res.json({ success: true, opex: doc });
  } catch (e) {
    console.error('POST /admin/opex/add', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Edit OPEX
router.post('/opex/edit', async (req, res) => {
  try {
    const { id, type, amount } = req.body || {};
    if (!id) return res.status(400).json({ success: false, message: 'id required' });
    const set = {};
    if (typeof type === 'string') set.type = type.trim();
    if (amount !== undefined) {
      const n = Number(amount);
      if (!Number.isFinite(n) || n < 0) return res.status(400).json({ success: false, message: 'invalid amount' });
      set.amount = n;
    }
    const updated = await Operating.findByIdAndUpdate(id, { $set: set }, { new: true }).lean();
    if (!updated) return res.status(404).json({ success: false, message: 'not found' });
    res.json({ success: true, opex: updated });
  } catch (e) {
    console.error('POST /admin/opex/edit', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Delete OPEX
router.post('/opex/delete', async (req, res) => {
  try {
    const { id } = req.body || {};
    if (!id) return res.status(400).json({ success: false, message: 'id required' });
    const r = await Operating.findByIdAndDelete(id);
    if (!r) return res.status(404).json({ success: false, message: 'not found' });
    res.json({ success: true });
  } catch (e) {
    console.error('POST /admin/opex/delete', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
// Download all OPEX receipts for a given month/year as a ZIP
router.get('/opex/download', async (req, res) => {
  try {
    const month = parseInt(req.query.month, 10);
    const year  = parseInt(req.query.year, 10);
    if (!Number.isInteger(month) || month < 1 || month > 12 || !Number.isInteger(year)) {
      return res.status(400).send('month (1..12) and year are required');
    }

    const start = new Date(year, month - 1, 1, 0, 0, 0, 0);
    const end   = new Date(year, month, 0, 23, 59, 59, 999);

    // Pull OPEX docs in the month range
    const docs = await Operating.find({
      createdAt: { $gte: start, $lte: end }
    }).lean();

    // Collect absolute file paths from receipts[]
    const receiptsDir = path.join(__dirname, '../public/receipts');

    const safeName = (s, fb='receipt') =>
      String(s || fb).replace(/[^\w.\-]+/g, '_');

    // Prepare streaming zip response
    const fileBase   = `Receipts_${year}-${String(month).padStart(2,'0')}`;
    const zipName    = `${fileBase}.zip`;
    const folderName = `${fileBase}/`;

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);
    res.setHeader('Cache-Control', 'no-store');

    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.on('error', (err) => {
      console.error('archiver error:', err);
      try { res.status(500).end(); } catch(_) {}
    });

    archive.pipe(res);

    let added = 0;
    let idx = 1;

    for (const d of (docs || [])) {
      const created = d.createdAt ? new Date(d.createdAt) : null;
      const day = created ? String(created.getDate()).padStart(2,'0') : '00';
      const datePrefix = created
        ? `${created.getFullYear()}-${String(created.getMonth()+1).padStart(2,'0')}-${day}`
        : `${year}-${String(month).padStart(2,'0')}-${day}`;

      const files = Array.isArray(d.receipts) ? d.receipts : [];
      for (const f of files) {
        // Prefer filename (we stored it when uploading)
        const baseName = safeName(f.originalName || f.filename || `receipt_${idx}`);
        const diskName = String(f.filename || '').trim();
        // Absolute path inside /public/receipts
        const abs = path.join(receiptsDir, diskName);

        if (diskName && fs.existsSync(abs)) {
          const nameInZip = `${folderName}${datePrefix}_${safeName(d.type || 'expense')}_${idx}_${baseName}`;
          archive.file(abs, { name: nameInZip });
          added++;
          idx++;
        }
      }
    }

    if (added === 0) {
      // Always return a zip so the UX is consistent
      archive.append(
        `No receipts found for ${year}-${String(month).padStart(2,'0')}.\n`,
        { name: `${folderName}no-receipts.txt` }
      );
    }

    archive.finalize();
  } catch (e) {
    console.error('GET /admin/opex/download error:', e);
    // If headers already sent, just end the stream
    if (res.headersSent) return res.end();
    return res.status(500).send('Server error creating ZIP');
  }
});

module.exports = router;
