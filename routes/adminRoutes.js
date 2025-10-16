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
const PetDetailsSetting = require('../models/petDetailsSetting'); // <-- use the ACTUAL filename/casing
const Pet = require('../models/pet');
const clinicAnalytics = require('../controllers/clinicAnalyticsController');
// ⬇️ add these
const Reservation = require('../models/reservation');
const { addClient, removeClient } = require('../utils/hrSse'); // reuse your SSE hub
const PetDetailsSettings = require('../models/petDetailsSettings');
const Consultation = require('../models/consultation');


// ⬇️ add this (use the same path/name you use elsewhere)
const authMiddleware = require('../middleware/authMiddleware');
// ---- Inventory expiry helpers ----
function splitByToday(dates) {
  const arr = Array.isArray(dates) ? dates.map(d => new Date(d)) : [];
  const today = new Date(); today.setHours(0,0,0,0);
  const stillGood = [], newlyExpired = [];
  for (const d of arr) (d <= today ? newlyExpired : stillGood).push(d);
  return { stillGood, newlyExpired };
}

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

router.get('/get-pet-history', async (req, res) => {
  const { petId, petName, ownerId } = req.query;
  if (!petId && !petName) {
    return res.json({ success: false, message: 'petId or petName is required' });
  }
  try {
    const entry = await PetList.findOne(
      petId
        ? { _id: petId }
        : { owner: ownerId, petName }
    )
    .populate({
      path: 'consultationHistory.consultation',
      populate: {
        path: 'reservation',
        // include disease + species for fallbacks
        select: 'date schedule doctor disease species',
        populate: { path: 'doctor', select: 'username' }
      }
    })
    .lean();

    if (!entry) {
      return res.json({ success: false, message: 'PetList entry not found.' });
    }

    // Build history with normalized diseases[]
    const history = (entry.consultationHistory || [])
      .map(ch => {
        const c    = ch.consultation || {};
        const resv = c.reservation   || {};

        // Normalize diseases (accept several legacy shapes)
        const diseaseRaw =
              Array.isArray(c.diseases)         ? c.diseases
            : c.disease                         ? [c.disease]
            : Array.isArray(c.existingDiseases) ? c.existingDiseases
            : c.existingDisease                 ? [c.existingDisease]
            : resv.disease                      ? [resv.disease]
            : [];

        const diseases = diseaseRaw
          .map(x => String(x || '').trim())
          .filter(Boolean)
          .filter((v, i, a) => a.findIndex(z => z.toLowerCase() === v.toLowerCase()) === i) // de-dupe ci
          .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

        return {
          id:         c._id,
          date:       c.createdAt || ch.addedAt,
          doctor:     resv.doctor || null,
          notes:      c.notes || c.consultationNotes || '',
          physical:   c.physicalExam || {},
          diagnosis:  c.diagnosis || '',
          diseases, // <<<<<<<<<<<<<< NEW
          services:   c.services || [],
          medications:c.medications || [],
          confinement:c.confinementStatus || [],
          nextSchedule: resv.schedule
            ? {
                date:    resv.schedule.scheduleDate,
                details: resv.schedule.scheduleDetails
              }
            : null
        };
      })
      .sort((a, b) => new Date(b.date) - new Date(a.date));

    // Resolve species for header
    let pet = null;
    try {
      // Prefer real Pet doc for account owners
      if (entry.owner) {
        const pdoc = await Pet.findOne(
          { owner: entry.owner, petName: entry.petName },
          'petName species breed sex'
        ).lean();
        if (pdoc) {
          pet = { petName: pdoc.petName, species: pdoc.species || '', breed: pdoc.breed || '', sex: pdoc.sex || '' };
        }
      }
      // Fallback: latest reservation in history that has species
      if (!pet) {
        const latestWithSpecies = (entry.consultationHistory || [])
          .map(ch => ch?.consultation?.reservation)
          .filter(Boolean)
          .sort((a, b) => new Date(b.date || b.createdAt) - new Date(a.date || a.createdAt))
          .find(r => r && r.species);
        if (latestWithSpecies) {
          pet = { petName: entry.petName, species: latestWithSpecies.species || '' };
        }
      }
    } catch (_) { /* no-op */ }

    return res.json({ success: true, pet, history });
  } catch (err) {
    console.error('Error fetching pet history for admin:', err);
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
    const { name, category, basePrice, markup, quantity } = req.body;

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
      markup:     mAmt,          // pesos stored
      price:      finalPrice,    // base + markup
      quantity:   nonExpiredCount,   // <-- SELLABLE ONLY
      expirationDates: validDates,   // keep only future-dated here
      expiredDates:    alreadyExpired,
      expiredCount:    alreadyExpired.length
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
    const { id, name, category, basePrice, markup, quantity } = req.body;

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
      markup:          mAmt,        // pesos stored
      price:           finalPrice,  // base + markup
      quantity:        qty,
      expirationDates: validDates,
      expiredDates:    combinedExpiredDates,
      expiredCount:    newExpiredCount
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
    const { category, serviceName, weight, dosage, price } = req.body;
    const newService = new Service({ category, serviceName, weight, dosage, price });
    await newService.save();
    res.json({ message: "Service added successfully" });
  } catch (error) {
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
    const { id, category, serviceName, weight, dosage, price } = req.body;
    await Service.findByIdAndUpdate(id, { category, serviceName, weight, dosage, price });
    res.json({ message: "Service updated successfully" });
  } catch (error) {
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

module.exports = router;
