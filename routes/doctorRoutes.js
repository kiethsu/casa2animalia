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

// Updated schema for adding consultation details
const addConsultationSchema = Joi.object({
  reservationId: Joi.string().required(),
  consultationNotes: Joi.string().optional().allow(""),
  examWeight: Joi.string().optional().allow(""),
  examTemperature: Joi.string().optional().allow(""),
  examOthers: Joi.string().optional().allow(""),
  diagnosis: Joi.string().optional().allow(""),
  notes: Joi.string().optional().allow(""),
  medicationsData: Joi.string().optional().allow(""),
  servicesData: Joi.string().optional().allow("")
}).unknown(true);  // Allow unknown keys

// Schema for adding a follow-up schedule
const addScheduleSchema = Joi.object({
  reservationId: Joi.string().required(),
  scheduleDate: Joi.date().required(),
  scheduleDetails: Joi.string().required()
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

// GET /doctor/d-patient
// GET /doctor/d-patient  (REPLACED)
// GET /doctor/d-patient
router.get("/d-patient", authMiddleware, async (req, res) => {
  try {
    const reservations = await Reservation.find({
      doctor: req.user.userId,
      status: { $ne: 'Done' }
    })
      .populate('pets.petId', 'petName birthday')
      .lean();

    const reservationIds = reservations.map(r => r._id);

    const consults = await Consultation.find({
      reservation: { $in: reservationIds }
    }).select('targetPetId targetPetName').lean();

    const consultedById   = new Set(consults.filter(c => c.targetPetId).map(c => String(c.targetPetId)));
    const consultedByName = new Set(consults.filter(c => c.targetPetName).map(c => String(c.targetPetName).toLowerCase()));

    const rows = [];
    for (const r of reservations) {
      for (const p of (r.pets || [])) {
        if (p?.done) continue;
        const petObj  = p.petId || p;
        const pid     = petObj && petObj._id ? String(petObj._id) : '';
        const nameRaw = (petObj && petObj.petName) || p.petName || '';
        const nameKey = nameRaw.toLowerCase();
        const hasConsultation =
          (p.hasConsult === true) ||
          (pid && consultedById.has(pid)) ||
          (nameKey && consultedByName.has(nameKey));

        rows.push({
          reservationId: String(r._id),
          ownerName: r.ownerName || '',
          petId: pid,
          petName: nameRaw || '—',
          service: findServiceForPet(r, p) || '—',
          petSchedule: p.schedule || null,
          hasConsultation
        });
      }
    }

    const serviceCategories = await ServiceCategory.find({}).lean();

    // ✅ Pull the same services list customers see (PetDetailsSetting.services)
    const rawPetDetails = await PetDetailsSetting.findOne().lean();
    let simpleServices = [];
    if (Array.isArray(rawPetDetails?.services) && rawPetDetails.services.length) {
      simpleServices = rawPetDetails.services
        .map(s => {
          if (typeof s === 'string') return s.trim();
          if (s && typeof s === 'object') {
            return (s.name || s.serviceName || s.title || s.label || s.value || '').toString().trim();
          }
          return '';
        })
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b));
    } else {
      // Fallback: de-dup from Service collection if settings are empty
      simpleServices = (await Service.distinct('serviceName'))
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b));
    }

    res.render("doctor/d-patient", { rows, serviceCategories, simpleServices });
  } catch (error) {
    console.error("Error fetching assigned patients:", error);
    res.status(500).send("Server error");
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
router.post('/mark-done', authMiddleware, async (req, res) => {
  try {
    const { reservationId, petId, petName } = req.body;
    if (!reservationId || (!petId && !petName)) {
      return res.status(400).json({ success: false, message: 'reservationId + (petId or petName) are required' });
    }

    // Prefer matching by petId; fall back to petName for walk-ins
    let selector;
    if (petId) {
      const rid = mongoose.Types.ObjectId.isValid(reservationId) ? new mongoose.Types.ObjectId(reservationId) : reservationId;
      const pid = mongoose.Types.ObjectId.isValid(petId) ? new mongoose.Types.ObjectId(petId) : petId;
      selector = { _id: rid, 'pets.petId': pid };
    } else {
      selector = { _id: reservationId, 'pets.petName': petName };
    }

    const result = await Reservation.updateOne(selector, { $set: { 'pets.$.done': true } });
    if ((result.matchedCount ?? result.n) === 0) {
      return res.status(404).json({ success: false, message: 'Reservation or pet not found' });
    }

    // If all pets are done, flip reservation to Done
    const updated = await Reservation.findById(reservationId).lean();
    const allDone = (updated?.pets || []).every(p => !!p.done);
    if (allDone && updated.status !== 'Done') {
      await Reservation.updateOne({ _id: reservationId }, { $set: { status: 'Done' } });
    }

    return res.json({ success: true, allDone });
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
        notes,
        medicationsData,
        servicesData,
        // NEW (pass these from your form):
        targetPetId,        // optional
        targetPetName,      // optional (fallback if no id)
        // Optional follow-up for THIS pet:
        scheduleDate,
        scheduleDetails
      } = req.body;

      const reservation = await Reservation.findById(reservationId);
      if (!reservation) {
        return res.status(404).json({ success: false, message: 'Reservation not found.' });
      }
      if (reservation.doctor?.toString() !== req.user.userId.toString()) {
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
  notes,
  medications,   // replace entire array
  services,      // replace entire array
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
      let selector;
      if (finalPetId) {
        selector = { _id: reservationId, 'pets.petId': finalPetId };
      } else if (finalPetName) {
        selector = { _id: reservationId, 'pets.petName': finalPetName };
      }

      if (selector) {
        const setObj = { 'pets.$.hasConsult': true };
        if (scheduleDate) {
          setObj['pets.$.schedule'] = {
            scheduleDate:   new Date(scheduleDate),
            scheduleDetails: scheduleDetails || ''
          };
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

     res.json({ success: true, consultation: updatedConsult });

    } catch (error) {
      console.error("Error adding consultation details:", error);
      res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);
// POST /doctor/save-consult-flag  (OPTIONAL - instant flip button)
router.post('/save-consult-flag', authMiddleware, async (req, res) => {
  try {
    const { reservationId, petId, petName } = req.body;
    if (!reservationId || (!petId && !petName)) {
      return res.status(400).json({ success: false, message: 'reservationId + (petId or petName) are required' });
    }

    const isValid = (s) => mongoose.Types.ObjectId.isValid(String(s));
    let selector;
    if (petId && isValid(petId)) {
      selector = { _id: reservationId, 'pets.petId': new mongoose.Types.ObjectId(petId) };
    } else {
      selector = { _id: reservationId, 'pets.petName': petName };
    }

    const result = await Reservation.updateOne(selector, { $set: { 'pets.$.hasConsult': true } });
    if ((result.matchedCount ?? result.n) === 0) {
      return res.status(404).json({ success: false, message: 'Reservation or pet not found' });
    }
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Server error saving consult flag.' });
  }
});



// POST /doctor/add-schedule
// expects: reservationId, petId, scheduleDate (YYYY-MM-DD), scheduleDetails
// POST /doctor/add-schedule  (per-pet; supports petId OR petName)
// Make sure these are at the top of the file (if not already):
// const mongoose = require('mongoose');
// const Reservation = require('../models/reservation');

router.post('/add-schedule', authMiddleware, async (req, res) => {
  try {
    const {
      reservationId,
      petId,
      petName,
      scheduleDate,
      scheduleDetails,
      // NEW: service fields coming from the modal
      scheduleServiceId,
      scheduleServiceName,
      scheduleCategoryId,
      scheduleCategoryName
    } = req.body;

    if (!reservationId || !scheduleDate || (!petId && !petName)) {
      return res
        .status(400)
        .json({
          success: false,
          message: 'reservationId + (petId or petName) + scheduleDate are required'
        });
    }

    // Build schedule payload saved on the specific pet
    const schedulePayload = {
      scheduleDate: new Date(scheduleDate),
      scheduleDetails: scheduleDetails || ''
    };

    // Only attach service object if we have at least a name or id
    if (scheduleServiceId || scheduleServiceName) {
      schedulePayload.service = {
        id: scheduleServiceId || null,
        name: scheduleServiceName || '',
        categoryId: scheduleCategoryId || null,
        categoryName: scheduleCategoryName || ''
      };
    }

    // Prefer petId; otherwise fall back to petName (for walk-ins)
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

    const update = {
      $set: { 'pets.$.schedule': schedulePayload }
    };

    const result = await Reservation.updateOne(selector, update);

    // Mongoose v5 returns { n, nModified }, v6+ returns { matchedCount, modifiedCount }
    const matched = (result.matchedCount ?? result.n) || 0;
    if (matched === 0) {
      return res.status(404).json({ success: false, message: 'Pet not found in reservation.' });
    }

    // ---- Keep a TOP-LEVEL reservation.schedule for dashboards ----
    // Recompute the earliest upcoming follow-up across all pets and store it at reservation.schedule
    const fresh = await Reservation.findById(reservationId).lean();
    const petSchedules = (fresh?.pets || [])
      .map(p => p.schedule)
      .filter(s => s && s.scheduleDate);

    if (petSchedules.length) {
      // Pick the earliest scheduleDate
      petSchedules.sort((a, b) => new Date(a.scheduleDate) - new Date(b.scheduleDate));
      const earliest = petSchedules[0];

      await Reservation.updateOne(
        { _id: reservationId },
        { $set: { schedule: earliest } }
      );
    } else {
      // No per-pet schedules left — clear top-level
      await Reservation.updateOne(
        { _id: reservationId },
        { $unset: { schedule: '' } }
      );
    }

    return res.json({
      success: true,
      saved: schedulePayload
    });
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

module.exports = router;
