const express = require('express');
const router = express.Router();
const Reservation = require('../models/reservation');
const Pet = require('../models/pet');
const authMiddleware = require('../middleware/authMiddleware');
const AppointmentSetting = require('../models/appointmentSetting');
const User = require('../models/user');
const Joi = require('joi');
const Consultation = require('../models/consultation');
const PetList = require('../models/petlist');
const Inventory    = require('../models/inventory');
const Service      = require('../models/service');
const nodemailer = require('nodemailer'); // Import Nodemailer
const Payment = require('../models/Payment')
const { addClient, removeClient, broadcast } = require('../utils/hrSse');

const mongoose = require('mongoose');;
const { isValidObjectId } = mongoose;
// ===== SSE for HR live updates =====


// at the top
const PetDetailsSetting = require('../models/petDetailsSetting');
// Helper middleware for validation
function validateRequest(schema, property = 'body') {
  return (req, res, next) => {
    const { error } = schema.validate(req[property]);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    next();
  };
}

// Schema for approving reservation (requires reservationId)
const reservationIdSchema = Joi.object({
  reservationId: Joi.string().required()
});
// before any routes
// REPLACE the whole walkinSchema with this:
const walkinSchema = Joi.object({
  ownerId: Joi.string().optional().allow(''),
  ownerName: Joi.string().optional().allow(''),

  // NEW OPTIONAL CONTACTS
  contactEmail: Joi.string().email({ tlds: { allow: false } }).optional().allow(''),
  contactMobile: Joi.string()
    .pattern(/^(\+?63|0)9\d{9}$/)
    .message('Mobile must be PH format (09XXXXXXXXX or +639XXXXXXXXXX)')
    .optional()
    .allow(''),

  petName: Joi.string().required().label('Pet Name'),

  isExistingPet: Joi.boolean()
    .truthy('true').falsy('false')
    .default(true),

  species: Joi.string().trim().when('isExistingPet', { is: false, then: Joi.required(), otherwise: Joi.strip() }).label('Species'),
  breed:   Joi.string().trim().when('isExistingPet', { is: false, then: Joi.required(), otherwise: Joi.strip() }).label('Breed'),
  sex:     Joi.string().valid('Male','Female').when('isExistingPet', { is: false, then: Joi.required(), otherwise: Joi.strip() }).label('Sex'),

  existingDisease: Joi.string().optional().allow('').label('Existing Disease'),
  otherDisease: Joi.when('existingDisease', {
    is: 'Other',
    then: Joi.string().required().label('Other Disease'),
    otherwise: Joi.string().optional().allow('')
  }),

  service: Joi.string().required().label('Service'),
  date:    Joi.date().required().label('Date'),
  time:    Joi.string().required().label('Time'),

  weight:       Joi.number().optional().allow('', null),
  temperature:  Joi.number().optional().allow('', null),
  observations: Joi.string().optional().allow(''),
  concerns:     Joi.string().optional().allow('')
})
  .or('ownerId', 'ownerName')
  .unknown(false);

function validateWalkin(req, res, next) {
  const { error, value } = walkinSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      details: error.details.map(d => d.message)
    });
  }
  req.walkinData = value;
  next();
}

// GET /reservation route
router.get('/reservation', authMiddleware, async (req, res) => {
  try {
    // 1) Fetch all reservations
    const reservations = await Reservation.find()
      .populate('doctor', 'username')
      .populate('owner', '_id username')
      .lean();
// 2) Annotate each reservation (multi-pet aware)
for (let r of reservations) {
  const petNames = (r.pets || [])
    .map(p => p.petId?.petName || p.petName)
    .filter(Boolean);

  if (petNames.length === 0) {
    r.petExists = false;
    r.isStacked = false;
    r.isInitialEntry = false;
    continue;
  }

  const entries = await PetList.find(
    { owner: r.owner, petName: { $in: petNames } },
    'petName reservation consultationHistory'
  ).lean();

  const byName = new Map(entries.map(e => [e.petName, e]));

  let allExist = true;
  let allStacked = true;
  let anyInitial = false;

  for (const name of petNames) {
    const entry = byName.get(name);
    if (!entry) { allExist = false; allStacked = false; continue; }

    const hasThisReservation = (entry.consultationHistory || [])
      .some(ch => String(ch.reservation) === String(r._id));
    if (!hasThisReservation) allStacked = false;

    if (String(entry.reservation) === String(r._id)) anyInitial = true;
  }

  r.petExists = allExist;        // all pets have a PetList entry
  r.isStacked = allStacked;      // all those entries include this reservation
  r.isInitialEntry = anyInitial; // at least one entry was created by this reservation
}

    // 3) Compute ongoingReservations
    const ongoingReservations = reservations.filter(r =>
      (r.status === 'Paid' || r.status === 'Done' || !!r.doctor) &&
      !r.isInitialEntry &&
      !r.isStacked
    );

    // 4) Fetch helpers
    const doctors = await User.find({ role: 'Doctor' }).lean();
    const petDetails = (await PetDetailsSetting.findOne().lean()) || {
      species: [], speciesBreeds: {}, diseases: [], services: []
    };
    const pets = await Pet.find().populate('owner', 'username').lean();

    // —— NEW: fetch every PetList entry so we can build the owner→pet dropdown —— 
    const petlistEntries = await PetList.find()
      .populate('owner', 'username')
      .lean();

    // 5) Render, including petlistEntries
    res.render('hr/Reservation', {
      reservations,
      ongoingReservations,
      doctors,
      petDetails,
      pets,
      petlistEntries      // ← now available in your EJS
    });
  } catch (error) {
    console.error("Error fetching reservations:", error);
    res.status(500).send("Server error");
  }
});
// Live event stream for HR dashboard
router.get('/stream', authMiddleware, async (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });
  res.flushHeaders?.();
  res.write('retry: 3000\n\n'); // client auto-retry

  addClient(res);
  res.write(`data: ${JSON.stringify({ type: 'hello', t: Date.now() })}\n\n`);

  req.on('close', () => {
    removeClient(res);
    try { res.end(); } catch (_) {}
  });
});



// Updated /petlist route
// NEW: load from your PetList model
router.get('/petlist', authMiddleware, async (req, res) => {
  try {
   const entries = await PetList.find()
   .populate('owner', 'username email cellphone')
      .populate({
        path: 'consultationHistory.consultation',
        select: 'createdAt',    // or any fields you want
      })
      .lean();
    res.render('hr/petlist', { entries });
  } catch (err) {
    console.error("Error fetching pet list:", err);
    res.status(500).send("Server error");
  }
});
// ── after your other GET endpoints (e.g. /reservation, /petlist, /get-medication, etc.) ──
// hrroutes.js

// at top


// …

router.get('/get-owner-pets', authMiddleware, async (req, res) => {
  const { ownerId, ownerName } = req.query;

  // If we have an account owner (ownerId), use that (existing behavior)
  if (ownerId) {
    const listEntries = await PetList.find({ owner: ownerId }).lean();
    const listNames   = listEntries.map(e => e.petName);

    const realPets    = await Pet.find({ owner: ownerId }).lean();
    const realNames   = realPets.map(p => p.petName);

    const allNames = Array.from(new Set([...realNames, ...listNames]));
    return res.json({ pets: allNames });
  }

  // If we have a walk-in owner (by ownerName string), pull from PetList by ownerName
  if (ownerName && ownerName.trim()) {
    const listEntries = await PetList.find({ ownerName: ownerName.trim() }).lean();
    const listNames   = listEntries.map(e => e.petName);
    const allNames    = Array.from(new Set(listNames));
    return res.json({ pets: allNames });
  }

  return res.json({ pets: [] });
});


router.post(
  '/walkin-reservation',
  authMiddleware,
  validateWalkin,
  async (req, res) => {
    try {
    const {
  ownerId,
  ownerName,
  contactEmail,   // NEW
  contactMobile,  // NEW
  petName,
  isExistingPet,
  species,
  breed,
  sex,
  existingDisease,
  otherDisease,
  service,
  date,
  time,
  // weight, temperature, observations,
  concerns
} = req.walkinData;

// --- NORMALIZE UI TOKENS COMING FROM THE <select> ---
// The Owner <select> uses "ID::<ObjectId>" for accounts and "NAME::<text>" for walk-ins.
// Strip those prefixes so we never save tokens into the DB.
const rawOwnerId   = (ownerId   || '').trim();
const rawOwnerName = (ownerName || '').trim();

const ownerIdNorm   = rawOwnerId.startsWith('ID::')     ? rawOwnerId.slice(4)  : rawOwnerId;
const ownerNameNorm = rawOwnerName.startsWith('NAME::') ? rawOwnerName.slice(6) : rawOwnerName;

  // 1) Resolve owner (use normalized values)
let userId = null;
let nameToSave = '';

if (ownerIdNorm) {
  const existing = await User.findById(ownerIdNorm).lean();
  if (!existing) {
    return res.status(400).json({ success: false, message: 'Invalid owner.' });
  }
  userId     = existing._id;
  nameToSave = existing.username;  // clean, stable name for PetList display
} else {
  if (!ownerNameNorm) {
    return res.status(400).json({ success: false, message: 'Owner name is required for walk-in.' });
  }
  nameToSave = ownerNameNorm;      // clean walk-in name (no token)
}

      // 2) Normalize disease
      let disease = (existingDisease || '').trim();
      if (disease === 'Other') disease = (otherDisease || '').trim();
      if (disease === 'None')  disease = '';  // optional, store blank if "None"

      // 3) Create the reservation
      const reservationPayload = {
        owner:     userId || undefined,
        ownerName: nameToSave,
        walkIn:    true,
        pets:      [{ petName }], // we track per-pet in consultations later
        service,
        concerns,
        date,
        time,
        status:        'Approved',
        isExistingPet: !!isExistingPet ,   // <-- store the flag
          // NEW
  contactEmail:  (contactEmail && contactEmail.trim()) || undefined,
  contactMobile: (contactMobile && contactMobile.trim()) || undefined
      };

      // If it's a NEW pet, keep the quick meta on the reservation so you can later
      // create/merge a Pet document after the consult if you want
      if (isExistingPet === false) {
        reservationPayload.species = species;
        reservationPayload.breed   = breed;
        reservationPayload.sex     = sex;
        reservationPayload.disease = disease;
      } else {
        // existing pet selection: still store normalized disease if you want
        reservationPayload.disease = disease || undefined;
      }

      const reservation = await Reservation.create(reservationPayload);

      // 4) Broadcast so UIs update
      broadcast({
        type: 'reservation:walkin',
        reservation: {
          _id:       String(reservation._id),
          ownerName: reservation.ownerName,
          service:   reservation.service,
          time:      reservation.time,
          status:    reservation.status,
          date:      reservation.date || reservation.createdAt
        }
      });

      return res.json({ success: true, reservation });
    } catch (err) {
      console.error('Walkin reservation error:', err);
      const msg = err?.message || 'Server error.';
      return res.status(500).json({ success: false, message: msg });
    }
  }
);


// Approve Reservation route (updated with email notification)
// Approve Reservation route (updated with email notification using verified sender)
// ===================== APPROVE RESERVATION (updated) =====================
router.post('/approve-reservation',
  authMiddleware,
  validateRequest(reservationIdSchema),
  async (req, res) => {
    try {
      const { reservationId } = req.body;

      // 1) Load & validate
      const reservation = await Reservation.findById(reservationId);
      if (!reservation) {
        return res.status(404).json({ success: false, message: 'Reservation not found.' });
      }

      // 2) Update status
      reservation.status = 'Approved';
      await reservation.save();

      // 3) Broadcast to HR dashboards (SSE)
     broadcast({
        type: 'reservation:approved',
        id: String(reservation._id),
        reservation: {
          _id: String(reservation._id),
          ownerName: reservation.ownerName,
          service: reservation.service,
          time: reservation.time,
          status: reservation.status,
          date: reservation.date || reservation.createdAt
        }
      });

      // 4) Notify customer (email) — non-blocking
      try {
      const customer = reservation.owner ? await User.findById(reservation.owner) : null;
const toEmail = (customer && customer.email) || reservation.contactEmail;

if (toEmail) {
  const displayName = (customer && (customer.username || customer.name)) || reservation.ownerName || 'Customer';

  const mailOptions = {
    from: `"SmartVet Clinic" <dehe.marquez.au@phinmaed.com>`,
    to: toEmail,
    subject: "Your Consultation is Approved!",
    text:
`Hello ${displayName},

Your consultation has been approved by our HR team.
You can now visit the vet clinic at your earliest convenience.

Thank you,
SmartVet Clinic`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) console.error("Error sending approval email:", error);
    else console.log("Approval email sent:", info.response);
  });
} else {
  console.warn("No email available for reservation:", reservation._id);
}

      } catch (mailErr) {
        console.error("Email notification failed:", mailErr);
        // do not fail the main request on email issues
      }

      // 5) Done
      return res.json({ success: true, reservation });
    } catch (error) {
      console.error("Error approving reservation:", error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);

// --- Update PetList contact (walk-ins only) ---
const updatePetListContactSchema = Joi.object({
  id:            Joi.string().required(),
  contactEmail:  Joi.string().email({ tlds: { allow: false } }).allow('', null),
  contactMobile: Joi.string()
                      .pattern(/^(\+?63|0)9\d{9}$/)
                      .message('Mobile must be PH format (09XXXXXXXXX or +639XXXXXXXXXX)')
                      .allow('', null),
  applyToAllSameWalkin: Joi.boolean().truthy('true').falsy('false').default(false)
});

router.post(
  '/petlist/update-contact',
  authMiddleware,
  validateRequest(updatePetListContactSchema),
  async (req, res) => {
    try {
      const { id, contactEmail, contactMobile, applyToAllSameWalkin } = req.body;

      // Guard: valid ObjectId
      if (!isValidObjectId(id)) {
        return res.status(400).json({ success: false, message: 'Invalid PetList id.' });
      }

      const entry = await PetList.findById(id).populate('owner', '_id').lean();
      if (!entry) {
        return res.status(404).json({ success:false, message:'PetList entry not found.' });
      }

      // If this row belongs to an account owner, block edits here.
      if (entry.owner && entry.owner._id) {
        return res.status(400).json({
          success: false,
          message: 'This owner has an account. Update their email/mobile in the User profile. Pet List will reflect it automatically.'
        });
      }

      // Build updates safely (no empty $set)
      const $set = {};
      const $unset = {};

      if (typeof contactEmail === 'string' || contactEmail === null) {
        const v = (contactEmail || '').trim();
        if (v) $set.contactEmail = v; else $unset.contactEmail = '';
      }
      if (typeof contactMobile === 'string' || contactMobile === null) {
        const v = (contactMobile || '').trim();
        if (v) $set.contactMobile = v; else $unset.contactMobile = '';
      }

      // If no changes, short-circuit
      const hasSet = Object.keys($set).length > 0;
      const hasUnset = Object.keys($unset).length > 0;
      if (!hasSet && !hasUnset) {
        return res.json({ success: true, message: 'No changes.' });
      }

      const updateDoc = {};
      if (hasSet) updateDoc.$set = $set;
      if (hasUnset) updateDoc.$unset = $unset;

      if (applyToAllSameWalkin) {
        // Match walk-ins robustly: owner missing OR null, and same ownerName
        await PetList.updateMany(
          {
            ownerName: entry.ownerName,
            $or: [{ owner: { $exists: false } }, { owner: null }]
          },
          updateDoc
        );
      } else {
        await PetList.updateOne({ _id: id }, updateDoc);
      }

      return res.json({ success: true });
    } catch (err) {
      console.error('petlist/update-contact failed:', err);
      return res.status(500).json({ success:false, message:'Server error' });
    }
  }
);

// ===================== ASSIGN DOCTOR (updated) =====================
const assignDoctorSchema = Joi.object({
  reservationId: Joi.string().required(),
  doctorId: Joi.string().required()
});

router.post(
  '/assign-doctor',
  authMiddleware,
  validateRequest(assignDoctorSchema),
  async (req, res) => {
    try {
      const { reservationId, doctorId } = req.body;

      // 1) Load & validate
      const reservation = await Reservation.findById(reservationId);
      if (!reservation) {
        return res
          .status(404)
          .json({ success: false, message: 'Reservation not found.' });
      }
      if (reservation.doctor && reservation.doctor.toString() === doctorId) {
        return res
          .status(400)
          .json({ success: false, message: 'Doctor is already assigned to this reservation.' });
      }

      // 2) Assign & save
      reservation.doctor = doctorId;
      await reservation.save();

      // Populate what we need for both the HR payload and the doctor rows
      await reservation.populate([
        { path: 'doctor', select: 'username' },
        { path: 'pets.petId', select: 'petName' }
      ]);

      // Convert to plain object for safe spreading/serialization
      const updated = reservation.toObject();

      // 3) Build doctor-targeted "rows" (one per pet) so d-patient.ejs can insert without reload
      const reqs = Array.isArray(updated.petRequests) ? updated.petRequests : [];

      // Map requested service per pet (by ObjectId first, then by petName; fallback to reservation.service)
      const getServiceForPet = (pet) => {
        if (pet?.petId) {
          const r = reqs.find(x => String(x.petId) === String(pet.petId));
          if (r?.service) return r.service;
        }
        if (pet?.petName) {
          const r = reqs.find(x => x.petName === pet.petName);
          if (r?.service) return r.service;
        }
        return updated.service || '';
      };

      const rows = (updated.pets || []).map(p => ({
        reservationId: String(updated._id),
        ownerName: updated.ownerName || '',
        petId: p?.petId?._id ? String(p.petId._id) : '',
        petName: p?.petId?.petName || p?.petName || '—',
        service: getServiceForPet(p) || '—',
        petSchedule: p?.schedule || null,
        hasConsultation: false
      }));

      // 4) Broadcast (HR dashboards can ignore the extra fields; doctors filter by doctorId)
      broadcast({
        type: 'reservation:assigned',
        id: String(updated._id),                             // keeps your existing HR shape working
        doctorId: String(updated.doctor?._id || doctorId),   // lets doctors filter events for themselves
        reservation: {
          _id: String(updated._id),
          ownerName: updated.ownerName,
          service: updated.service,
          time: updated.time,
          date: updated.date || updated.createdAt,
          doctor: updated.doctor && {
            _id: String(updated.doctor._id),
            username: updated.doctor.username
          }
        },
        rows                                                // used by d-patient.ejs to prepend table rows
      });

      // 5) Respond
      return res.json({ success: true, reservation: updated });
    } catch (error) {
      console.error('Error assigning doctor:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);


// GET limit-per-hour route (no validation required)
router.get('/limit-per-hour', authMiddleware, async (req, res) => {
  try {
    let setting = await AppointmentSetting.findOne().lean();
    if (!setting) {
      setting = await AppointmentSetting.create({});
      setting = setting.toObject();
    }
    res.render('hr/limitPerHour', { setting });
  } catch (error) {
    console.error("Error fetching appointment setting:", error);
    res.status(500).send("Server error");
  }
});

// Schema for updating limit-per-hour
const limitPerHourSchema = Joi.object({
  limitPerHour: Joi.number().integer().min(1).required()
});

router.post('/limit-per-hour', authMiddleware, validateRequest(limitPerHourSchema), async (req, res) => {
  try {
    const { limitPerHour } = req.body;
    let setting = await AppointmentSetting.findOne();
    if (!setting) {
      setting = await AppointmentSetting.create({ limitPerHour });
    } else {
      setting.limitPerHour = limitPerHour;
      await setting.save();
    }
    res.json({ success: true, setting });
  } catch (error) {
    console.error("Error updating appointment setting:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// GET medication details for a reservation (validate reservationId in query)
router.get('/get-medication', authMiddleware, validateRequest(reservationIdSchema, 'query'), async (req, res) => {
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
    console.error("Error fetching medication details:", error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Add pet from reservation (validate reservationId)
// 1) Add to PetList (on “Add” button)
// Add to PetList (on “Add” button)
// Add to PetList (on “Add” button)
router.post('/add-to-petlist', authMiddleware, validateRequest(reservationIdSchema), async (req, res) => {
  try {
    const { reservationId } = req.body;

    const reservation = await Reservation.findById(reservationId).lean();
    if (!reservation) return res.status(404).json({ success: false, message: 'Reservation not found.' });

    const consults = await Consultation.find({ reservation: reservationId }).lean();
    if (!consults.length) return res.status(404).json({ success: false, message: 'No consult found.' });

    // ---------- 1) Decide the BEST contact info ONCE ----------
    // Prefer the reservation’s contact (walk-ins), otherwise fall back to the User record (accounts).
    let contactEmail  = reservation.contactEmail  || null;
    let contactMobile = reservation.contactMobile || null;

    if (reservation.owner) {
      const ownerDoc = await User.findById(reservation.owner).lean();
      if (ownerDoc) {
        if (!contactEmail)  contactEmail  = ownerDoc.email || null;
        if (!contactMobile) contactMobile = ownerDoc.cellphone || null;
      }
    }
    // ----------------------------------------------------------

    // helper to resolve pet name for a consultation
    const petsArr = reservation.pets || [];
    const resolvePetName = (c) => {
      if (c?.targetPetName && String(c.targetPetName).trim()) return String(c.targetPetName).trim();
      if (c?.petName && String(c.petName).trim())             return String(c.petName).trim();

      const byId = c?.targetPetId || c?.petId;
      if (byId && mongoose.isValidObjectId(byId)) {
        const hit = petsArr.find(p => String(p.petId?._id) === String(byId));
        if (hit) return hit.petId?.petName || hit.petName || '—';
      }

      const byNameMaybe = (typeof byId === 'string' && !mongoose.isValidObjectId(byId)) ? byId : null;
      if (byNameMaybe) {
        const hit = petsArr.find(p => (p.petId?.petName || p.petName) === byNameMaybe);
        if (hit) return hit.petId?.petName || hit.petName || '—';
      }

      if (petsArr.length === 1) return petsArr[0].petId?.petName || petsArr[0].petName || '—';
      return '—';
    };

    // ---------- 2) For each consult, create/update the PetList row ----------
    for (const c of consults) {
      const petName = resolvePetName(c);
      if (!petName || petName === '—') continue;

      // look up by owner (if account) OR ownerName (walk-in) + petName
      const baseLookup = reservation.owner
        ? { owner: reservation.owner, petName }
        : { ownerName: reservation.ownerName, petName };

      let entry = await PetList.findOne(baseLookup).lean();

      if (!entry) {
        // Create NEW PetList entry and store the contact info immediately
        entry = await PetList.create({
          owner: reservation.owner ?? undefined,
          ownerName: reservation.ownerName,
          petName,
          reservation: reservationId,
          contactEmail,              // <<<<<<<<<< NEW
          contactMobile,             // <<<<<<<<<< NEW
          consultationHistory: [{ reservation: reservationId, consultation: c._id }]
        });
      } else {
        // Update existing row:
        //  - push this reservation into consultationHistory if missing
        //  - fill in contact fields if they are currently empty
        const hasThis = (entry.consultationHistory || [])
          .some(ch => String(ch.reservation) === String(reservationId));

        const setPayload = {};
        if (!entry.contactEmail && contactEmail)   setPayload.contactEmail  = contactEmail;
        if (!entry.contactMobile && contactMobile) setPayload.contactMobile = contactMobile;

        if (!hasThis && Object.keys(setPayload).length) {
          await PetList.updateOne(
            { _id: entry._id },
            { 
              $set: setPayload,
              $push: { consultationHistory: { reservation: reservationId, consultation: c._id } }
            }
          );
        } else if (!hasThis) {
          await PetList.updateOne(
            { _id: entry._id },
            { $push: { consultationHistory: { reservation: reservationId, consultation: c._id } } }
          );
        } else if (Object.keys(setPayload).length) {
          await PetList.updateOne(
            { _id: entry._id },
            { $set: setPayload }
          );
        }
      }
    }
    // -----------------------------------------------------------------------

    await Reservation.findByIdAndUpdate(reservationId, { status: 'Done' });
    return res.json({ success: true });
  } catch (err) {
    console.error('Error in add-to-petlist:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// 2) Update PetList (on “Update” button)
// 2) Update PetList (on “Update” button)
router.post('/update-petlist', authMiddleware, validateRequest(reservationIdSchema), async (req, res) => {
  try {
    const { reservationId } = req.body;

    const reservation = await Reservation.findById(reservationId).lean();
    if (!reservation) return res.status(404).json({ success: false, message: 'Reservation not found.' });

    const consults = await Consultation.find({ reservation: reservationId }).lean();
    if (!consults.length) return res.status(404).json({ success: false, message: 'No consult found.' });

    // ---------- 1) Decide the BEST contact info ONCE ----------
    let contactEmail  = reservation.contactEmail  || null;
    let contactMobile = reservation.contactMobile || null;

    if (reservation.owner) {
      const ownerDoc = await User.findById(reservation.owner).lean();
      if (ownerDoc) {
        if (!contactEmail)  contactEmail  = ownerDoc.email || null;
        if (!contactMobile) contactMobile = ownerDoc.cellphone || null;
      }
    }
    // ----------------------------------------------------------

    const petsArr = reservation.pets || [];
    const resolvePetName = (c) => {
      if (c?.targetPetName && String(c.targetPetName).trim()) return String(c.targetPetName).trim();
      if (c?.petName && String(c.petName).trim())             return String(c.petName).trim();
      const byId = c?.targetPetId || c?.petId;
      if (byId && mongoose.isValidObjectId(byId)) {
        const hit = petsArr.find(p => String(p.petId?._id) === String(byId));
        if (hit) return hit.petId?.petName || hit.petName || '—';
      }
      const byNameMaybe = (typeof byId === 'string' && !mongoose.isValidObjectId(byId)) ? byId : null;
      if (byNameMaybe) {
        const hit = petsArr.find(p => (p.petId?.petName || p.petName) === byNameMaybe);
        if (hit) return hit.petId?.petName || hit.petName || '—';
      }
      if (petsArr.length === 1) return petsArr[0].petId?.petName || petsArr[0].petName || '—';
      return '—';
    };

    for (const c of consults) {
      const petName = resolvePetName(c);
      if (!petName || petName === '—') continue;

      const baseLookup = reservation.owner
        ? { owner: reservation.owner, petName }
        : { ownerName: reservation.ownerName, petName };

      let entry = await PetList.findOne(baseLookup).lean();

      if (!entry) {
        entry = await PetList.create({
          owner: reservation.owner ?? undefined,
          ownerName: reservation.ownerName,
          petName,
          reservation: reservationId,
          contactEmail,              // <<<<<<<<<< NEW
          contactMobile,             // <<<<<<<<<< NEW
          consultationHistory: [{ reservation: reservationId, consultation: c._id }]
        });
      } else {
        const hasThis = (entry.consultationHistory || [])
          .some(ch => String(ch.reservation) === String(reservationId));

        const setPayload = {};
        if (!entry.contactEmail && contactEmail)   setPayload.contactEmail  = contactEmail;
        if (!entry.contactMobile && contactMobile) setPayload.contactMobile = contactMobile;

        if (!hasThis && Object.keys(setPayload).length) {
          await PetList.updateOne(
            { _id: entry._id },
            { 
              $set: setPayload,
              $push: { consultationHistory: { reservation: reservationId, consultation: c._id } }
            }
          );
        } else if (!hasThis) {
          await PetList.updateOne(
            { _id: entry._id },
            { $push: { consultationHistory: { reservation: reservationId, consultation: c._id } } }
          );
        } else if (Object.keys(setPayload).length) {
          await PetList.updateOne(
            { _id: entry._id },
            { $set: setPayload }
          );
        }
      }
    }

    await Reservation.findByIdAndUpdate(reservationId, { status: 'Done' });
    return res.json({ success: true });
  } catch (err) {
    console.error('Error in update-petlist:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});


// GET /hr/get-pet-history
router.get('/get-pet-history', authMiddleware, async (req, res) => {
  try {
    const { petId, petName, ownerId, ownerName } = req.query;

    if (!petId && !petName) {
      return res.json({ success: false, message: 'petId or petName is required' });
    }

    // Build a SAFE query (avoid casting invalid ObjectIds)
    let query;
    if (petId) {
      if (!isValidObjectId(petId)) {
        return res.json({ success: false, message: 'Invalid petId' });
      }
      query = { _id: petId };
    } else {
      // lookup by name + owner (ObjectId when valid; otherwise by ownerName for walk-ins)
      if (ownerId && isValidObjectId(ownerId)) {
        query = { petName, owner: ownerId };
      } else if (ownerName && ownerName.trim()) {
        query = { petName, ownerName: ownerName.trim() };
      } else {
        // last fallback: name only (could be ambiguous, but won’t cast error)
        query = { petName };
      }
    }

    const entry = await PetList.findOne(query)
      .populate({
        path: 'consultationHistory.consultation',
        populate: [
          {
            path: 'reservation',
            select: 'date doctor schedule',
            populate: { path: 'doctor', select: 'username' }
          }
        ]
      })
      .lean();

    if (!entry) {
      return res.json({ success: false, message: 'PetList entry not found.' });
    }
// Build pet meta (name + species/breed/sex)
// 1) If account owner, pull from Pet collection.
// 2) If walk-in, try newest related Reservation (where you may have saved quick meta for new pets).
let petMeta = { name: entry.petName, species: '', breed: '', sex: '' };

try {
  if (entry.owner) {
    const petDoc = await Pet.findOne(
      { owner: entry.owner, petName: entry.petName },
      'species breed sex'
    ).lean();
    if (petDoc) {
      petMeta.species = petDoc.species || '';
      petMeta.breed   = petDoc.breed   || '';
      petMeta.sex     = petDoc.sex     || '';
    }
  } else {
    const latestCh = (entry.consultationHistory || [])
      .slice()
      .sort((a, b) => new Date(b.addedAt) - new Date(a.addedAt))[0];

    if (latestCh && latestCh.reservation) {
      // Pull quick meta stored on reservation for NEW pets
      const r = await Reservation.findById(latestCh.reservation, 'species breed sex').lean();
      if (r) {
        petMeta.species = r.species || '';
        petMeta.breed   = r.breed   || '';
        petMeta.sex     = r.sex     || '';
      }
    }
  }
} catch (_) { /* best effort only */ }

    // map out history with nextSchedule
const history = (entry.consultationHistory || [])
  .map(ch => {
    const c    = ch.consultation || {};
    const resv = c.reservation   || {};

    // --- NEW: normalize diseases based on possible schema keys ---
    const diseaseRaw =
          Array.isArray(c.diseases)         ? c.diseases
        : c.disease                         ? [c.disease]
        : Array.isArray(c.existingDiseases) ? c.existingDiseases
        : c.existingDisease                 ? [c.existingDisease]
        : resv.disease                      ? [resv.disease]      // fallback from reservation
        : [];

    const diseases = diseaseRaw
      .map(x => String(x || '').trim())
      .filter(Boolean)
      .filter((v, i, a) => a.findIndex(z => z.toLowerCase() === v.toLowerCase()) === i) // de-dupe (case-insensitive)
      .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

    return {
      id:         c._id,
      date:       c.createdAt || ch.addedAt,
      doctor:     resv.doctor || null,
      notes:      c.notes || c.consultationNotes || '',
      physical:   c.physicalExam || { weight: '', temperature: '', observations: '' },
      diagnosis:  c.diagnosis || '',
      diseases, // <-- NEW FIELD in the payload
      services:   (c.services || []).map(s => ({
                    category:    s.category    || 'Uncategorized',
                    serviceName: s.serviceName || '',
                    details:     s.details     || '',
                    file:        s.file        || null
                  })),
      medications:(c.medications || []).map(m => ({
                    name:     m.name     || m.medicationName || '',
                    dosage:   m.dosage   || '',
                    remarks:  m.remarks  || '',
                    quantity: m.quantity || 0
                  })),
      confinement:c.confinementStatus || [],
      nextSchedule: resv.schedule
        ? { date: resv.schedule.scheduleDate, details: resv.schedule.scheduleDetails }
        : null
    };
  })
  .sort((a, b) => new Date(b.date) - new Date(a.date));

return res.json({ success: true, pet: petMeta, history });
  } catch (err) {
    console.error('get-pet-history failed:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// at the bottom of hrroutes.js
router.post('/add-consult-existing', authMiddleware, async (req, res) => {
  // pull req.body.ownerName, petId, service, date, time, weight, temperature, observations, concerns
  // create a new Reservation (or Consultation) record
  // return { success: true }
});
// GET /hr/get-consultation-details
// GET /hr/get-consultation-details  (PASTE/REPLACE)
// GET /hr/get-consultation-details
router.get('/get-consultation-details', authMiddleware, async (req, res) => {
  try {
    const { reservationId } = req.query;
    if (!reservationId) {
      return res.json({ success: false, message: 'Missing reservationId' });
    }

    const reservation = await Reservation.findById(reservationId)
      .populate('owner', 'username')           // owner._id + username (lean)
      .populate('pets.petId', 'petName')       // petId._id + petName (lean)
      .lean();

    if (!reservation) {
      return res.json({ success: false, message: 'Reservation not found' });
    }

    // ----------------------------
    // NEW: Compute PetList flags
    // ----------------------------
    // truth source: PetList (not just "has petId")
    let petExists = false, isStacked = false, isInitialEntry = false;
    {
      const petNames = (reservation.pets || [])
        .map(p => p?.petId?.petName || p?.petName)
        .filter(Boolean);

      if (petNames.length) {
        // prefer account owner when available, else string ownerName
        const ownerId = reservation.owner?._id || reservation.owner || null;
        const lookup = ownerId
          ? { owner: ownerId, petName: { $in: petNames } }
          : { ownerName: reservation.ownerName, petName: { $in: petNames } };

        const entries = await PetList
          .find(lookup, 'petName reservation consultationHistory')
          .lean();

        const byName = new Map(entries.map(e => [e.petName, e]));

        let allExist = true;
        let allStacked_ = true;
        let anyInitial = false;

        for (const name of petNames) {
          const entry = byName.get(name);
          if (!entry) { allExist = false; allStacked_ = false; continue; }

          // already stacked to this consultation?
          const hasThisConsult = (entry.consultationHistory || [])
            .some(ch => String(ch.reservation) === String(reservation._id));
          if (!hasThisConsult) allStacked_ = false;

          // initial PetList entry was created by this reservation?
          if (String(entry.reservation) === String(reservation._id)) {
            anyInitial = true;
          }
        }

        petExists = allExist;
        isStacked = allStacked_;
        isInitialEntry = anyInitial;
      }
    }

    // -----------------------------------------
    // Load consultations (newest first), keep
    // ONLY the newest per pet (by id or name)
    // -----------------------------------------
    const consultDocs = await Consultation
      .find({ reservation: reservationId })
      .sort({ updatedAt: -1, _id: -1 })
      .lean();

    const latestByPet = new Map();
    for (const c of consultDocs) {
      const key = c.targetPetId
        ? `id:${c.targetPetId}`
        : `name:${(c.targetPetName || c.petName || '').trim().toLowerCase()}`;
      if (!latestByPet.has(key)) latestByPet.set(key, c); // first = newest
    }

    // Helper: resolve pet name for a consultation (supports targetPet* and legacy pet*)
    // (requires: const mongoose = require('mongoose') at top of file)
    function resolvePetName(c) {
      // 1) explicit names first
      if (c?.targetPetName && String(c.targetPetName).trim()) return String(c.targetPetName).trim();
      if (c?.petName && String(c.petName).trim())             return String(c.petName).trim();

      const petsArr = reservation.pets || [];

      // 2) try by id (prefer targetPetId; fall back to petId)
      const candidateId = c?.targetPetId || c?.petId;
      if (candidateId && mongoose.isValidObjectId(candidateId)) {
        const hitById = petsArr.find(p => String(p.petId?._id) === String(candidateId));
        if (hitById) return hitById.petId?.petName || hitById.petName || '—';
      }

      // 3) try by name string (some old data put the name in petId)
      const candidateName =
        (typeof candidateId === 'string' && !mongoose.isValidObjectId(candidateId))
          ? candidateId
          : (c?.targetPetName || c?.petName || null);

      if (candidateName) {
        const hitByName = petsArr.find(p => (p.petId?.petName || p.petName) === candidateName);
        if (hitByName) return hitByName.petId?.petName || hitByName.petName || '—';
      }

      // 4) single-pet reservation fallback
      if (petsArr.length === 1) return petsArr[0].petId?.petName || petsArr[0].petName || '—';

      return '—';
    }

    // -----------------------------------------
    // Enrich medications/services with prices
    // -----------------------------------------
    const consultations = [];
    for (const c of latestByPet.values()) {
      const petName = resolvePetName(c);

      // ----- Medications -----
      const meds = [];
      for (const m of (c.medications || [])) {
        const medName = m.name || m.medicationName || '';
        let inv = null;
        if (medName) inv = await Inventory.findOne({ name: medName }).lean();

        // Prefer the selling price (basePrice + markup). Fallbacks included.
const unitPrice = (() => {
  if (typeof m.unitPrice === 'number') return m.unitPrice;    // keep explicit override
  if (inv) {
    if (typeof inv.price === 'number') return inv.price;       // already computed (pre hooks)
    const b  = Number(inv.basePrice || 0);
    const mk = Number(inv.markup || 0);
    return b + mk;                                             // legacy docs w/o .price
  }
  return 0;
})();


        // heuristic for "Added" label on manual rows
        const hasConsultTarget = !!(c.targetPetId || c.targetPetName || c.petId || c.petName);
        const medHasTarget     = !!(m.targetPetId || m.petId || m.targetPetName || m.petName);
        const inferredAdded    = m.added === true ? true : (!hasConsultTarget && !medHasTarget);

        meds.push({
          ...m,
          name: medName,
          unitPrice,
          category: m.category || inv?.category || 'Uncategorized',
          quantity: Number(m.quantity || 0),
          added: !!inferredAdded
        });
      }

      // ----- Services -----
      const svcs = [];
      for (const s of (c.services || [])) {
        let svcDoc = null;
        if (s.serviceId) {
          try { svcDoc = await Service.findById(s.serviceId).lean(); } catch (e) {}
        }
        if (!svcDoc && s.serviceName) {
          svcDoc = await Service.findOne({ serviceName: s.serviceName }).lean();
        }
        svcs.push({
          ...s,
          serviceName: s.serviceName || svcDoc?.serviceName || '',
          price: (typeof s.price === 'number') ? s.price : (svcDoc?.price || 0)
        });
      }

      consultations.push({
        petId: c.petId || null,
        petName,
        medications: meds,
        services: svcs
      });
    }

    // Payment present?
    const payment = await Payment.findOne({ reservation: reservationId }).lean();

    // ----------------------------
    // Respond with flags included
    // ----------------------------
    res.json({
      success: true,
      data: {
        reservation,
        consultations,
        payment: payment || null,
        flags: { petExists, isStacked, isInitialEntry }
      }
    });
  } catch (err) {
    console.error('get-consultation-details failed:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});


// Put this near your other Joi schemas in hrroutes.js

// Accept extra keys on each line item (e.g., pet, category, etc.)
const lineItemSchema = Joi.object({
  name:      Joi.string().required(),
  quantity:  Joi.number().min(0).required(),
  unitPrice: Joi.number().min(0).required(),
  lineTotal: Joi.number().min(0).required()
}).unknown(true);

const markPaidSchema = Joi.object({
  reservationId: Joi.string().required(),
  amount:        Joi.number().min(0).required(),
  products:      Joi.array().items(lineItemSchema).default([]),
  services:      Joi.array().items(lineItemSchema).default([])
});

router.get('/get-consultation', authMiddleware, async (req, res) => {
  try {
    const { reservationId } = req.query;
    if (!reservationId) {
      return res.status(400).json({ success: false, message: 'reservationId is required.' });
    }

    const reservation = await Reservation.findById(reservationId)
      .populate('doctor', 'username')
      .populate('pets.petId', 'petName birthday species breed sex') // so we can show more pet info
      .lean();

    if (!reservation) {
      return res.status(404).json({ success: false, message: 'Reservation not found.' });
    }

    // merge its Consultation (if any)
    const consult = await Consultation.findOne({ reservation: reservationId }).lean();
    if (consult) {
      reservation.physicalExam       = consult.physicalExam;
      reservation.diagnosis          = consult.diagnosis;
      reservation.services           = consult.services;
      reservation.medications        = consult.medications;
      reservation.notes              = consult.notes;
      reservation.confinementStatus  = consult.confinementStatus;
    }

    return res.json({ success: true, reservation });
  } catch (err) {
    console.error('HR get-consultation error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// HR: Check inventory quantity for medications (so your HR UI can call it)
router.get('/inventory/checkQuantity', authMiddleware, async (req, res) => {
  try {
    const { product } = req.query;
    if (!product) {
      return res.status(400).json({ success: false, message: 'Product is required.' });
    }
    const inventoryItem = await Inventory.findOne({ name: product }).lean();
    if (!inventoryItem) {
      return res.status(404).json({ success: false, message: 'Product not found.' });
    }
    res.json({ success: true, availableQty: inventoryItem.quantity });
  } catch (error) {
    console.error("Error checking inventory quantity (HR):", error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
// GET /hr/inventory/categories
router.get('/inventory/categories', authMiddleware, async (req, res) => {
  try {
    const cats = await Inventory.distinct('category');
    res.json({ success: true, categories: cats });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.get('/inventory/listByCategory', authMiddleware, async (req, res) => {
  try {
    const { category } = req.query;
    const products = await Inventory
      .find({ category }, 'name price basePrice markup')
      .lean();

    res.json({
      success: true,
      products: products.map(p => ({
        name: p.name,
        // selling price = basePrice + markup (prefer the stored .price if present)
        price: (typeof p.price === 'number')
          ? p.price
          : (Number(p.basePrice || 0) + Number(p.markup || 0))
      }))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});


// Your /mark-paid route (REPLACE the whole block)
router.post(
  '/mark-paid',
  authMiddleware,
  validateRequest(markPaidSchema),
  async (req, res) => {
    try {
      const { reservationId } = req.body;
      const products = Array.isArray(req.body.products) ? req.body.products : [];
      const services = Array.isArray(req.body.services) ? req.body.services : [];

      // 1) Find & mark reservation paid
      const reservation = await Reservation.findById(reservationId);
      if (!reservation) {
        return res.status(404).json({ success: false, message: 'Reservation not found.' });
      }

      // --- Build an Inventory lookup to get selling prices (base + markup) ---
      const names = [...new Set(products.map(p => p.name).filter(Boolean))];
      const invDocs = names.length
        ? await Inventory.find(
            { name: { $in: names } },
            'name price basePrice markup quantity'
          ).lean()
        : [];
      const invByName = new Map(invDocs.map(d => [d.name, d]));

      // 2) Clean + normalize Products — compute unitPrice from Inventory
      const cleanProducts = products.map(p => {
        const inv = invByName.get(p.name);
        const unit = inv
          ? (typeof inv.price === 'number'
              ? inv.price
              : (Number(inv.basePrice || 0) + Number(inv.markup || 0)))
          : Number(p.unitPrice || 0); // fallback if not found in inventory
        const qty = Number(p.quantity || 0);
        const lineTotal = parseFloat((unit * qty).toFixed(2));
        return {
          name:      p.name,
          quantity:  qty,
          unitPrice: unit,
          lineTotal
        };
      });

      // 3) Clean Services (keep incoming price unless you also want to force-load from Service model)
      const cleanServices = services.map(s => {
        const qty = Number(s.quantity || 0);
        const unit = Number(s.unitPrice || 0);
        const lineTotal = parseFloat((unit * qty).toFixed(2));
        return {
          name:      s.name,
          quantity:  qty,
          unitPrice: unit,
          lineTotal
        };
      });

      // 4) Compute authoritative amount on the server
      const computedAmount =
        cleanProducts.reduce((sum, i) => sum + i.lineTotal, 0) +
        cleanServices.reduce((sum, i) => sum + i.lineTotal, 0);

      // Mark reservation paid
      reservation.status = 'Paid';
      await reservation.save();

      // 5) Decrement each product’s inventory (use the lookup; fallback query if missing)
      for (const { name, quantity } of cleanProducts) {
        const inv = invByName.get(name) || await Inventory.findOne({ name }).lean();
        if (!inv) continue;

        const newQty = Math.max(Number(inv.quantity || 0) - Number(quantity || 0), 0);

        // Only update the quantity field; this won't trigger other validators
        await Inventory.updateOne(
          { _id: inv._id },
          { $set: { quantity: newQty } }
        );
      }

      // 6) Save the payment record — always store computed selling prices and totals
      const payment = new Payment({
        reservation:  reservation._id,
        customer:     reservation.owner || undefined, // if there is a real user
        customerName: reservation.ownerName || '',
        by:           req.user.userId,
        products:     cleanProducts,
        services:     cleanServices,
        amount:       parseFloat(computedAmount.toFixed(2))
      });
      await payment.save();

      return res.json({ success: true, reservation, paymentId: String(payment._id) });
    } catch (err) {
      console.error('Error marking paid and updating inventory:', err);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);

 // === POS / Retail: mark paid without reservation ===
 const retailPaidSchema = Joi.object({
   customerName: Joi.string().optional().allow(''),
   amount:        Joi.number().min(0).required(),
   products:      Joi.array().items(lineItemSchema).min(1).required()
 });

 router.post(
   '/mark-paid-retail',
   authMiddleware,
   validateRequest(retailPaidSchema),
   async (req, res) => {
     try {
       const { customerName, amount, products } = req.body;

       // sanitize like in /mark-paid
       const cleanProducts = (products || []).map(p => ({
         name:      p.name,
         quantity:  Number(p.quantity)  || 0,
         unitPrice: Number(p.unitPrice) || 0,
         lineTotal: Number(p.lineTotal) || 0
       }));

       // decrement inventory for each product
      for (const { name, quantity } of cleanProducts) {
         const invDoc = await Inventory.findOne({ name }).lean();
         if (!invDoc) continue;
         const newQty = Math.max((invDoc.quantity || 0) - Number(quantity || 0), 0);
         await Inventory.updateOne({ _id: invDoc._id }, { $set: { quantity: newQty } });
       }

      // save payment record (no reservation)
       const payment = new Payment({
         isRetail:    true,
         customer:    undefined,
         customerName: (customerName && customerName.trim()) || 'Walk-in',
         by:          req.user.userId,
         amount,
         products:    cleanProducts,
        services:    []
       });
       await payment.save();

      return res.json({ success: true, paymentId: String(payment._id) });
    } catch (err) {
       console.error('Retail mark-paid failed:', err);
       return res.status(500).json({ success: false, message: 'Server error' });
     }
   }
 );


// 1) Update one medication’s quantity
router.post(
  '/update-medication',
  authMiddleware,
  validateRequest(Joi.object({
    reservationId: Joi.string().required(),
    medicationName:Joi.string().required(),
    quantity:      Joi.number().min(0).required()
  })),
  async (req, res) => {
    const { reservationId, medicationName, quantity } = req.body;
    try {
      // find the consultation
      const consult = await Consultation.findOne({ reservation: reservationId });
      if (!consult) return res.status(404).json({ success:false, message:'No consultation.' });

      // find the med entry and update its qty
      const med = consult.medications.find(m => m.name === medicationName);
      if (!med) return res.status(404).json({ success:false, message:'Medication not found.' });
      med.quantity = quantity;
      await consult.save();

      res.json({ success:true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success:false, message:'Server error' });
    }
  }
);

// 2) Remove a medication entirely
router.post(
  '/remove-medication',
  authMiddleware,
  validateRequest(Joi.object({
    reservationId: Joi.string().required(),
    medicationName:Joi.string().required()
  })),
  async (req, res) => {
    const { reservationId, medicationName } = req.body;
    try {
      const consult = await Consultation.findOne({ reservation: reservationId });
      if (!consult) return res.status(404).json({ success:false, message:'No consultation.' });

      // filter out the med
      consult.medications = consult.medications.filter(m => m.name !== medicationName);
      await consult.save();

      res.json({ success:true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success:false, message:'Server error' });
    }
  }
);
// Add a new medication to the consultation
const addMedicationSchema = Joi.object({
  reservationId:   Joi.string().required(),
  medicationName:  Joi.string().required(),
  quantity:        Joi.number().min(1).required()
});

// Add a new medication to the consultation
router.post('/add-medication', authMiddleware, validateRequest(addMedicationSchema), async (req, res) => {
  try {
    const { reservationId, medicationName, quantity } = req.body;
    const consult = await Consultation.findOne({ reservation: reservationId });
    if (!consult) return res.status(404).json({ success:false, message:'Consultation not found.' });

    // 👇 mark manual additions
    consult.medications.push({ name: medicationName, quantity, added: true });
    await consult.save();
    res.json({ success:true });
  } catch (err) {
    console.error('Error adding medication:', err);
    res.status(500).json({ success:false, message:'Server error.' });
  }
});

// Search owners that exist in PetList (accounts + walk-ins)
router.get('/search-owners', authMiddleware, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q) return res.json({ items: [] });

    const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');

    // 1) Account owners that appear in PetList
    const ownerIdsInPetList = await PetList.distinct('owner', { owner: { $ne: null } });
    let accountItems = [];
    if (ownerIdsInPetList.length) {
      const users = await User.find({ _id: { $in: ownerIdsInPetList }, username: rx })
                              .select('_id username')
                              .lean();
      accountItems = users.map(u => ({
        token: `ID::${u._id}`,
        label: u.username
      }));
    }

    // 2) Walk-in names that appear in PetList
    const walkinNames = await PetList.distinct('ownerName', { ownerName: rx });
    const walkinItems = walkinNames
      .filter(Boolean)
      .map(name => ({
        token: `NAME::${name}`,
        label: `${name} (walk-in)`
      }));

    // 3) Merge + de-dupe by label
    const seen = new Set();
    const items = [...accountItems, ...walkinItems].filter(x => {
      if (seen.has(x.label)) return false;
      seen.add(x.label);
      return true;
    }).slice(0, 20); // cap results

    res.json({ items });
  } catch (err) {
    console.error('search-owners failed:', err);
    res.status(500).json({ items: [] });
  }
});
// GET /hr/history and /hr/reservation-history  – Reservation History partial
router.get(['/history', '/reservation-history'], authMiddleware, async (req, res) => {
  try {
    const statuses = ['Done', 'Paid', 'Not Attended'];

    const reservations = await Reservation.find({ status: { $in: statuses } })
      .populate('owner', 'username')
      .lean();

    const historyReservations = reservations.map(r => {
      const service =
        typeof r.service === 'string'
          ? r.service
          : (r.service && r.service.serviceName) || '';

      const date = r.date || (r.schedule && r.schedule.scheduleDate) || r.createdAt;
      const time = r.time || (r.schedule && (r.schedule.scheduleTime || r.schedule.time)) || '';

      return {
        ...r,
        ownerName: r.ownerName || (r.owner && r.owner.username) || '',
        service,
        date,
        time
      };
    });
    // Retail payments (POS)
    const retailSales = await Payment.find({ isRetail: true })
      .sort({ createdAt: -1 })
      .lean();

    res.render('hr/ReservationHistory', { historyReservations, retailSales });
  } catch (err) {
    console.error('Error loading History:', err);
    res.status(500).send('Server error');
  }
});

module.exports = router;
