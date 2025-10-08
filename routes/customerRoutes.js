// customerRoutes.js
const CANCEL_THRESHOLD = 2;    // how many cancels before suspension
const SUSPEND_DAYS     = 1;    // suspension length
const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const User = require("../models/user");
const Pet = require('../models/pet');
const multer = require('multer');
const Reservation = require('../models/reservation');
const AppointmentSetting = require('../models/appointmentSetting');
const DashboardSetting = require('../models/dashboardSetting');
const Joi = require('joi');
const nodemailer = require('nodemailer');
const bcrypt = require("bcryptjs");
const PetList = require('../models/petlist');
const Consultation = require('../models/consultation');
const pdf = require('html-pdf');
const Message = require('../models/message');
const { broadcast } = require('../utils/hrSse');
// --- helper: normalize to YYYY-MM-DD (local-safe fallback) ---
// helper → normalize to YYYY-MM-DD
const toYMD = (d) => {
  const x = new Date(d);
  if (!x || isNaN(x)) return '';
  const y = x.getFullYear();
  const m = String(x.getMonth() + 1).padStart(2, '0');
  const dd = String(x.getDate()).padStart(2, '0');
  return `${y}-${m}-${dd}`;
};
// ===== SSE (Server-Sent Events) plumbing for realtime badge & status =====
const clients = new Map(); // userId -> Set(res objects)

function pushTo(userId, payload){
  const set = clients.get(String(userId));
  if (!set) return;
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) {
    try { res.write(data); } catch(e) {}
  }
}

router.get('/messages/stream', authMiddleware, async (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.flushHeaders?.();
  res.write('retry: 3000\n\n'); // auto-retry in 3s

  const uid = String(req.user.userId);
  if (!clients.has(uid)) clients.set(uid, new Set());
  clients.get(uid).add(res);

  // send initial snapshot
  try {
    const unread = await Message.countDocuments({ user: uid, isRead: false });
    const me = await User.findById(uid, 'isSuspended cancelCount').lean();
    res.write(`data: ${JSON.stringify({
      topic: 'snapshot',
      unread,
      isSuspended: !!me?.isSuspended,
      cancelCount: me?.cancelCount || 0
    })}\n\n`);
  } catch(e){}

  const keepAlive = setInterval(() => res.write(':ka\n\n'), 25000);
  req.on('close', () => {
    clearInterval(keepAlive);
    const set = clients.get(uid);
    if (set) { set.delete(res); if (!set.size) clients.delete(uid); }
  });
});

// Helper to send “almost there” warning
async function sendWarningEmail(toEmail, cancelCount) {
  const transporter = nodemailer.createTransport({
    host: "smtp-relay.brevo.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.SMTP_EMAIL,
      pass: process.env.SMTP_PASS
    }
  });
  await transporter.sendMail({
    from: `"SmartVet Support" <dehe.marquez.au@phinmaed.com>`,

    to: toEmail,
    subject: "Careful – One More Cancellation Will Suspend You",
    html: `
      <p>You’ve cancelled ${cancelCount} out of ${CANCEL_THRESHOLD} allowed consultations.</p>
      <p>If you cancel one more, your account will be suspended from submitting new consultations for ${SUSPEND_DAYS} day(s).</p>
      <p>Please make sure you really want to cancel next time.</p>
    `
  });
}


// Import the PetDetailsSetting model
const PetDetailsSetting = require('../models/petDetailsSetting');
// Temporary in-memory store for email update OTPs (for demo purposes only)
let emailUpdateOtpStore = {};
    // For registration OTP
// -------------------- Helper Functions --------------------
// Helper to send suspension email
async function sendSuspensionEmail(toEmail) {
  const transporter = nodemailer.createTransport({
    host: "smtp-relay.brevo.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.SMTP_EMAIL,
      pass: process.env.SMTP_PASS
    }
  });
  await transporter.sendMail({
   from: `"SmartVet Support" <dehe.marquez.au@phinmaed.com>`,
    to: toEmail,
    subject: "Consultation Submission Suspended",
    html: `
      <p>You have cancelled too many consultations.</p>
      <p>Your account is suspended from submitting new consultations for ${SUSPEND_DAYS} days.</p>
      <p>If you think this is an error, reply to this email.</p>
    `
  });
}
 // helper → always grab the up-to-date user record
async function checkNotSuspended(req, res, next) {
  const freshUser = await User.findById(req.user.userId);
  if (freshUser.isSuspended) {
    return res
      .status(403)
      .json({
        success: false,
        suspended: true,
        message: 'Your account is suspended from submitting consultations.'
      });
  }
  next();
}


 
// Convert video URLs to embed format
function convertToEmbedUrl(url) {
  if (!url) return url;
  if (url.includes("youtube.com/watch?v=")) {
    return url.replace("watch?v=", "embed/");
  }
  if (url.includes("drive.google.com/file/d/")) {
    const match = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
    if (match && match[1]) {
      return `https://drive.google.com/file/d/${match[1]}/preview`;
    }
  }
  return url;
}

// Validation middleware helper
function validateRequest(schema, property = 'body') {
  return (req, res, next) => {
    const { error } = schema.validate(req[property]);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    next();
  };
}

// -------------------- Joi Schemas --------------------

// Schema for updating profile details
const updateProfileSchema = Joi.object({
  fullName: Joi.string()
    .trim()
    .max(40)
    .pattern(/^[\p{L}\p{N} .,'-]+$/u)
    .required()
   .messages({
  'string.empty': 'Full name is required.',
  'string.max': 'Full name must be 40 characters or fewer.',
  'string.pattern.base': 'Invalid full name.'
})
,
  address: Joi.string().max(120).optional().allow(""),
  cellphone: Joi.string().max(30).optional().allow("")
});

// Schema for adding a pet (unchanged)
const addPetSchema = Joi.object({
  petName: Joi.string().required(),
  species: Joi.string().required(),
  breed: Joi.string().optional().allow(""),
  birthday: Joi.date().optional().allow(null),
  existingDisease: Joi.string().optional().allow(""),
  sex: Joi.string().optional().allow(""),
  petPic: Joi.string().optional().allow("")
});

// Per-pet request (service/concerns per selected pet)
const perPetRequestSchema = Joi.object({
  petId: Joi.string().required(),
  petName: Joi.string().required(),
  service: Joi.string().required(),
  concerns: Joi.string().optional().allow("")
});

// Schema for submitting a reservation (NEW: multi-pet, shared date/time)
// Schema for submitting a reservation (NEW: multi-pet, shared date/time)
const submitReservationSchema = Joi.object({
  date: Joi.date().required(),
  time: Joi.string().required(),
  idemKey: Joi.string().trim().max(256).required(),   // ← add this
  petRequests: Joi.array().items(perPetRequestSchema).min(1).required()
});

// Schema for reservation ID validation (for query parameters)
const reservationIdSchema = Joi.object({
  reservationId: Joi.string().required()
});
async function pushMessage(userId, { type = 'info', title, body }) {
  try {
    await Message.create({ user: userId, type, title, body });
  } catch (e) {
    console.error('pushMessage error:', e);
  }
}
// --- SESSION PROBE: check if user is still logged in ---
router.get('/session', authMiddleware, (req, res) => {
  res.json({
    ok: true,
    userId: req.user.userId,
    username: req.user.username,
    role: req.user.role
  });
});

// -------------------- Routes --------------------

// Dashboard route
router.get('/dashboard', authMiddleware, async (req, res) => {
  try {
    const username = req.user.username || req.user.email;
    const now = new Date();

    // grab any reservation with a follow-up in the future
    const upcomingVisits = await Reservation.find({
      owner: req.user.userId,
      'schedule.scheduleDate': { $gte: now }
    })
    .populate('pets.petId', 'petName')  // so visit.pets[i].petId.petName is available
    .sort({ 'schedule.scheduleDate': 1 })
    .lean();

    // your recent “Done” visits
    const recentVisits = await Reservation.find({
      owner: req.user.userId,
      status: 'Done'
    })
    .sort({ createdAt: -1 })
    .limit(5)
    .lean();

    let dashboardSetting = await DashboardSetting.findOne().lean();
    if (dashboardSetting && dashboardSetting.videoUrl) {
      dashboardSetting.videoUrl = convertToEmbedUrl(dashboardSetting.videoUrl);
    }

    res.render('customer/dashboard', {
      username,
      upcomingVisits,
      recentVisits,
      dashboardSetting
    });
  } catch (error) {
    console.error("Error fetching dashboard data:", error);
    res.status(500).send("Server error");
  }
});

// customerRoutes.js

// customerRoutes.js

router.get('/mypet', authMiddleware, async (req, res) => {
  try {
    // current user, including hidden list
    const userDoc = await User.findById(req.user.userId, 'username hiddenPetNames').lean();
    const hiddenNames = userDoc?.hiddenPetNames || [];

    // 1) real pets
    const pets = await Pet.find({ owner: req.user.userId }).lean();

    // 2) clinic (PetList) entries, EXCLUDING hidden names
    const petListEntries = await PetList.find({
      owner: req.user.userId,
      ...(hiddenNames.length ? { petName: { $nin: hiddenNames } } : {})
    }).lean();

    // 3) de-dupe by name (keep your own pets first)
    const existingNames = new Set(pets.map(p => p.petName));
    const walkInPets = petListEntries
      .filter(e => !existingNames.has(e.petName))
      .map(e => ({
        _id:                  `list-${e._id}`,
        petName:              e.petName,
        species:              e.species || '',
        breed:                e.breed   || '',
        birthday:             '',
        existingDisease:      '',
        sex:                  '',
        petPic:               '',
        addedFromReservation: true
      }));

    const allPets = [...pets, ...walkInPets];

    // 4) dropdown settings
    let petDetails = await PetDetailsSetting.findOne().lean();
    if (!petDetails) petDetails = { species: [], speciesBreeds: {}, diseases: [], services: [] };

    res.render('customer/mypet', {
      pets: allPets,
      petListEntries,   // (already filtered)
      petDetails
    });
  } catch (error) {
    console.error("Error fetching My Pet data:", error);
    res.status(500).send("Server error");
  }
});


// Consult route
// customerRoutes.js

router.get('/consult', authMiddleware, async (req, res) => {
  try {
const pets = await Pet.find({ owner: req.user.userId }).lean();    const reservations = await Reservation.find({ owner: req.user.userId })
                                          .sort({ createdAt: -1 })
                                          .populate('doctor', 'username')
                                          .lean();
    const petDetails = (await PetDetailsSetting.findOne().lean()) 
                         || { species: [], breeds: [], diseases: [], services: [] };

    // pull the fresh user record
    const freshUser = await User.findById(req.user.userId).lean();

    res.render('customer/consult', {
      pets,
      reservations,
      petDetails,
      user: freshUser,
      error: req.flash('error'),
        threshold: CANCEL_THRESHOLD 
    });
  } catch (error) {
    console.error("Error fetching pets/reservations for consult:", error);
    res.status(500).send("Server error");
  }
});


// Profile Details route
router.get('/profileDetails', authMiddleware, async (req, res) => {
  try {
    const userData = await User.findById(req.user.userId);
    res.render('customer/profileDetails', { user: userData });
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});


// Update Profile Details route with validation
router.post('/update-profile-details', authMiddleware, validateRequest(updateProfileSchema), async (req, res) => {
  try {
    // Normalize the name (collapse spaces)
    const safeFullName = String(req.body.fullName || '').replace(/\s+/g, ' ').trim();
    const address      = String(req.body.address || '').trim();
    const cellphone    = String(req.body.cellphone || '').trim();
    const userId       = req.user.userId;

    // (Defense-in-depth) re-check allowed chars server-side
    const NAME_ALLOWED_RE = /^[\p{L}\p{N} .,'-]+$/u;
    if (!NAME_ALLOWED_RE.test(safeFullName) || safeFullName.length > 40 || !safeFullName) {
 return res.status(400).json({
  success: false,
  message: "Invalid full name. Up to 40 characters."
});

    }

    // Uniqueness (case-insensitive, excluding current user)
    const existingUser = await User.findOne({
      username: { $regex: `^${safeFullName}$`, $options: "i" },
      _id: { $ne: userId }
    });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "This full name is already taken." });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { username: safeFullName, address, cellphone },
      { new: true }
    );

    return res.json({ success: true, user: updatedUser, message: "Profile updated." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ success: false, message: "Server error. Please try again later." });
  }
});

// Configure multer for file uploads (profile image)
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, 'public/uploads/');
  },
  filename: function(req, file, cb) {
    const ext = file.originalname.split('.').pop();
    cb(null, req.user.userId + '-' + Date.now() + '.' + ext);
  }
});
const upload = multer({ storage: storage });
router.post('/update-profile-image', authMiddleware, upload.single('profilePic'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded.' });
    }
    const fileUrl = '/uploads/' + req.file.filename;
    const updatedUser = await User.findByIdAndUpdate(req.user.userId, { profilePic: fileUrl }, { new: true });
    return res.json({ success: true, profilePic: updatedUser.profilePic });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Schema for adding a pet
router.post('/add-pet', authMiddleware, validateRequest(addPetSchema), async (req, res) => {
  try {
    const { petName, species, breed, birthday, existingDisease, sex, petPic } = req.body;
    const owner = req.user.userId;
    const newPet = new Pet({
      owner,
      petName,
      species,
      breed,
      birthday: birthday ? new Date(birthday) : null,
      existingDisease,
      sex,
      petPic
    });
    await newPet.save();
    return res.json({ success: true, pet: newPet });
  } catch (error) {
    console.error("Error saving pet:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});


// Schema for submitting a reservation
// customerRoutes.js

router.post(
  '/submit-reservation',
  authMiddleware,
  checkNotSuspended,
  validateRequest(submitReservationSchema),
  async (req, res) => {
    try {
      const ownerId   = req.user.userId;
      const ownerName = req.user.username || req.user.email;

      // ---- normalize payload (same as your code) ----
      let { petRequests, selectedPets, service, concerns, date, time, idemKey } = req.body;
      if (!petRequests && selectedPets && service) {
        petRequests = selectedPets.map(p => ({
          petId: p.petId, petName: p.petName, service, concerns: concerns || ''
        }));
      }
      if (!Array.isArray(petRequests) || petRequests.length === 0) {
        return res.status(400).json({ success: false, message: "No pet requests provided." });
      }

      // ==== IDEMPOTENCY: place RIGHT HERE ====
      const idemKeyFromClient = String(idemKey || '').trim();
      if (!idemKeyFromClient) {
        return res.status(400).json({ success: false, message: 'Missing idempotency key.' });
      }

      // If the same submission already exists, return it as success
      const existingByKey = await Reservation.findOne({ idemKey: idemKeyFromClient }).lean();
      if (existingByKey) {
        return res.json({ success: true, duplicate: true, reservation: existingByKey });
      }
      // =======================================

      // ---- capacity check (unchanged) ----
      const setting = await AppointmentSetting.findOne();
      const limit   = setting ? setting.limitPerHour : 5;

      // how many PETS already booked for this slot?
      const bookedPets    = await countPetsBookedForSlot(date, time);
      const requestedPets = petRequests.length;
      const remaining     = Math.max(0, limit - bookedPets);

      if (requestedPets > remaining) {
        const msg = remaining === 0
          ? "This time slot is full."
          : `This time slot is almost full. Only ${remaining} pet slot${remaining>1?'s':''} remaining.`;
        return res.status(400).json({ success: false, message: msg });
      }

      // ---- build reservation (unchanged apart from idemKey) ----
      const isValidObjectId = (s) => /^[a-fA-F0-9]{24}$/.test(String(s));
      const pets = petRequests.map(pr => ({
        petId: isValidObjectId(pr.petId) ? pr.petId : undefined,
        petName: pr.petName
      }));

      const userProfile = await User.findById(ownerId);

      const newReservation = new Reservation({
        owner: ownerId,
        ownerName,
        pets,
        service:  petRequests.length === 1 ? petRequests[0].service : 'Multiple',
        concerns: petRequests.length === 1 ? (petRequests[0].concerns || '') : '',
        petRequests,
        date: date ? new Date(date) : null,
        time,
        status: 'Pending',
        address: userProfile?.address || "",
        phone:   userProfile?.cellphone || "",
        idemKey: idemKeyFromClient              // <-- NEW (important)
      });

   // Save with duplicate-key protection (race-safe)
try {
  await newReservation.save();
} catch (e) {
  if (e && e.code === 11000) {
    const r = await Reservation.findOne({ idemKey: idemKeyFromClient }).lean();
    return res.json({ success: true, duplicate: true, reservation: r });
  }
  throw e;
}

// compute the exact day the customer picked (prefer raw body if it's already YYYY-MM-DD)
// compute the exact day the customer picked (prefer raw body if already YYYY-MM-DD)
const dateKey =
  (typeof req.body.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(req.body.date))
    ? req.body.date
    : toYMD(newReservation.date || newReservation.createdAt);

// notify HR screens (Pending table + calendar day highlight)
broadcast({
  type: 'reservation:pending',
  reservation: {
    _id: String(newReservation._id),
    ownerName: newReservation.ownerName,
    service: newReservation.service,
    time: newReservation.time,
    status: newReservation.status,
    date: newReservation.date || newReservation.createdAt, // legacy
    dateKey,                                               // <- used by calendar
    petCount:
      (Array.isArray(newReservation.petRequests) && newReservation.petRequests.length)
        ? newReservation.petRequests.length
        : ((Array.isArray(newReservation.pets) && newReservation.pets.length)
            ? newReservation.pets.length
            : 1)
  }
});


return res.json({ success: true, reservation: newReservation });
    } catch (error) {
      console.error("Error submitting reservation:", error);
      return res.status(500).json({ success: false, message: "Server error" });
    }
  }
);



// Endpoint to get appointment count for a given time and date
// Cancel a reservation (increments cancelCount, may warn/suspend, pushes in-app messages)
router.post('/cancel-reservation', authMiddleware, async (req, res) => {
  try {
    // 1) Find reservation (must belong to the requesting user)
    const { reservationId } = req.body;
    const reservation = await Reservation.findOne({
      _id: reservationId,
      owner: req.user.userId
    });
    if (!reservation) {
      return res.status(404).json({ success: false, message: 'Reservation not found.' });
    }

    // 2) Increment & check user suspension
    const user = await User.findById(req.user.userId);
    const wasSuspended = !!user.isSuspended;

    user.cancelCount = (user.cancelCount || 0) + 1;

    // (a) Warning stage: exactly threshold - 1
    if (!wasSuspended && user.cancelCount === CANCEL_THRESHOLD - 1) {
      // email
      await sendWarningEmail(user.email, user.cancelCount);
      // in-app message
      await Message.create({
        user: user._id,
        type: 'warning',
        title: 'Careful — one more cancellation will suspend you',
        body: `You’ve cancelled ${user.cancelCount} out of ${CANCEL_THRESHOLD} allowed consultations. One more and your account will be suspended for ${SUSPEND_DAYS} day(s).`
      });
    }

    // (b) Suspension stage: reached threshold this time
    if (!wasSuspended && user.cancelCount >= CANCEL_THRESHOLD) {
      user.isSuspended = true;
      user.suspendedAt = new Date();

      // email
      await sendSuspensionEmail(user.email);
      // in-app message
      await Message.create({
        user: user._id,
        type: 'suspension',
        title: 'You have been suspended from submitting consultations',
        body: `Due to excessive cancellations, your account is suspended for ${SUSPEND_DAYS} day(s). You will regain access automatically afterwards. If you believe this is an error, please contact support.`
      });
    }

    await user.save();

    // 3) Update reservation status
    reservation.status = reservation.status === 'Pending'
      ? 'CanceledPending'
      : 'Canceled';
    reservation.canceledAt = new Date();
    reservation.doctor = undefined;
    await reservation.save();
// After: await reservation.save();

// compute the day this reservation was for
const dateKey =
  (reservation.date
    ? toYMD(reservation.date)
    : (reservation.schedule?.scheduleDate
        ? toYMD(reservation.schedule.scheduleDate)
        : toYMD(reservation.createdAt)));

// tell HR screens to remove it from Pending (and refresh calendar)
broadcast({
  type: 'reservation:canceled',
  id: String(reservation._id),
  reservation: {
    _id: String(reservation._id),
    dateKey
  }
});

    // 4) Respond (use justSuspended to update UI)
    const justSuspended = !wasSuspended && user.isSuspended && user.cancelCount >= CANCEL_THRESHOLD;
    return res.json({
      success: true,
      reservation,
      justSuspended,
      cancelCount: user.cancelCount
    });

  } catch (error) {
    console.error("Error canceling reservation:", error);
    return res.status(500).json({ success: false, message: 'Server error while canceling reservation.' });
  }
});




// Update pet details endpoint
router.put('/update-pet/:id', authMiddleware, async (req, res) => {
  try {
    const petId = req.params.id;
    const { petName, species, breed, birthday, existingDisease, sex } = req.body;
    const updatedPet = await Pet.findOneAndUpdate(
      { _id: petId, owner: req.user.userId },
      {
        petName,
        species,
        breed,
        birthday: birthday ? new Date(birthday) : null,
        existingDisease,
        sex
      },
      { new: true }
    );
    if (!updatedPet) {
      return res.status(404).json({ success: false, message: "Pet not found" });
    }
    return res.json({ success: true, pet: updatedPet });
  } catch (error) {
    console.error("Error updating pet:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Delete pet endpoint
router.post('/delete-pet', authMiddleware, async (req, res) => {
  try {
    const petId = req.body.id;
    if (!petId) {
      return res.status(400).json({ success: false, message: 'Pet ID is required' });
    }

    // delete only the user's own Pet doc
    const deletedPet = await Pet.findOneAndDelete({ _id: petId, owner: req.user.userId });
    if (!deletedPet) {
      return res.status(404).json({ success: false, message: 'Pet not found' });
    }

    // If there is a clinic PetList row with the same name for this owner,
    // mark that name as hidden for this user so it won't reappear in My Pets.
    const hasClinicRow = await PetList.exists({
      owner: req.user.userId,
      petName: deletedPet.petName
    });

    if (hasClinicRow) {
      await User.updateOne(
        { _id: req.user.userId },
        { $addToSet: { hiddenPetNames: deletedPet.petName } }
      );
    }

    return res.json({ success: true, hiddenMarked: !!hasClinicRow });
  } catch (error) {
    console.error("Error deleting pet:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

router.post('/delete-petlist', authMiddleware, async (req, res) => {
  try {
    const rawId = String(req.body.id || '');
    // we store rows as data-id="list-<mongoId>" in the UI
    const entryId = rawId.replace(/^list-/, '');
    if (!entryId) {
      return res.status(400).json({ success: false, message: 'PetList id is required.' });
    }

    const deleted = await PetList.findOneAndDelete({ _id: entryId, owner: req.user.userId });
    if (!deleted) {
      return res.status(404).json({ success: false, message: 'PetList entry not found.' });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('delete-petlist error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});


router.get('/get-pet-details', authMiddleware, async (req, res) => {
  try {
    let petDetails = await PetDetailsSetting.findOne().lean();
    if (!petDetails) {
      petDetails = { species: [], speciesBreeds: {}, diseases: [], services: [] };
    }
    res.json(petDetails);
  } catch (error) {
    console.error("Error fetching pet details:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Get consultation details for a reservation
// Get consultation details for a reservation  ✅ MULTI-PET
router.get(
  '/get-consultation',
  authMiddleware,
  validateRequest(reservationIdSchema, 'query'),
  async (req, res) => {
    try {
      const { reservationId } = req.query;

      // 1) reservation
      const reservation = await Reservation.findById(reservationId)
        .populate('doctor', 'username')
        .lean();
      if (!reservation) {
        return res.status(404).json({ success: false, message: 'Reservation not found.' });
      }

      // 2) all consults for this reservation (one per pet typically)
      const consults = await Consultation.find({ reservation: reservationId })
        .sort({ updatedAt: -1 }) // newest first
        .lean();

      // 3) index consults by target pet id and name
      const byId = new Map();
      const byName = new Map();
      for (const c of consults) {
        if (c.targetPetId) {
          const k = String(c.targetPetId);
          if (!byId.has(k)) byId.set(k, c); // keep latest per pet
        }
        if (c.targetPetName) {
          const k = String(c.targetPetName).trim().toLowerCase();
          if (!byName.has(k)) byName.set(k, c);
        }
      }

      // 4) map petRequests (requested service/concerns) for quick lookup
      const prById = new Map();
      const prByName = new Map();
      (reservation.petRequests || []).forEach(pr => {
        if (pr.petId) prById.set(String(pr.petId), pr);
        if (pr.petName) prByName.set(String(pr.petName).trim().toLowerCase(), pr);
      });

      // 5) choose pet list source (reservation.pets preferred)
      const petsSource = (reservation.pets && reservation.pets.length)
        ? reservation.pets
        : (reservation.petRequests || []).map(x => ({ petId: x.petId, petName: x.petName }));

      const perPets = [];

      // build per-pet blocks from petsSource
      for (const p of petsSource) {
        const idStr = p.petId ? String(p.petId) : null;
        const nameKey = (p.petName || '').trim().toLowerCase();

        let c = null;
        if (idStr && byId.has(idStr)) c = byId.get(idStr);
        else if (nameKey && byName.has(nameKey)) c = byName.get(nameKey);

        const pr = (idStr && prById.get(idStr)) || (nameKey && prByName.get(nameKey)) || null;

        perPets.push({
          petId: p.petId || null,
          petName: p.petName || (c && c.targetPetName) || 'Unknown',
          service: pr?.service || '',
          concerns: pr?.concerns || '',
          physicalExam: c?.physicalExam || null,
          overview: c?.overview || null,
          diagnosis: c?.diagnosis || '',
          services: c?.services || [],
          medications: c?.medications || [],
          confinementStatus: c?.confinementStatus || [],
          notes: c?.notes || c?.consultationNotes || ''
        });
      }

      // also include consults whose pets weren’t in reservation.pets (edge cases)
      for (const c of consults) {
        const nameKey = (c.targetPetName || '').trim().toLowerCase();
        const already = perPets.find(x =>
          (x.petId && c.targetPetId && String(x.petId) === String(c.targetPetId)) ||
          (x.petName && nameKey && x.petName.trim().toLowerCase() === nameKey)
        );
        if (!already) {
          const pr =
            (c.targetPetId && prById.get(String(c.targetPetId))) ||
            (nameKey && prByName.get(nameKey)) ||
            null;

          perPets.push({
            petId: c.targetPetId || null,
            petName: c.targetPetName || 'Unknown',
            service: pr?.service || '',
            concerns: pr?.concerns || '',
            physicalExam: c.physicalExam || null,
            overview: c.overview || null,
            diagnosis: c.diagnosis || '',
            services: c.services || [],
            medications: c.medications || [],
            confinementStatus: c.confinementStatus || [],
            notes: c.notes || c.consultationNotes || ''
          });
        }
      }

      // 6) Back-compat: keep a single consult’s fields on reservation (for old UIs)
      if (consults.length) {
        const first = consults[0];
        reservation.physicalExam = first.physicalExam;
        reservation.diagnosis = first.diagnosis;
        reservation.services = first.services;
        reservation.medications = first.medications;
        reservation.notes = first.notes || first.consultationNotes;
        reservation.confinementStatus = first.confinementStatus;
      }

      return res.json({ success: true, reservation, perPets });
    } catch (error) {
      console.error("Error fetching consultation details:", error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);



// customerRoutes.js
// GET /customer/get-pet-history
// at top of customerRoutes.js
const mongoose = require('mongoose');

// REPLACE the whole route definition with this:
router.get('/get-pet-history', authMiddleware, async (req, res) => {
  try {
    const { petId, petName } = req.query;
    const ownerId = req.user.userId;

    if (!petId && !petName) {
      return res.json({ success: false, message: 'petId or petName is required' });
    }

    // normalize petId: support "list-<ObjectId>" or plain ObjectId; otherwise fallback to petName
    let lookupId = null;
    if (petId) {
      const raw = String(petId);
      if (raw.startsWith('list-')) {
        const unpref = raw.slice(5);
        if (mongoose.Types.ObjectId.isValid(unpref)) lookupId = unpref;
      } else if (mongoose.Types.ObjectId.isValid(raw)) {
        lookupId = raw;
      }
    }

    const criteria = lookupId
      ? { _id: lookupId, owner: ownerId }
      : { owner: ownerId, petName };

    const entry = await PetList.findOne(criteria)
      .populate({
        path: 'consultationHistory.consultation',
        populate: [{
          path: 'reservation',
          // include _id explicitly for clarity
          select: 'date doctor schedule _id',
          populate: { path: 'doctor', select: 'username' }
        }]
      })
      .lean();

    if (!entry) return res.json({ success: true, history: [] });

    const history = (entry.consultationHistory || [])
      .map(ch => {
        const c    = ch.consultation || {};
        const resv = c.reservation || {};
        return {
          id:           c._id,
          date:         c.createdAt || ch.addedAt,
          doctor:       resv.doctor || null,
          notes:        c.notes || c.consultationNotes || '',
          physical:     c.physicalExam || { weight: '', temperature: '', observations: '' },
          diagnosis:    c.diagnosis || '',
          services:     (c.services || []).map(s => ({
                          category:    s.category || 'Uncategorized',
                          serviceName: s.serviceName || '',
                          details:     s.details || '',
                          file:        s.file || null
                        })),
          medications:  (c.medications || []).map(m => ({
                          name:     m.name || m.medicationName || '',
                          quantity: m.quantity || 0,
                          dosage:   m.dosage || '',
                          remarks:  m.remarks || ''
                        })),
          confinement:  c.confinementStatus || [],
          nextSchedule: resv.schedule
            ? { date: resv.schedule.scheduleDate, details: resv.schedule.scheduleDetails }
            : null,
          // ADDED: expose reservationId so the UI can show a Prescription button
          reservationId: resv._id || null
        };
      })
      .sort((a, b) => new Date(b.date) - new Date(a.date));

    res.json({ success: true, history });
  } catch (err) {
    console.error('customer/get-pet-history error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});



// In customerRoutes.js, after your other routes:

router.post('/send-email-otp', authMiddleware, async (req, res) => {
  try {
    const { newEmail } = req.body;
    if (!newEmail) {
      return res.status(400).json({ success: false, message: "New email is required." });
    }
    // Check if email is already taken
    const existingUser = await User.findOne({ email: newEmail });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "This email is already in use." });
    }
    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    // Save OTP along with the new email and a timestamp
    emailUpdateOtpStore[req.user.userId] = { otp, newEmail, createdAt: new Date() };
    
    // Configure nodemailer transporter
    const transporter = nodemailer.createTransport({
      host: "smtp-relay.brevo.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_PASS
      }
    });
    
    const mailOptions = {
      from: '"SmartVet" <dehe.marquez.au@phinmaed.com>',
      to: newEmail,
      subject: "Email Update OTP",
      text: `Your OTP code for email update is: ${otp}. It expires in 10 minutes.`
    };
    
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending OTP email:", error);
        return res.status(500).json({ success: false, message: "Failed to send OTP email." });
      }
      return res.json({ success: true, message: "OTP sent to new email." });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

router.post('/update-email', authMiddleware, async (req, res) => {
  try {
    const { newEmail, emailOTP } = req.body;
    const otpData = emailUpdateOtpStore[req.user.userId];
    if (!otpData) {
      return res.status(400).json({ success: false, message: "No OTP request found. Please request an OTP first." });
    }
    // Check if OTP is expired (10 minutes)
    const now = new Date();
    if ((now - otpData.createdAt) > 10 * 60 * 1000) {
      delete emailUpdateOtpStore[req.user.userId];
      return res.status(400).json({ success: false, message: "OTP expired. Please request a new one." });
    }
    if (otpData.otp !== emailOTP || otpData.newEmail !== newEmail) {
      return res.status(400).json({ success: false, message: "Invalid OTP or email mismatch." });
    }
    // Update user's email
    const updatedUser = await User.findByIdAndUpdate(req.user.userId, { email: newEmail }, { new: true });
    // Clear the OTP data
    delete emailUpdateOtpStore[req.user.userId];
    return res.json({ success: true, user: updatedUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});
router.post('/update-password', authMiddleware, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ success: false, message: "Password must be at least 8 characters long." });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const updatedUser = await User.findByIdAndUpdate(req.user.userId, { password: hashedPassword }, { new: true });
    return res.json({ success: true, message: "Password updated successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});
// used by your consult.ejs time-slot checker
async function countPetsBookedForSlot(dateISO, timeLabel) {
  const start = new Date(dateISO);
  const end   = new Date(dateISO);
  end.setDate(end.getDate() + 1);

  const agg = await Reservation.aggregate([
    {
      $match: {
        time: timeLabel,
        date: { $gte: start, $lt: end },
        status: { $in: ['Pending', 'Approved'] }
      }
    },
    {
      // choose petRequests length when present, else pets length, else 1
      $project: {
        petCount: {
          $cond: [
            { $gt: [ { $size: { $ifNull: ['$petRequests', []] } }, 0 ] },
            { $size: { $ifNull: ['$petRequests', []] } },
            {
              $cond: [
                { $gt: [ { $size: { $ifNull: ['$pets', []] } }, 0 ] },
                { $size: { $ifNull: ['$pets', []] } },
                1
              ]
            }
          ]
        }
      }
    },
    { $group: { _id: null, total: { $sum: '$petCount' } } }
  ]);

  return (agg[0]?.total) || 0;
}

// GET /customer/consult/appointmentCount
router.get('/consult/appointmentCount', authMiddleware, async (req, res) => {
  try {
    const { time, date } = req.query;
    const count = await countPetsBookedForSlot(date, time);
    res.json({ count });
  } catch (err) {
    console.error('appointmentCount error:', err);
    res.status(500).json({ count: 0 });
  }
});
// Let the client read the configured per-hour limit
router.get('/settings/appointmentLimit', authMiddleware, async (req, res) => {
try {
   const setting = await AppointmentSetting.findOne().lean();
   res.json({ success: true, limit: setting ? setting.limitPerHour : 5 });
} catch (e) {
    console.error('appointmentLimit read error:', e);
   res.json({ success: true, limit: 5 }); // safe default
 }
});
// in customerRoutes.js, above your module.exports
router.get('/get-pets', authMiddleware, async (req, res) => {
  try {
    const pets = await Pet.find({ owner: req.user.userId })
                          .lean()
                          .sort({ petName: 1 });
    res.json({ success: true, pets });
  } catch (err) {
    console.error("Error fetching pets:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
router.get('/prescription/:reservationId', authMiddleware, async (req, res) => {
  try {
   const { reservationId } = req.params;
    const reservation = await Reservation.findById(reservationId)
      .populate('doctor', 'username')
      .lean();
    if (!reservation) return res.status(404).send('Reservation not found');

    const consult = await Consultation.findOne({ reservation: reservationId }).lean();
    if (consult) reservation.medications = consult.medications;

    // render the EJS to a HTML string
    res.render('customer/prescription', { reservation }, (err, html) => {
      if (err) {
       console.error('EJS render error:', err);
        return res.status(500).send('Error rendering prescription');
      }
      // convert HTML to PDF
      pdf.create(html, { format: 'A4' }).toStream((err, stream) => {
        if (err) {
         console.error('PDF creation error:', err);
          return res.status(500).send('Error generating PDF');
        }
        // set headers so browser will download
        res.setHeader('Content-Type', 'application/pdf');
       res.setHeader(
          'Content-Disposition',
         `attachment; filename=prescription_${reservationId}.pdf`
        );
        stream.pipe(res);
      });
    });
  } catch (err) {
    console.error('Prescription route error:', err);
    res.status(500).send('Server error generating prescription');
  }
});
// Upload/update a pet's picture
router.post('/update-pet-image/:id', authMiddleware, upload.single('petPic'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded.' });
    }
    const petId = req.params.id;

    // Only allow updating *real* Pet docs owned by the user
    const pet = await Pet.findOneAndUpdate(
      { _id: petId, owner: req.user.userId },
      { petPic: '/uploads/' + req.file.filename },
      { new: true }
    );

    if (!pet) {
      return res.status(404).json({ success: false, message: 'Pet not found.' });
    }

    return res.json({ success: true, petPic: pet.petPic });
  } catch (err) {
    console.error('update-pet-image error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});
// Unread count (badge)
router.get('/messages/unread-count', authMiddleware, async (req, res) => {
  try {
    const count = await Message.countDocuments({ user: req.user.userId, isRead: false });
    res.json({ success: true, count });
  } catch (e) {
    console.error('unread-count error:', e);
    res.status(500).json({ success: false, count: 0 });
  }
});
router.get('/messages/count', authMiddleware, async (req, res) => {
  try {
    const unread = await Message.countDocuments({ user: req.user.userId, isRead: false });
    res.json({ success: true, unread });
  } catch (e) {
    console.error('messages/count error:', e);
    res.status(500).json({ success: false, unread: 0 });
  }
});

// Full list (latest first)
router.get('/messages', authMiddleware, async (req, res) => {
  try {
    const messages = await Message.find({ user: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();
    res.json({ success: true, messages });
  } catch (e) {
    console.error('messages list error:', e);
    res.status(500).json({ success: false, messages: [] });
  }
});
// Optional: list endpoint with limit support for older clients
router.get('/messages/list', authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
    const messages = await Message.find({ user: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();
    res.json({ success: true, messages });
  } catch (e) {
    console.error('messages/list error:', e);
    res.status(500).json({ success: false, messages: [] });
  }
});

// Mark read (ids[] or all:true)
router.post('/messages/mark-read', authMiddleware, async (req, res) => {
  try {
    const { ids, messageIds, all } = req.body || {};
    const list = Array.isArray(ids) ? ids
               : Array.isArray(messageIds) ? messageIds
               : [];

    const filter = all
      ? { user: req.user.userId, isRead: false }
      : (list.length ? { user: req.user.userId, _id: { $in: list } } : null);

    if (!filter) {
      return res.status(400).json({ success: false, message: 'Provide ids[] or all:true' });
    }

    await Message.updateMany(filter, { isRead: true, readAt: new Date() });
    res.json({ success: true });
  } catch (e) {
    console.error('mark-read error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
// Hide a clinic PetList row by name (do NOT delete PetList)
// POST /customer/hide-petlist
router.post('/hide-petlist', authMiddleware, async (req, res) => {
  try {
    const { petName } = req.body;
    if (!petName || !petName.trim()) {
      return res.status(400).json({ success: false, message: 'petName is required.' });
    }

    await User.updateOne(
      { _id: req.user.userId },
      { $addToSet: { hiddenPetNames: petName.trim() } }
    );

    return res.json({ success: true });
  } catch (err) {
    console.error('hide-petlist error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});


module.exports = router;
