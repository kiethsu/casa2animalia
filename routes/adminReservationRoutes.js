// routes/adminReservationRoutes.js
const express = require('express');
const router  = express.Router();
const Joi     = require('joi');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');

const authMiddleware = require('../middleware/authMiddleware');

// Models
const Reservation  = require('../models/reservation');
const User         = require('../models/user');
const Pet          = require('../models/pet');
const PetList      = require('../models/petlist');
const Consultation = require('../models/consultation');
const AppointmentSetting = require('../models/appointmentSetting');
const PetDetailsSetting  = require('../models/petDetailsSetting');
const Inventory    = require('../models/inventory');
const Service      = require('../models/service');
const MessageTemplate = require('../models/messageTemplate');
const Payment      = require('../models/Payment');
const ReservationMessage = require('../models/ReservationMessage');
const Message      = require('../models/message');

// SSE hub (reuse same broadcaster HR uses)
const { broadcast } = require('../utils/hrSse');

const { isValidObjectId } = mongoose;

function resolveOwnerTokens(rawId = '', rawName = '') {
  const id   = String(rawId || '').trim();
  const name = String(rawName || '').trim();
  return {
    ownerId:   id.startsWith('ID::')   ? id.slice(4)   : id,
    ownerName: name.startsWith('NAME::') ? name.slice(6) : name
  };
}


// ───────────────────────────────── helpers / guards ─────────────────────────────────
const roleOf = req => String(req?.user?.role || '').toLowerCase();
const allow = (...roles) => (req, res, next) => {
  const ok = roles.map(r => String(r).toLowerCase()).includes(roleOf(req));
  if (!ok) return res.status(403).send('Forbidden');
  next();
};

function validateRequest(schema, property = 'body') {
  return (req, res, next) => {
    const { error } = schema.validate(req[property]);
    if (error) return res.status(400).json({ message: error.details[0].message });
    next();
  };
}

function getBrevoTransport() {
  const host = process.env.SMTP_HOST || 'smtp-relay.brevo.com';
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_EMAIL;
  const pass = process.env.SMTP_PASS;
  if (!user || !pass) return null;
  return nodemailer.createTransport({
    host, port, secure: port === 465, auth: { user, pass }
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

// ───────────────────────────────── Joi Schemas ─────────────────────────────────
const reservationIdSchema = Joi.object({ reservationId: Joi.string().required() });

const declineReservationSchema = Joi.object({
  reservationId:        Joi.string().required(),
  templateId:           Joi.string().optional().allow(''),
  message:              Joi.string().optional().allow(''),
  alsoEmail:            Joi.boolean().truthy('true').falsy('false').default(false),
  sendToCustomerInbox:  Joi.boolean().truthy('true').falsy('false').default(true),
  suppressCustomerPopup:Joi.boolean().truthy('true').falsy('false').default(true)
});

const assignDoctorSchema = Joi.object({
  reservationId: Joi.string().required(),
  doctorId: Joi.string().required()
});

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

const addMedicationSchema = Joi.object({
  reservationId:   Joi.string().required(),
  medicationName:  Joi.string().required(),
  quantity:        Joi.number().min(1).required()
});

// ───────────────────────────────── RENDER: /admin/reservation ─────────────────────────────────
// Mirrors GET /hr/reservation but renders views/admin/reservation.ejs (which includes hr/reservation)
router.get('/reservation', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const reservations = await Reservation.find()
      .populate('doctor', 'username')
      .populate('owner', '_id username')
      .lean();

    // annotate flags using PetList (multi-pet aware)
    for (let r of reservations) {
      const petNames = (r.pets || [])
        .map(p => p.petId?.petName || p.petName)
        .filter(Boolean);

      if (!petNames.length) {
        r.petExists = false; r.isStacked = false; r.isInitialEntry = false;
        continue;
      }

      const entries = await PetList.find(
        { owner: r.owner, petName: { $in: petNames } },
        'petName reservation consultationHistory'
      ).lean();

      const byName = new Map(entries.map(e => [e.petName, e]));
      let allExist = true, allStacked = true, anyInitial = false;

      for (const name of petNames) {
        const entry = byName.get(name);
        if (!entry) { allExist = false; allStacked = false; continue; }
        const hasThisReservation = (entry.consultationHistory || [])
          .some(ch => String(ch.reservation) === String(r._id));
        if (!hasThisReservation) allStacked = false;
        if (String(entry.reservation) === String(r._id)) anyInitial = true;
      }
      r.petExists = allExist;
      r.isStacked = allStacked;
      r.isInitialEntry = anyInitial;
    }

    const ongoingReservations = reservations.filter(r =>
      (r.status === 'Paid' || r.status === 'Done' || !!r.doctor) &&
      !r.isInitialEntry && !r.isStacked
    );

    const doctors = await User.find({ role: 'Doctor' }).lean();
    const petDetails = (await PetDetailsSetting.findOne().lean()) || {
      species: [], speciesBreeds: {}, diseases: [], services: []
    };
    const pets = await Pet.find().populate('owner','username').lean();
    const petlistEntries = await PetList.find()
      .populate('owner','username')
      .lean();

    res.render('admin/reservation', {
      reservations,
      ongoingReservations,
      doctors,
      petDetails,
      pets,
      petlistEntries
    });
  } catch (e) {
    console.error('[admin] GET /reservation failed:', e);
    res.status(500).send('Server error');
  }
});

// ───────────────────────────────── ACTIONS (mirror HR endpoints) ─────────────────────────────────
// Small spinner so /spinner.svg rewrites to here
// Tiny inline spinner so the UI never 404s
router.get('/spinner.svg', (req, res) => {
  res.type('image/svg+xml').send(`
<svg width="28" height="28" viewBox="0 0 38 38" xmlns="http://www.w3.org/2000/svg" aria-label="loading">
  <defs>
    <linearGradient x1="8.042%" y1="0%" x2="65.682%" y2="23.865%" id="a">
      <stop stop-color="#999" stop-opacity="0" offset="0%"/>
      <stop stop-color="#999" stop-opacity=".631" offset="63.146%"/>
      <stop stop-color="#999" offset="100%"/>
    </linearGradient>
  </defs>
  <g fill="none" fill-rule="evenodd">
    <g transform="translate(1 1)">
      <path d="M36 18c0-9.94-8.06-18-18-18" stroke="url(#a)" stroke-width="3">
        <animateTransform attributeName="transform" type="rotate" from="0 18 18" to="360 18 18" dur="0.9s" repeatCount="indefinite"/>
      </path>
      <circle fill="#999" cx="36" cy="18" r="1">
        <animateTransform attributeName="transform" type="rotate" from="0 18 18" to="360 18 18" dur="0.9s" repeatCount="indefinite"/>
      </circle>
    </g>
  </g>
</svg>`);
});

// Approve reservation
router.post('/approve-reservation',
  authMiddleware, allow('admin'),
  validateRequest(reservationIdSchema),
  async (req, res) => {
    try {
      const { reservationId } = req.body;
      const reservation = await Reservation.findById(reservationId);
      if (!reservation) return res.status(404).json({ success:false, message:'Reservation not found.' });

      reservation.status = 'Approved';
      await reservation.save();

      // push to dashboards (SSE)
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

      // dismiss any customer popup
      try {
        const io = req.app.get('io');
        if (io) {
          io.to(`reservation:${reservation._id}`).emit('reservation:dismiss-notify', {
            reservationId: String(reservation._id),
            reason: 'approved'
          });
        }
      } catch (_) {}

      // email (best-effort)
      try {
        const customer = reservation.owner ? await User.findById(reservation.owner) : null;
        const toEmail = (customer && customer.email) || reservation.contactEmail;
        if (toEmail) {
          const displayName = (customer && (customer.username || customer.name)) ||
                              reservation.ownerName || 'Customer';
          const when =
            (reservation.date ? new Date(reservation.date).toLocaleDateString('en-PH') : '') +
            (reservation.time ? ` ${reservation.time}` : '');
          const subject = 'Your consultation is approved';
          const text =
`Hello ${displayName},

Your consultation${when ? ` on ${when}` : ''} has been approved by our team.
See you at the clinic!

Thank you,
SmartVet Clinic`;

          const transport = getBrevoTransport();
          if (transport) {
            const fromEmail = process.env.SENDER_EMAIL || process.env.SMTP_EMAIL;
            const fromName  = process.env.SENDER_NAME  || 'SmartVet Clinic';
            await transport.sendMail({
              from: `${fromName} <${fromEmail}>`,
              to: toEmail,
              subject,
              text,
              html: `<p>${esc(text).replace(/\n/g,'<br>')}</p>`
            });
          }
        }
      } catch (mailErr) {
        console.error('[admin] approval email failed:', mailErr);
      }

      return res.json({ success:true, reservation });
    } catch (err) {
      console.error('[admin] approve-reservation error:', err);
      res.status(500).json({ success:false, message:'Server error' });
    }
  }
);

// Decline reservation
router.post('/decline-reservation',
  authMiddleware, allow('admin'),
  validateRequest(declineReservationSchema),
  async (req, res) => {
    try {
      const {
        reservationId, templateId, message,
        alsoEmail, sendToCustomerInbox, suppressCustomerPopup
      } = req.body;

      const reservation = await Reservation.findById(reservationId)
        .populate('owner','_id username email')
        .lean();
      if (!reservation) return res.status(404).json({ success:false, message:'Reservation not found.' });

      let finalMessageText = (message || '').trim();
      if (!finalMessageText && templateId) {
        const tmpl = await MessageTemplate.findById(templateId).lean();
        if (!tmpl || tmpl.type !== 'declined') {
          return res.status(400).json({ success:false, message:'Invalid decline template.' });
        }
        finalMessageText = String(tmpl.body || '').trim();
      }
      if (!finalMessageText) {
        return res.status(400).json({ success:false, message:'Please select a decline reason or enter a message.' });
      }

      if (sendToCustomerInbox && reservation.owner?._id) {
        await Message.create({
          user: reservation.owner._id,
          type: 'declined',
          title:'Reservation declined',
          body: finalMessageText,
          isRead:false
        });
      }

      if (!suppressCustomerPopup) {
        try {
          const io = req.app.get('io');
          if (io) {
            io.to(`reservation:${reservationId}`).emit('reservation:notify', {
              reservationId: String(reservationId),
              text: finalMessageText,
              reason: 'declined'
            });
          }
        } catch (_) {}
      }

      // email (optional)
      let emailSent = false, emailError = null;
      try {
        const toEmail = (reservation.owner && reservation.owner.email) || reservation.contactEmail || null;
        if (alsoEmail && toEmail) {
          const transport = getBrevoTransport();
          if (transport) {
            const fromEmail = process.env.SENDER_EMAIL || process.env.SMTP_EMAIL;
            const fromName  = process.env.SENDER_NAME  || 'SmartVet Clinic';
            await transport.sendMail({
              from: `${fromName} <${fromEmail}>`,
              to: toEmail,
              subject: 'Appointment Declined',
              text: finalMessageText,
              html: `<p>${esc(finalMessageText).replace(/\n/g,'<br>')}</p>`
            });
            emailSent = true;
          } else {
            emailError = 'SMTP not configured';
          }
        }
      } catch (e) {
        console.error('[admin] decline email failed:', e);
        emailError = e.message || 'sendMail failed';
      }

      await Reservation.updateOne({ _id: reservationId }, { $set: { status: 'Canceled' } });

      try {
        const io = req.app.get('io');
        if (io) {
          io.to(`reservation:${reservationId}`).emit('reservation:dismiss-notify', {
            reservationId: String(reservationId),
            reason: 'declined'
          });
        }
      } catch (_) {}

      broadcast({ type: 'reservation:declined', id: String(reservationId) });

      return res.json({ success:true, email: { sent: emailSent, error: emailError } });
    } catch (err) {
      console.error('[admin] decline-reservation error:', err);
      res.status(500).json({ success:false, message:'Server error' });
    }
  }
);

// Assign doctor
router.post('/assign-doctor',
  authMiddleware, allow('admin'),
  validateRequest(assignDoctorSchema),
  async (req, res) => {
    try {
      const { reservationId, doctorId } = req.body;
      const reservation = await Reservation.findById(reservationId);
      if (!reservation) return res.status(404).json({ success:false, message:'Reservation not found.' });
      if (reservation.doctor && String(reservation.doctor) === doctorId) {
        return res.status(400).json({ success:false, message:'Doctor already assigned.' });
      }

      reservation.doctor = doctorId;
      await reservation.save();

      await reservation.populate([
        { path: 'doctor', select: 'username' },
        { path: 'pets.petId', select: 'petName' }
      ]);

      const updated = reservation.toObject();
      const reqs = Array.isArray(updated.petRequests) ? updated.petRequests : [];
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

      broadcast({
        type: 'reservation:assigned',
        id: String(updated._id),
        doctorId: String(updated.doctor?._id || doctorId),
        reservation: {
          _id: String(updated._id),
          ownerName: updated.ownerName,
          service: updated.service,
          time: updated.time,
          date: updated.date || updated.createdAt,
          doctor: updated.doctor && { _id: String(updated.doctor._id), username: updated.doctor.username }
        },
        rows
      });

      return res.json({ success:true, reservation: updated });
    } catch (err) {
      console.error('[admin] assign-doctor error:', err);
      res.status(500).json({ success:false, message:'Server error' });
    }
  }
);

// Consultation detail (price-enriched, newest-per-pet)
router.get('/get-consultation-details', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { reservationId } = req.query;
    if (!reservationId) return res.json({ success:false, message:'Missing reservationId' });

    const reservation = await Reservation.findById(reservationId)
      .populate('owner','username')
      .populate('pets.petId','petName')
      .lean();
    if (!reservation) return res.json({ success:false, message:'Reservation not found' });

    // mirror HR logic to compute flags + latest consult per pet and enrich with prices
    const consultDocs = await Consultation
      .find({ reservation: reservationId })
      .sort({ updatedAt: -1, _id: -1 })
      .lean();

    const latestByPet = new Map();
    for (const c of consultDocs) {
      const key = c.targetPetId
        ? `id:${c.targetPetId}`
        : `name:${(c.targetPetName || c.petName || '').trim().toLowerCase()}`;
      if (!latestByPet.has(key)) latestByPet.set(key, c);
    }

    const consultations = [];
    for (const c of latestByPet.values()) {
      // resolve pet name
      function resolvePetName(c0) {
        if (c0?.targetPetName && String(c0.targetPetName).trim()) return String(c0.targetPetName).trim();
        if (c0?.petName && String(c0.petName).trim())             return String(c0.petName).trim();
        const petsArr = reservation.pets || [];
        const candidateId = c0?.targetPetId || c0?.petId;
        if (candidateId && mongoose.isValidObjectId(candidateId)) {
          const hitById = petsArr.find(p => String(p.petId?._id) === String(candidateId));
          if (hitById) return hitById.petId?.petName || hitById.petName || '—';
        }
        const candidateName =
          (typeof candidateId === 'string' && !mongoose.isValidObjectId(candidateId))
            ? candidateId
            : (c0?.targetPetName || c0?.petName || null);
        if (candidateName) {
          const hitByName = petsArr.find(p => (p.petId?.petName || p.petName) === candidateName);
          if (hitByName) return hitByName.petId?.petName || hitByName.petName || '—';
        }
        if (petsArr.length === 1) return petsArr[0].petId?.petName || petsArr[0].petName || '—';
        return '—';
      }

      // meds
      const meds = [];
      for (const m of (c.medications || [])) {
        const medName = m.name || m.medicationName || '';
        let inv = null;
        if (medName) inv = await Inventory.findOne({ name: medName }).lean();
        const unitPrice = (() => {
          if (typeof m.unitPrice === 'number') return m.unitPrice;
          if (inv) {
            if (typeof inv.price === 'number') return inv.price;
            const b  = Number(inv.basePrice || 0);
            const mk = Number(inv.markup || 0);
            return b + mk;
          }
          return 0;
        })();

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

      // services
      const svcs = [];
      for (const s of (c.services || [])) {
        let svcDoc = null;
        if (s.serviceId) { try { svcDoc = await Service.findById(s.serviceId).lean(); } catch(_) {} }
        if (!svcDoc && s.serviceName) svcDoc = await Service.findOne({ serviceName: s.serviceName }).lean();
        svcs.push({
          ...s,
          serviceName: s.serviceName || (svcDoc?.serviceName || ''),
          price: (typeof s.price === 'number') ? s.price : (svcDoc?.price || 0)
        });
      }

      consultations.push({
        petId: c.petId || null,
        petName: resolvePetName(c),
        medications: meds,
        services: svcs
      });
    }

    const payment = await Payment.findOne({ reservation: reservationId }).lean();

    // PetList flags (copied logic from HR route, trimmed)
    let petExists=false, isStacked=false, isInitialEntry=false;
    const petNames = (reservation.pets||[]).map(p => p?.petId?.petName || p?.petName).filter(Boolean);
    if (petNames.length) {
      const ownerId = reservation.owner?._id || reservation.owner || null;
      const lookup = ownerId
        ? { owner: ownerId, petName: { $in: petNames } }
        : { ownerName: reservation.ownerName, petName: { $in: petNames } };
      const entries = await PetList.find(lookup,'petName reservation consultationHistory').lean();
      const byName = new Map(entries.map(e => [e.petName, e]));
      let allExist=true, allStacked_=true, anyInitial=false;
      for (const n of petNames) {
        const entry = byName.get(n);
        if (!entry) { allExist=false; allStacked_=false; continue; }
        const hasThis = (entry.consultationHistory||[])
          .some(ch => String(ch.reservation) === String(reservation._id));
        if (!hasThis) allStacked_ = false;
        if (String(entry.reservation) === String(reservation._id)) anyInitial = true;
      }
      petExists = allExist; isStacked = allStacked_; isInitialEntry = anyInitial;
    }

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
    console.error('[admin] get-consultation-details failed:', err);
    res.status(500).json({ success:false, message:'Server error' });
  }
});

// Compact consultation (used by some modals)
router.get('/get-consultation', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { reservationId } = req.query;
    if (!reservationId) return res.status(400).json({ success:false, message:'reservationId is required.' });

    const reservation = await Reservation.findById(reservationId)
      .populate('doctor','username')
      .populate('pets.petId','petName birthday species breed sex')
      .lean();
    if (!reservation) return res.status(404).json({ success:false, message:'Reservation not found.' });

    const consult = await Consultation.findOne({ reservation: reservationId }).lean();
    if (consult) {
      reservation.physicalExam      = consult.physicalExam;
      reservation.diagnosis         = consult.diagnosis;
      reservation.services          = consult.services;
      reservation.medications       = consult.medications;
      reservation.notes             = consult.notes;
      reservation.confinementStatus = consult.confinementStatus;
    }
    res.json({ success:true, reservation });
  } catch (err) {
    console.error('[admin] get-consultation error:', err);
    res.status(500).json({ success:false, message:'Server error' });
  }
});

// Message templates (alias that HR UI expects)
router.get('/message-templates', authMiddleware, allow('admin'), async (req, res) => {
  try {
    let type = String(req.query.type || 'notif').trim().toLowerCase();
    if (type === 'notify') type = 'notif';
    const templates = await MessageTemplate
      .find({ type })
      .select('_id title body isDefault')
      .sort({ isDefault: -1, createdAt: -1 })
      .lean();
    res.json({ success:true, templates });
  } catch (e) {
    console.error('[admin] message-templates failed:', e);
    res.status(500).json({ success:false, message:'Failed to load message templates.' });
  }
});

// Notify reservation (popup + optional email)
const notifySchema = Joi.object({
  reservationId: Joi.string().required(),
  templateId: Joi.string().optional().allow(''),
  message: Joi.string().optional().allow(''),
  emailMessage: Joi.string().optional().allow(''),
  interactive: Joi.boolean().truthy('true').falsy('false').optional(),
  reason: Joi.string().optional().allow('')
});
router.post('/notify-reservation',
  authMiddleware, allow('admin'),
  async (req, res) => {
    try {
      const reservationId = req.body.reservationId || req.body.id;
      const templateId    = req.body.templateId    || req.body.template || '';
      const messageIn     = req.body.message       || req.body.body     || '';
      const emailMessage  = req.body.emailMessage  || '';
      const interactive   = !!(req.body.interactive);
      const reason        = req.body.reason || null;

      if (!reservationId || (!templateId && !messageIn)) {
        return res.status(400).json({ success:false, message:'Missing inputs.' });
      }

      const reservation = await Reservation.findById(reservationId)
        .populate('owner','_id username email')
        .lean();
      if (!reservation) return res.json({ success:false, message:'Reservation not found.' });

      // resolve in-app text
      let inAppText = (messageIn || '').trim();
      if (!inAppText && templateId) {
        const tmpl = await MessageTemplate.findById(templateId).lean();
        if (!tmpl) return res.json({ success:false, message:'Template not found.' });
        inAppText = String(tmpl.body || '').trim();
      }
      if (!inAppText) return res.json({ success:false, message:'No message text.' });

      const emailText = (emailMessage && String(emailMessage).trim()) || inAppText;
      const subject =
        String(reason || '').toLowerCase() === 'doctor_unavailable'
          ? 'Doctor unavailable — quick action'
          : 'Appointment Update';

      const msgDoc = await ReservationMessage.create({
        reservation: reservation._id,
        toOwner: reservation.owner?._id || undefined,
        ownerName: reservation.ownerName || reservation.owner?.username || '',
        body: inAppText,
        templateId: templateId || undefined,
        status: 'sent'
      });

      try {
        const io = req.app.get('io');
        if (io) {
          io.to(`reservation:${reservation._id}`).emit('reservation:notify', {
            id: String(msgDoc._id),
            reservationId: String(reservation._id),
            text: inAppText,
            interactive,
            reason
          });
        }
      } catch (_) {}

      const toEmail = (reservation.owner && reservation.owner.email) || reservation.contactEmail || null;
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
          console.error('[admin] notify email failed:', err);
          emailError = err.message || 'sendMail failed';
        }
      }

      return res.json({
        success:true,
        message:'Sent.',
        id: String(msgDoc._id),
        email: { attempted: !!toEmail, sent: emailSent, error: emailError }
      });
    } catch (e) {
      return res.status(500).json({ success:false, message: e.message || 'Failed to send.' });
    }
  }
);


// Last message state (for banner)
router.get('/reservation-message-state', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { reservationId } = req.query;
    if (!reservationId) return res.json({ success:false, message:'Missing reservationId' });
    const last = await ReservationMessage
      .findOne({ reservation: reservationId })
      .sort({ createdAt: -1 })
      .lean();
    if (!last) return res.json({ success:true, last: null });
    return res.json({
      success: true,
      last: {
        id: String(last._id),
        status: last.status || 'sent',
        response: last.response || null,
        body: last.body || null,
        createdAt: last.createdAt
      }
    });
  } catch (e) {
    return res.json({ success:false, message: e.message || 'Failed to fetch message state' });
  }
});

// Simple notify alias (used by some HR code)
router.post('/reservations/:id/notify', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { body, alsoEmail } = req.body || {};
    if (!body || !body.trim()) {
      return res.status(400).json({ success:false, message:'Message body is required.' });
    }
    const reservation = await Reservation.findById(id).lean();
    if (!reservation) return res.status(404).json({ success:false, message:'Reservation not found.' });

    const msg = await ReservationMessage.create({
      reservation: id, body: body.trim(), status:'sent', createdAt: new Date()
    });

    try {
      const io = req.app.get('io');
      if (io) {
        io.to(`reservation:${id}`).emit('reservation:notify', {
          id: String(msg._id), reservationId: String(id), body: msg.body, sentAt: msg.createdAt
        });
      }
    } catch (_) {}

    let emailSent = false;
    if (alsoEmail) {
      const customer = await User.findById(reservation.owner).lean();
      if (customer?.email) {
        const transport = getBrevoTransport();
        if (transport) {
          const fromEmail = process.env.SENDER_EMAIL || process.env.SMTP_EMAIL;
          const fromName  = process.env.SENDER_NAME  || 'SmartVet Clinic';
          await transport.sendMail({
            from: `${fromName} <${fromEmail}>`,
            to: customer.email,
            subject: 'Message from SmartVet about your reservation',
            text: body.trim(),
            html: `<p>${esc(body.trim()).replace(/\n/g,'<br>')}</p>`
          });
          emailSent = true;
        }
      }
    }
    return res.json({ success:true, emailSent });
  } catch (err) {
    console.error('[admin] /reservations/:id/notify error:', err);
    return res.status(500).json({ success:false, message:'Server error sending notification.' });
  }
});

// Medications CRUD (inline edits in modal)
router.post('/update-medication',
  authMiddleware, allow('admin'),
  validateRequest(Joi.object({
    reservationId: Joi.string().required(),
    medicationName:Joi.string().required(),
    quantity:      Joi.number().min(0).required()
  })),
  async (req, res) => {
    try {
      const { reservationId, medicationName, quantity } = req.body;
      const consult = await Consultation.findOne({ reservation: reservationId });
      if (!consult) return res.status(404).json({ success:false, message:'No consultation.' });
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

router.post('/remove-medication',
  authMiddleware, allow('admin'),
  validateRequest(Joi.object({
    reservationId: Joi.string().required(),
    medicationName:Joi.string().required()
  })),
  async (req, res) => {
    try {
      const { reservationId, medicationName } = req.body;
      const consult = await Consultation.findOne({ reservation: reservationId });
      if (!consult) return res.status(404).json({ success:false, message:'No consultation.' });
      consult.medications = consult.medications.filter(m => m.name !== medicationName);
      await consult.save();
      res.json({ success:true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success:false, message:'Server error' });
    }
  }
);

router.post('/add-medication',
  authMiddleware, allow('admin'),
  validateRequest(addMedicationSchema),
  async (req, res) => {
    try {
      const { reservationId, medicationName, quantity } = req.body;
      const consult = await Consultation.findOne({ reservation: reservationId });
      if (!consult) return res.status(404).json({ success:false, message:'Consultation not found.' });
      consult.medications.push({ name: medicationName, quantity, added: true });
      await consult.save();
      res.json({ success:true });
    } catch (err) {
      console.error('Error adding medication:', err);
      res.status(500).json({ success:false, message:'Server error.' });
    }
  }
);

// Billing: mark paid (reservation)
router.post('/mark-paid',
  authMiddleware, allow('admin'),
  validateRequest(markPaidSchema),
  async (req, res) => {
    try {
      const { reservationId } = req.body;
      const products = Array.isArray(req.body.products) ? req.body.products : [];
      const services = Array.isArray(req.body.services) ? req.body.services : [];

      const reservation = await Reservation.findById(reservationId);
      if (!reservation) return res.status(404).json({ success:false, message:'Reservation not found.' });

      const names = [...new Set(products.map(p => p.name).filter(Boolean))];
      const invDocs = names.length
        ? await Inventory.find({ name: { $in: names } }, 'name price basePrice markup quantity').lean()
        : [];
      const invByName = new Map(invDocs.map(d => [d.name, d]));

      const cleanProducts = products.map(p => {
        const inv = invByName.get(p.name);
        const unit = inv
          ? (typeof inv.price === 'number' ? inv.price : (Number(inv.basePrice||0) + Number(inv.markup||0)))
          : Number(p.unitPrice || 0);
        const qty = Number(p.quantity || 0);
        const lineTotal = parseFloat((unit * qty).toFixed(2));
        return { name: p.name, quantity: qty, unitPrice: unit, lineTotal };
      });

      const cleanServices = services.map(s => {
        const qty = Number(s.quantity || 0);
        const unit = Number(s.unitPrice || 0);
        const lineTotal = parseFloat((unit * qty).toFixed(2));
        return { name: s.name, quantity: qty, unitPrice: unit, lineTotal };
      });

      const computedAmount =
        cleanProducts.reduce((sum, i) => sum + i.lineTotal, 0) +
        cleanServices.reduce((sum, i) => sum + i.lineTotal, 0);

      reservation.status = 'Paid';
      await reservation.save();

      // decrement inventory
      for (const { name, quantity } of cleanProducts) {
        const inv = invByName.get(name) || await Inventory.findOne({ name }).lean();
        if (!inv) continue;
        const newQty = Math.max(Number(inv.quantity || 0) - Number(quantity || 0), 0);
        await Inventory.updateOne({ _id: inv._id }, { $set: { quantity: newQty } });
      }

      const payment = new Payment({
        reservation: reservation._id,
        customer:    reservation.owner || undefined,
        customerName: reservation.ownerName || '',
        by:           req.user.userId,
        products:     cleanProducts,
        services:     cleanServices,
        amount:       parseFloat(computedAmount.toFixed(2))
      });
      await payment.save();

      res.json({ success:true, reservation, paymentId: String(payment._id) });
    } catch (err) {
      console.error('[admin] mark-paid error:', err);
      res.status(500).json({ success:false, message:'Server error' });
    }
  }
);

// POS / retail
const retailPaidSchema = Joi.object({
  customerName: Joi.string().optional().allow(''),
  amount:        Joi.number().min(0).required(),
  products:      Joi.array().items(lineItemSchema).min(1).required()
});
router.post('/mark-paid-retail',
  authMiddleware, allow('admin'),
  validateRequest(retailPaidSchema),
  async (req, res) => {
    try {
      const { customerName, products } = req.body;

      const cleanProducts = (products || []).map(p => ({
        name:      p.name,
        quantity:  Number(p.quantity)||0,
        unitPrice: Number(p.unitPrice)||0,
        lineTotal: Number(p.lineTotal)||0
      }));

      // recompute amount server-side for safety
      const amount = Number(
        cleanProducts.reduce((s,i)=> s + (Number(i.unitPrice||0)*Number(i.quantity||0)), 0).toFixed(2)
      );

      for (const { name, quantity } of cleanProducts) {
        const invDoc = await Inventory.findOne({ name }).lean();
        if (!invDoc) continue;
        const newQty = Math.max((invDoc.quantity || 0) - Number(quantity || 0), 0);
        await Inventory.updateOne({ _id: invDoc._id }, { $set: { quantity: newQty } });
      }

      const payment = new Payment({
        isRetail: true,
        customer: undefined,
        customerName: (customerName && customerName.trim()) || 'Walk-in',
        by: req.user.userId,
        amount,
        products: cleanProducts,
        services: []
      });
      await payment.save();

      res.json({ success:true, paymentId: String(payment._id) });
    } catch (err) {
      console.error('[admin] mark-paid-retail failed:', err);
      res.status(500).json({ success:false, message:'Server error' });
    }
  }
);

// Helper used by walk-in owner pet dropdowns (kept minimal)
router.get('/get-owner-pets', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { ownerId, ownerName } = req.query;
    if (ownerId) {
      const listEntries = await PetList.find({ owner: ownerId }).lean();
      const listNames   = listEntries.map(e => e.petName);
      const realPets    = await Pet.find({ owner: ownerId }).lean();
      const realNames   = realPets.map(p => p.petName);
      const allNames = Array.from(new Set([...realNames, ...listNames]));
      return res.json({ pets: allNames });
    }
    if (ownerName && ownerName.trim()) {
      const listEntries = await PetList.find({ ownerName: ownerName.trim() }).lean();
      const listNames   = listEntries.map(e => e.petName);
      const allNames    = Array.from(new Set(listNames));
      return res.json({ pets: allNames });
    }
    return res.json({ pets: [] });
  } catch (e) {
    console.error('[admin] get-owner-pets failed:', e);
    res.json({ pets: [] });
  }
});
// === Helpers
const pickRow = (r) => ({
  _id: String(r._id),
  ownerName: r.ownerName || '',
  contactEmail: r.contactEmail || '',
  contactMobile: r.contactMobile || '',
  status: r.status || '',
  date: r.date,
  time: r.time,
  doctor: r.doctor
    ? { _id: String(r.doctor._id || r.doctor), username: r.doctor.username || '' }
    : null,
  pets: (r.pets || []).map(p => ({
    petId: p?.petId?._id ? String(p.petId._id) : null,
    petName: p?.petId?.petName || p?.petName || '',
    schedule: p?.schedule || null,
    done: !!p?.done
  }))
});

// === List reservations (multiple aliases the HR UI probes)
router.get([
  '/reservations',
  '/list-reservations',
  '/api/reservations',
  '/reservations/list',
  '/pending-reservations',
  '/reservations/pending'
], authMiddleware, allow('admin'), async (req, res) => {
  try {
    const forcePending =
      req.path.endsWith('/pending') || req.path.endsWith('/pending-reservations');
    const status = (req.query.status || (forcePending ? 'Pending' : '')).trim();

    const q = {};
    if (status) q.status = status;

    // 🔽 enable one of these based on your schema
    const hrId = req.viewAsHrId;
    // if (hrId) q.hr = hrId;              // if you store reservation.hr
    // if (hrId) q.createdBy = hrId;       // if you store reservation.createdBy

    const items = await Reservation.find(q)
      .populate('doctor', 'username')
      .populate('pets.petId', 'petName')
      .sort({ createdAt: -1 })
      .lean();

    return res.json({ success: true, reservations: items.map(pickRow) });
  } catch (e) {
    console.error('[admin] reservations list error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});


router.all('/batch-reservation-message-state',
  authMiddleware, allow('admin'),
  async (req, res) => {
    try {
      let ids = req.query.ids || req.query.id || (req.body && (req.body.ids || req.body.id)) || '';
      if (typeof ids === 'string') {
        ids = ids.split(',').map(s => s.trim()).filter(Boolean);
      }
      if (!Array.isArray(ids) || !ids.length) {
        return res.json({ success: true, states: {} });
      }

      const wanted = ids
        .map(v => mongoose.Types.ObjectId.isValid(v) ? new mongoose.Types.ObjectId(v) : null)
        .filter(Boolean);

      const rows = await ReservationMessage.aggregate([
        { $match: { reservation: { $in: wanted } } },
        { $sort:  { createdAt: -1, _id: -1 } },
        { $group: { _id: '$reservation', last: { $first: '$$ROOT' } } }
      ]);

      const states = {};
      for (const r of rows) {
        const last = r.last || {};
        states[String(r._id)] = {
          id:       String(last._id || ''),
          status:   last.status || 'sent',
          response: last.response || null,
          createdAt:last.createdAt || null
        };
      }

      return res.json({ success: true, states });
    } catch (e) {
      console.error('[admin] batch-reservation-message-state error:', e);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);

// GET /admin/consult/appointmentCount?date=YYYY-MM-DD&time=H%3AMM%20AM
router.get('/consult/appointmentCount', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const { date, time } = req.query;
    if (!date || !time) return res.status(400).json({ success:false, message:'Missing date/time' });

    // Count reservations that collide with the same date+time (loose match to mirror customer version)
    const rows = await Reservation.find({ date, time, status: { $in: ['Pending','Approved','Paid'] } }).lean();
    res.json({ success:true, count: rows.length });
  } catch (e) {
    console.error('[admin] consult/appointmentCount failed:', e);
    res.status(500).json({ success:false, message:'Server error' });
  }
});
async function stackFromReservation(reservationId) {
  const reservation = await Reservation.findById(reservationId).lean();
  if (!reservation) return { ok:false, status:404, message:'Reservation not found.' };

  const consults = await Consultation.find({ reservation: reservationId }).lean();
  if (!consults.length) return { ok:false, status:404, message:'No consult found.' };

  let contactEmail  = reservation.contactEmail  || null;
  let contactMobile = reservation.contactMobile || null;
  if (reservation.owner) {
    const ownerDoc = await User.findById(reservation.owner).lean();
    if (ownerDoc) {
      if (!contactEmail)  contactEmail  = ownerDoc.email || null;
      if (!contactMobile) contactMobile = ownerDoc.cellphone || null;
    }
  }

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
      await PetList.create({
        owner: reservation.owner ?? undefined,
        ownerName: reservation.ownerName,
        petName,
        reservation: reservationId,
        contactEmail,
        contactMobile,
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
          { $set: setPayload,
            $push: { consultationHistory: { reservation: reservationId, consultation: c._id } } }
        );
      } else if (!hasThis) {
        await PetList.updateOne(
          { _id: entry._id },
          { $push: { consultationHistory: { reservation: reservationId, consultation: c._id } } }
        );
      } else if (Object.keys(setPayload).length) {
        await PetList.updateOne({ _id: entry._id }, { $set: setPayload });
      }
    }
  }

  await Reservation.findByIdAndUpdate(reservationId, { status: 'Done' });
  return { ok:true };
}



router.post('/add-to-petlist', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const reservationId = req.body.reservationId;
    if (reservationId) {
      const r = await stackFromReservation(reservationId);
      if (!r.ok) return res.status(r.status || 400).json({ success:false, message:r.message || 'Failed' });
      return res.json({ success:true });
    }

    // fallback legacy shape: { ownerId/ownerName, petName }
    const { ownerId, ownerName } = req.body || {};
    const petName = (req.body.petName || '').trim();
    if (!petName || (!ownerId && !ownerName)) {
      return res.status(400).json({ success:false, message:'ownerId/ownerName and petName are required' });
    }
    const q = ownerId ? { owner: ownerId, petName } : { ownerName, petName };
    let doc = await PetList.findOne(q);
    if (!doc) doc = new PetList(q);
    await doc.save();
    return res.json({ success:true, petlistId: String(doc._id) });
  } catch (e) {
    console.error('[admin] add-to-petlist failed:', e);
    res.status(500).json({ success:false, message:'Server error' });
  }
});

router.post('/update-petlist', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const reservationId = req.body.reservationId;
    if (reservationId) {
      const r = await stackFromReservation(reservationId);
      if (!r.ok) return res.status(r.status || 400).json({ success:false, message:r.message || 'Failed' });
      return res.json({ success:true });
    }

    // fallback legacy shape
    const { ownerId, ownerName } = req.body || {};
    const petName = (req.body.petName || '').trim();
    if (!petName || (!ownerId && !ownerName)) {
      return res.status(400).json({ success:false, message:'ownerId/ownerName and petName are required' });
    }
    const q = ownerId ? { owner: ownerId, petName } : { ownerName, petName };
    let doc = await PetList.findOne(q);
    if (!doc) doc = new PetList(q);
    await doc.save();
    return res.json({ success:true, petlistId: String(doc._id) });
  } catch (e) {
    console.error('[admin] update-petlist failed:', e);
    res.status(500).json({ success:false, message:'Server error' });
  }
});

// POST /admin/walkin-reservation
// body: { ownerName, contactMobile?, contactEmail?, pets:[{petName}], service?, date?, time? }
router.post('/walkin-reservation', authMiddleware, allow('admin'), async (req, res) => {
  try {
    const b = req.body || {};

    // CASE A: HR-shaped body (petName + ownerId/ownerName tokens)
    if (b.petName) {
      const { ownerId, ownerName } = resolveOwnerTokens(b.ownerId, b.ownerName);

      let userId = null;
      let nameToSave = '';
      if (ownerId) {
        const existing = await User.findById(ownerId).lean();
        if (!existing) return res.status(400).json({ success:false, message:'Invalid owner.' });
        userId = existing._id;
        nameToSave = existing.username;
      } else {
        if (!ownerName) return res.status(400).json({ success:false, message:'Owner name is required for walk-in.' });
        nameToSave = ownerName;
      }

      const reservation = await Reservation.create({
        owner:     userId || undefined,
        ownerName: nameToSave,
        walkIn:    true,
        pets:      [{ petName: b.petName }],
        service:   b.service || '',
        concerns:  b.concerns || '',
        date:      b.date || null,
        time:      b.time || null,
        status:    'Approved',
        contactEmail:  (b.contactEmail  && b.contactEmail.trim())  || undefined,
        contactMobile: (b.contactMobile && b.contactMobile.trim()) || undefined,
        // optional quick meta for new pets
        isExistingPet: b.isExistingPet !== undefined ? !!b.isExistingPet : undefined,
        species: b.species || undefined,
        breed:   b.breed   || undefined,
        sex:     b.sex     || undefined,
        disease: b.existingDisease === 'Other' ? (b.otherDisease || '') : (b.existingDisease || '')
      });

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

      return res.json({ success:true, reservationId: String(reservation._id) });
    }

    // CASE B: Admin-simple body (ownerName + pets[])
    if (!b.ownerName || !Array.isArray(b.pets) || !b.pets.length) {
      return res.status(400).json({ success:false, message:'ownerName and pets[] are required' });
    }

    const reservation = await Reservation.create({
      ownerName: b.ownerName,
      contactMobile: b.contactMobile || '',
      contactEmail:  b.contactEmail || '',
      service: b.service || '',
      date: b.date || null,
      time: b.time || null,
      status: 'Approved',
      pets: (b.pets || []).map(p => ({ petName: p.petName || p }))
    });

    broadcast({
      type: 'reservation:created',
      id: String(reservation._id),
      reservation: {
        _id: String(reservation._id),
        ownerName: reservation.ownerName,
        service: reservation.service,
        time: reservation.time,
        date: reservation.date || reservation.createdAt,
        status: reservation.status
      }
    });

    return res.json({ success:true, reservationId: String(reservation._id) });
  } catch (e) {
    console.error('[admin] walkin-reservation failed:', e);
    res.status(500).json({ success:false, message:'Server error' });
  }
});
// GET /admin/search-owners  — mirror of HR endpoint for Admin
router.get('/search-owners', authMiddleware, allow('admin'), async (req, res) => {
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
      accountItems = users.map(u => ({ token: `ID::${u._id}`, label: u.username }));
    }

    // 2) Walk-in names in PetList
    const walkinNames = await PetList.distinct('ownerName', { ownerName: rx });
    const walkinItems = walkinNames
      .filter(Boolean)
      .map(name => ({ token: `NAME::${name}`, label: `${name} (walk-in)` }));

    // 3) Merge + de-dupe by label, cap
    const seen = new Set();
    const items = [...accountItems, ...walkinItems].filter(x => {
      if (seen.has(x.label)) return false;
      seen.add(x.label);
      return true;
    }).slice(0, 20);

    res.json({ items });
  } catch (err) {
    console.error('[admin] search-owners failed:', err);
    res.status(500).json({ items: [] });
  }
});

module.exports = router;
