// utils/activityLogger.js
const mongoose     = require('mongoose');
const ActivityLog  = require('../models/activityLog');
const User         = require('../models/user');
const Reservation  = require('../models/reservation');
const Consultation = require('../models/consultation');
const Payment      = require('../models/Payment');
// ⬇️ NEW: pull in Pet & PetList so we can resolve pet ids/names
const Pet          = require('../models/pet');
const PetList      = require('../models/petlist');

function clientIp(req){
  const fwd = (req.headers['x-forwarded-for'] || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  return fwd[0] || req.ip || req.connection?.remoteAddress || '';
}

const safe    = v => (v == null ? '' : String(v));
const isObjId = v => mongoose.isValidObjectId(v);

// ───────────────── context fetch ─────────────────

async function fetchContext(targetType, targetId, meta = {}) {
  const ctx = { resv: null, consult: null, payment: null };

  try {
    // 1) If the target is a Consultation, prefer that first
    if (safe(targetType) === 'Consultation' && isObjId(targetId)) {
      ctx.consult = await Consultation.findById(targetId).lean();
      if (ctx.consult?.reservation && isObjId(ctx.consult.reservation)) {
        ctx.resv = await Reservation.findById(ctx.consult.reservation)
          .populate('owner', 'username')
          .populate('pets.petId', 'petName')
          .lean();
      }
      return ctx;
    }

    // 2) Direct Reservation target
    if (safe(targetType) === 'Reservation' && isObjId(targetId)) {
      ctx.resv = await Reservation.findById(targetId)
        .populate('owner', 'username')
        .populate('pets.petId', 'petName')
        .lean();
      return ctx;
    }

    // 3) Payment target → may reference a reservation
    if (safe(targetType) === 'Payment' && isObjId(targetId)) {
      ctx.payment = await Payment.findById(targetId).lean();
      const rid = ctx.payment?.reservation || meta.reservationId;
      if (rid && isObjId(rid)) {
        ctx.resv = await Reservation.findById(rid)
          .populate('owner', 'username')
          .populate('pets.petId', 'petName')
          .lean();
      }
      return ctx;
    }

    // 4) Fallback: meta.reservationId
    const rid = meta.reservationId;
    if (rid && isObjId(rid)) {
      ctx.resv = await Reservation.findById(rid)
        .populate('owner', 'username')
        .populate('pets.petId', 'petName')
        .lean();
      return ctx;
    }
  } catch (_) {
    // Best-effort; logging must never break main flow
  }
  return ctx;
}

// ───────────────── pet resolution helpers ─────────────────

/**
 * Try to resolve the pet name from consult/meta/reservation.
 */
function resolvePetName(resv, consult, meta = {}) {
  // 1) explicit text first
  const explicit =
    safe(meta.petName).trim() ||
    safe(meta.targetPetName).trim() ||
    safe(consult?.targetPetName).trim();
  if (explicit) return explicit;

  // 2) try by any id-ish field in meta/consult
  const candId = meta.petId || meta.targetPetId || consult?.targetPetId;
  const pets = resv?.pets || [];

  if (candId) {
    if (isObjId(candId)) {
      const hit = pets.find(p => String(p?.petId?._id) === String(candId));
      if (hit) return hit?.petId?.petName || hit?.petName || '';
    } else {
      // some legacy flows stuffed the name into id
      const byName = pets.find(p => (p?.petId?.petName || p?.petName) === candId);
      if (byName) return byName?.petId?.petName || byName?.petName || '';
    }
  }

  // 3) single-pet reservation fallback
  if (pets.length === 1) {
    return pets[0]?.petId?.petName || pets[0]?.petName || '';
  }

  return '';
}

/**
 * Try to resolve the pet _id using (in order):
 * - reservation.pets by name/id,
 * - Pet (account owners),
 * - PetList (walk-ins; may still not have a Pet _id),
 * - single-pet reservation fallback
 */
async function resolvePetId(resv, consult, meta = {}) {
  const pets = resv?.pets || [];

  // Canonical candidate name & id
  const byName =
    safe(meta.petName).trim() ||
    safe(meta.targetPetName).trim() ||
    safe(consult?.targetPetName).trim() ||
    '';

  const byId = meta.petId || meta.targetPetId || consult?.targetPetId || null;

  // 1) If we already have a valid ObjectId, prefer it
  if (isObjId(byId)) return String(byId);

  // 2) Try from reservation.pets by name
  if (byName) {
    const hit = pets.find(p => (p?.petId?.petName || p?.petName) === byName);
    if (hit?.petId?._id) return String(hit.petId._id);
  }

  // 3) Try from reservation.pets by string "id" that is actually a name (legacy)
  if (byId && typeof byId === 'string' && !isObjId(byId)) {
    const hit = pets.find(p => (p?.petId?.petName || p?.petName) === byId);
    if (hit?.petId?._id) return String(hit.petId._id);
  }

  // 4) If this is an account owner, look up Pet(owner, petName)
  if (resv?.owner && byName) {
    try {
      const petDoc = await Pet.findOne(
        { owner: resv.owner, petName: byName },
        '_id'
      ).lean();
      if (petDoc?._id) return String(petDoc._id);
    } catch (_) {}
  }

  // 5) If walk-in, try PetList(ownerName, petName) → (PetList won’t give Pet _id, but we tried)
  if (!resv?.owner && resv?.ownerName && byName) {
    try {
      const pl = await PetList.findOne(
        { ownerName: resv.ownerName, petName: byName },
        '_id' // PetList _id is not a Pet id, so we don't return it; this just checks existence.
      ).lean();
      if (pl) {
        // we found a matching PetList row but no Pet _id to return — keep searching…
      }
    } catch (_) {}
  }

  // 6) single-pet reservation fallback
  if (pets.length === 1 && pets[0]?.petId?._id) {
    return String(pets[0].petId._id);
  }

  return null;
}

function formatTargetName(targetType, ownerName, petName, payment) {
  const own = safe(ownerName).trim() || safe(payment?.customerName).trim();
  const pet = safe(petName).trim();

  switch (safe(targetType)) {
    case 'Consultation':
      return (own && pet) ? `${own} - ${pet}` : (own || pet || '');
    case 'Reservation':
    case 'PetList':
      return own || pet || '';
    case 'Payment':
      return own || '';
    default:
      return own || pet || '';
  }
}

// ───────────────── main logger ─────────────────

/**
 * logActivity(req, { action, targetType, targetId, targetName, meta })
 * Safe to await; never throws (errors logged to console).
 */
async function logActivity(req, { action, targetType, targetId, targetName, meta }) {
  try {
    const ua = req.headers['user-agent'] || '';
    const ip = clientIp(req);

    // Actor (enrich if partial)
    let actorId   = req.user?.userId || req.user?._id || null;
    let actorRole = req.user?.role || null;
    let actorName = req.user?.username || null;

    if (actorId && (!actorRole || !actorName)) {
      try {
        const u = await User.findById(actorId).select('username role email').lean();
        if (u) {
          actorRole = actorRole || u.role;
          actorName = actorName || u.username || u.email;
        }
      } catch (_) {}
    }

    // Pull context (reservation/consult/payment) for inference
    const ctx = await fetchContext(targetType, targetId, meta || {});
    const ownerName =
      ctx.resv?.ownerName ||
      ctx.resv?.owner?.username ||
      safe(meta?.ownerName);

    // Resolve pet name & id
    const petNameResolved = resolvePetName(ctx.resv, ctx.consult, meta || {});
    const petIdResolved   = await resolvePetId(ctx.resv, ctx.consult, meta || {});

    // Build normalized meta (merge with original)
    const normalizedMeta = { ...(meta || {}) };

    // Prefer not to overwrite if caller already provided values
    if (petNameResolved && !normalizedMeta.petName && !normalizedMeta.targetPetName) {
      normalizedMeta.petName = petNameResolved;
    }
    if (petIdResolved && !normalizedMeta.petId && !normalizedMeta.targetPetId) {
      normalizedMeta.petId = petIdResolved;
    }
    // Also mirror into targetPet* for newer/older UIs to agree
    if (petNameResolved && !normalizedMeta.targetPetName) {
      normalizedMeta.targetPetName = petNameResolved;
    }
    if (petIdResolved && !normalizedMeta.targetPetId) {
      normalizedMeta.targetPetId = petIdResolved;
    }

    // Target display name (fallback if blank)
    let finalTargetName = safe(targetName).trim();
    if (!finalTargetName) {
      finalTargetName = formatTargetName(targetType, ownerName, petNameResolved, ctx.payment);
    }

    await ActivityLog.create({
      actor     : actorId || undefined,
      actorName : actorName || 'Unknown',
      actorRole : actorRole || (actorId ? 'Unknown' : 'System'),
      action    : safe(action),
      target    : {
        type: safe(targetType) || 'Unknown',
        id  : targetId || undefined,
        name: finalTargetName || undefined
      },
      meta      : Object.keys(normalizedMeta).length ? normalizedMeta : undefined,
      ip,
      userAgent : ua
    });
  } catch (e) {
    console.error('[activity] failed to log', action, e);
  }
}

module.exports = { logActivity };
