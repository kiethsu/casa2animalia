// models/reservation.js
const mongoose = require('mongoose');

// Optional subdoc used by your notify-response route
const NotifyResponseSchema = new mongoose.Schema({
  action:       { type: String, enum: ['confirm', 'resched'] },
  respondedAt:  { type: Date },
  respondedBy:  { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { _id: false });

// NEW: reschedule metadata (who moved it, from→to, when)
const RescheduledInfoSchema = new mongoose.Schema({
  fromDate: { type: Date },
  fromTime: { type: String },
  toDate:   { type: Date },
  toTime:   { type: String },
  at:       { type: Date, default: Date.now },
  by:       { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { _id: false });

const PetEntrySchema = new mongoose.Schema({
  petId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Pet' },
  petName: { type: String },

  // Per-pet follow-up schedule
  schedule: {
    scheduleDate:    { type: Date },
    scheduleDetails: { type: String },           // human-readable fallback (e.g. "Deworming")
    time:            { type: String },           // keep chosen follow-up time

    // Structured service info (optional)
    service: {
      id:           { type: mongoose.Schema.Types.ObjectId, ref: 'Service' },
      name:         { type: String },
      categoryId:   { type: mongoose.Schema.Types.ObjectId, ref: 'ServiceCategory' },
      categoryName: { type: String }
    },

    // NEW: last reschedule info for this pet’s follow-up
    rescheduled: RescheduledInfoSchema
  },

  done:       { type: Boolean, default: false },
  hasConsult: { type: Boolean, default: false }
}, { _id: false });

const PetRequestSchema = new mongoose.Schema({
  petId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Pet' },
  petName:  { type: String },

  // Legacy single service (keep for back-compat)
  service:  { type: String },

  // ✅ New multi-service support
  services: [{ type: String }],

  concerns: { type: String }
}, { _id: false });


const ReservationSchema = new mongoose.Schema({
  // Owner (account or walk-in)
  owner:     { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // optional for walk-ins
  ownerName: { type: String, required: true, trim: true },
  walkIn:    { type: Boolean, default: false },

  // Optional contact info (works for both account owners & walk-ins)
  contactEmail: {
    type: String,
    trim: true,
    lowercase: true,
    validate: {
      validator: v => !v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
      message: 'Invalid email format'
    }
  },
  contactMobile: {
    type: String,
    trim: true,
    // PH formats: 09XXXXXXXXX or +639XXXXXXXXXX (lenient, optional)
    validate: {
      validator: v => !v || /^(\+?63|0)9\d{9}$/.test(v),
      message: 'Invalid PH mobile format (use 09XXXXXXXXX or +639XXXXXXXXXX)'
    }
  },

  // Walk-in modal flag
  isExistingPet: { type: Boolean, default: true },

  // Quick meta (only required for brand-new pets)
  species: {
    type: String,
    trim: true,
    required: function () { return this.isExistingPet === false; }
  },
  breed: {
    type: String,
    trim: true,
    required: function () { return this.isExistingPet === false; }
  },
  sex: {
    type: String,
    enum: ['Male', 'Female'],
    required: function () { return this.isExistingPet === false; }
  },

  // Disease note captured from the walk-in modal.
  // For NEW pets it's required; "None" is a valid value.
  disease: {
    type: String,
    trim: true,
    default: 'None',
    set: v => (typeof v === 'string' && v.trim() === '' ? 'None' : v),
    required: function () { return this.isExistingPet === false; }
  },

  // Multi-pet support (doctor UI)
  pets:        [PetEntrySchema],
  petRequests: [PetRequestSchema],

  // Legacy reservation-level fields (kept for compatibility)
  service:   { type: String },
  concerns:  { type: String },

  // Booking slot selected by the customer (original appointment)
  date:  { type: Date },
  time:  { type: String },

  // Doctor assignment & preference
  doctor:          { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // assigned by staff later
  preferredDoctor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // customer's optional choice

  status: { type: String, default: 'Pending' }, // Pending/Approved/Done/etc.

  // Reservation-level follow-up (earliest across pets for dashboards)
  schedule: {
    scheduleDate:    { type: Date },
    scheduleDetails: { type: String },           // human-readable fallback
    time:            { type: String },           // keep chosen follow-up time
    service: {
      id:           { type: mongoose.Schema.Types.ObjectId, ref: 'Service' },
      name:         { type: String },
      categoryId:   { type: mongoose.Schema.Types.ObjectId, ref: 'ServiceCategory' },
      categoryName: { type: String }
    },

    // NEW: last reschedule info at reservation-level mirror (optional)
    rescheduled: RescheduledInfoSchema
  },

  isFollowUp: { type: Boolean, default: false },
  petAdded:   { type: Boolean, default: false },

  canceledAt: { type: Date },

  // Idempotency key to avoid duplicate submissions
  idemKey: { type: String },

  // For auto-followups created in /add-schedule ensureOneAutoFollowup()
  // (used by your de-duplication & analytics)
  source: { type: String }, // e.g. "doctor_auto_followup"

  // Records customer's reply to staff notify (optional)
  notifyResponse: NotifyResponseSchema
}, { timestamps: true });

// Indices
ReservationSchema.index({ date: 1, time: 1, status: 1 });
ReservationSchema.index({ idemKey: 1 }, { unique: true, sparse: true });
ReservationSchema.index({ preferredDoctor: 1, date: 1 });
ReservationSchema.index({ doctor: 1, date: 1 });
// Helpful when listing upcoming follow-ups
ReservationSchema.index({ 'schedule.scheduleDate': 1 });
// Helpful for queries that match per-pet schedule dates
ReservationSchema.index({ 'pets.schedule.scheduleDate': 1 });

/**
 * Normalize disease fields so validation never fails when user selects "None".
 * - For NEW pets (isExistingPet === false): always set disease, defaulting to "None".
 * - For EXISTING pets: disease is optional; clear if "None".
 * Accepts form-only fields existingDisease/otherDisease.
 */
ReservationSchema.pre('validate', function (next) {
  const ex    = typeof this.existingDisease === 'string' ? this.existingDisease.trim() : '';
  const other = typeof this.otherDisease    === 'string' ? this.otherDisease.trim()    : '';

  if (this.isExistingPet === false) {
    let d = ex;
    if (d === 'Other') d = other;
    if (d === 'None')  d = 'None';
    if (!d)            d = 'None';
    this.disease = d;
  } else {
    if (ex === 'None') {
      this.disease = undefined;
    } else if (!this.disease && (ex || other)) {
      this.disease = ex === 'Other' ? (other || undefined) : (ex || undefined);
    }
  }

  next();
});

module.exports = mongoose.model('Reservation', ReservationSchema);
