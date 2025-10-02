// models/reservation.js
const mongoose = require('mongoose');

const PetEntrySchema = new mongoose.Schema({
  petId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Pet' },
  petName: { type: String },
  schedule: {
    scheduleDate:    { type: Date },
    scheduleDetails: { type: String }
  },
  done:       { type: Boolean, default: false },
  hasConsult: { type: Boolean, default: false }
}, { _id: false });

const PetRequestSchema = new mongoose.Schema({
  petId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Pet' },
  petName:  { type: String },
  service:  { type: String },
  concerns: { type: String }
}, { _id: false });

const ReservationSchema = new mongoose.Schema({
  // Owner (account or walk-in)
  owner:     { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // optional for walk-ins
  ownerName: { type: String, required: true, trim: true },
  walkIn:    { type: Boolean, default: false },

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

  // Booking slot
  date:  { type: Date },
  time:  { type: String },

  // Doctor assignment & status
  doctor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, default: 'Pending' }, // Pending/Approved/Done/etc.

  // Optional reservation-level follow-up
  schedule: {
    scheduleDate:    { type: Date },
    scheduleDetails: { type: String }
  },

  isFollowUp: { type: Boolean, default: false },
  petAdded:   { type: Boolean, default: false },

  canceledAt: { type: Date },

  idemKey: { type: String } // idempotency
}, { timestamps: true });

// Indices
ReservationSchema.index({ date: 1, time: 1, status: 1 });
ReservationSchema.index({ idemKey: 1 }, { unique: true, sparse: true });

/**
 * Normalize disease fields so validation never fails when user selects "None".
 * - For NEW pets (isExistingPet === false): always set disease, defaulting to "None".
 * - For EXISTING pets: disease is optional; clear if "None".
 * Also accepts form-only fields existingDisease/otherDisease.
 */
ReservationSchema.pre('validate', function (next) {
  // Accept values that may arrive from the form (even if not in schema)
  const ex    = typeof this.existingDisease === 'string' ? this.existingDisease.trim() : '';
  const other = typeof this.otherDisease    === 'string' ? this.otherDisease.trim()    : '';

  if (this.isExistingPet === false) {
    // Build the disease string from the two-part UI
    let d = ex;
    if (d === 'Other') d = other;
    if (d === 'None')  d = 'None';
    if (!d)            d = 'None'; // default for new pets

    this.disease = d;  // guaranteed non-empty (thanks to default above)
  } else {
    // Existing pet flow: optional; drop it if "None"
    if (ex === 'None') {
      this.disease = undefined;
    } else if (!this.disease && (ex || other)) {
      // if something meaningful was provided, store it
      this.disease = ex === 'Other' ? (other || undefined) : (ex || undefined);
    }
  }

  next();
});

module.exports = mongoose.model('Reservation', ReservationSchema);
