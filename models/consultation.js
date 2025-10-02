// models/consultation.js
const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Subdocs
 */
const MedicationSchema = new Schema({
  productId: { type: Schema.Types.ObjectId, ref: 'Inventory' },
  name:      { type: String },
  dosage:    { type: String },
  remarks:   { type: String },
  quantity:  { type: Number },

  // NEW: persist manual/receipt-added rows so the UI can show "Added"
  added:     { type: Boolean, default: false }
}, { _id: false });

const ServiceEntrySchema = new Schema({
  category:    { type: String },
  serviceName: { type: String },
  details:     { type: String },
  file:        { type: String } // stored file path or URL
}, { _id: false });

/**
 * Main schema
 */
const ConsultationSchema = new Schema({
  // Which reservation this consult belongs to
  reservation:   { type: Schema.Types.ObjectId, ref: 'Reservation', required: true },

  // Which pet inside that reservation this consult is for
  targetPetId:   { type: Schema.Types.ObjectId, ref: 'Pet' }, // preferred
  targetPetName: { type: String },                             // fallback for name-only

  // (Optional) legacy free-form notes some UIs used
  consultationNotes: { type: String },

  // Vital overview
  overview: {
    weight:       { type: String },
    temperature:  { type: String },
    pulse:        { type: String },
    respiration:  { type: String },
    others:       { type: String }
  },

  // Detailed Physical Exam
  physicalExam: {
    heart:   { type: String },
    lungs:   { type: String },
    abdomen: { type: String },
    skin:    { type: String },
    eyes:    { type: String },
    ears:    { type: String },
    mouth:   { type: String },
    others:  { type: String },

    // Back-compat fields (some older forms saved these here)
    weight:       { type: String },
    temperature:  { type: String },
    observations: { type: String }
  },

  // Diagnosis, notes, meds, services, confinement
  diagnosis:         { type: String },
  notes:             { type: String },
  medications:       [MedicationSchema],
  services:          [ServiceEntrySchema],
  confinementStatus: [{ type: String }]
}, { timestamps: true });

/**
 * Indexes to speed up “prefill latest by pet”
 */
ConsultationSchema.index({ reservation: 1, targetPetId: 1, updatedAt: -1 });
ConsultationSchema.index({ reservation: 1, targetPetName: 1, updatedAt: -1 });

/**
 * Back-compat shim:
 * - If legacy forms placed vitals in physicalExam.weight/temperature/observations,
 *   mirror them into overview when overview fields are empty.
 */
ConsultationSchema.pre('save', function(next) {
  try {
    const o = this.overview || {};
    const pe = this.physicalExam || {};
    // Only fill overview if not provided
    if (!o.weight && pe.weight)           this.overview = { ...(this.overview || {}), weight: pe.weight };
    if (!o.temperature && pe.temperature) this.overview = { ...(this.overview || {}), temperature: pe.temperature };
    if (!o.others && pe.observations)     this.overview = { ...(this.overview || {}), others: pe.observations };
  } catch (_) { /* no-op */ }
  next();
});

module.exports = mongoose.model('Consultation', ConsultationSchema);
