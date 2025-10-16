// models/petlist.js
const mongoose = require('mongoose');
const { Schema } = mongoose;

const ConsultationHistorySchema = new Schema({
  reservation: { type: Schema.Types.ObjectId, ref: 'Reservation', required: true },
  consultation:{ type: Schema.Types.ObjectId, ref: 'Consultation', required: true },
  addedAt:     { type: Date, default: Date.now }
}, { _id: false });

const PetListSchema = new Schema({
  owner:       { type: Schema.Types.ObjectId, ref: 'User' },  // optional for walk-ins
  ownerName:   { type: String, required: true },               // ALWAYS set (from reservation.ownerName)

  // NEW
  contactEmail:  { type: String },
  contactMobile: { type: String },

  petName:     { type: String, required: true },
  reservation: { type: Schema.Types.ObjectId, ref: 'Reservation', required: true },
  addedAt:     { type: Date, default: Date.now },

  consultationHistory: [ ConsultationHistorySchema ]
}, { timestamps: true });

PetListSchema.index({ owner: 1, ownerName: 1, petName: 1 });

module.exports = mongoose.model('PetList', PetListSchema);
