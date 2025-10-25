// models/ReservationMessage.js
const mongoose = require('mongoose');

const ReservationMessageSchema = new mongoose.Schema({
  reservation: { type: mongoose.Schema.Types.ObjectId, ref: 'Reservation', required: true },

  // who we sent to (optional; for walk-ins you might not have a User)
  toOwner:     { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  ownerName:   { type: String },                         // fallback name

  // content + template reference
  body:        { type: String, required: true },         // final text sent
  templateId:  { type: mongoose.Schema.Types.ObjectId, ref: 'MessageTemplate' }, // optional

  // status/response lifecycle
  status:      { type: String, enum: ['sent','responded'], default: 'sent' },
  // allow null until owner replies
  response:    { type: String, enum: ['confirm','resched', null], default: null },
  respondedAt: { type: Date },

  // channel for future expansion (sms/email/inapp)
  channel:     { type: String, default: 'inapp' },
}, { timestamps: true });

ReservationMessageSchema.index({ reservation: 1, createdAt: -1 });

// ---- Export with idempotent guard ----
const ModelName = 'ReservationMessage';
module.exports = mongoose.models[ModelName] || mongoose.model(ModelName, ReservationMessageSchema);
