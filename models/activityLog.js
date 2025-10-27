// models/activityLog.js
const mongoose = require('mongoose');

const TargetSchema = new mongoose.Schema({
  type: { type: String, required: true }, // 'Reservation' | 'Consultation' | 'Payment' | 'User' | 'Inventory' | 'Service' | ...
  id:   { type: mongoose.Schema.Types.ObjectId, required: false },
  name: { type: String } // human-friendly identifier (ownerName, petName, username, etc.)
}, { _id: false });

const ActivityLogSchema = new mongoose.Schema({
  // who did it
  actor:     { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // may be null for system jobs
  actorName: { type: String },
  actorRole: { type: String }, // 'Admin' | 'Doctor' | 'HR' | 'Customer' | 'System'

  // what happened
  action:    { type: String, required: true }, // e.g. 'reservation.approved', 'followup.rescheduled', 'consultation.created', 'payment.recorded'

  // to which entity
  target:    TargetSchema,

  // extra structured data (kept flexible)
  meta:      { type: mongoose.Schema.Types.Mixed },

  // request context
  ip:        { type: String },
  userAgent: { type: String }
}, { timestamps: true });

ActivityLogSchema.index({ createdAt: -1 });
ActivityLogSchema.index({ action: 1, 'target.type': 1 });
ActivityLogSchema.index({ actor: 1, createdAt: -1 });

module.exports = mongoose.model('ActivityLog', ActivityLogSchema);
