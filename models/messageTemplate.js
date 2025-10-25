// models/messageTemplate.js
const mongoose = require('mongoose');

const MessageTemplateSchema = new mongoose.Schema({
  // We’ll accept "notify" or "notif" externally, but store as "notif" or "declined"
  type: {
    type: String,
    enum: ['notif', 'declined'],
    required: true,
    index: true
  },
  title: { type: String, required: true, trim: true },
  body:  { type: String, required: true, trim: true },

  // Optional: mark one default template per type
  isDefault: { type: Boolean, default: false },

  // Optional audit
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false }
}, { timestamps: true });

// Normalize "notify" -> "notif" and lowercase type on set
MessageTemplateSchema.path('type').set(function (v) {
  const t = String(v || '').trim().toLowerCase();
  return (t === 'notify') ? 'notif' : t;
});

// Keep only a single default per type
MessageTemplateSchema.pre('save', async function(next){
  if (this.isDefault) {
    await this.constructor.updateMany(
      { _id: { $ne: this._id }, type: this.type, isDefault: true },
      { $set: { isDefault: false } }
    );
  }
  next();
});

// ---- Export with idempotent guard ----
const ModelName = 'MessageTemplate';
module.exports = mongoose.models[ModelName] || mongoose.model(ModelName, MessageTemplateSchema);
