// models/message.js
const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  user:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  type:   { 
    type: String,
    enum: ['info', 'warning', 'suspension', 'declined'], // ← added 'declined'
    default: 'info'
  },
  title:  { type: String, required: true },
  body:   { type: String, required: true },
  isRead: { type: Boolean, default: false, index: true },
  readAt: { type: Date, default: null }
}, { timestamps: true });

module.exports = mongoose.model('Message', MessageSchema);
