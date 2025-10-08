// models/Payment.js
const mongoose = require('mongoose');

const lineItemSchema = new mongoose.Schema({
  name:      { type: String, required: true },
  quantity:  { type: Number, default: 1 },
  unitPrice: { type: Number, required: true },
  lineTotal: { type: Number, required: true }
});

 const paymentSchema = new mongoose.Schema({
   // Reservation is optional so we can record retail (walk-in) sales
   reservation: { 
     type: mongoose.Schema.Types.ObjectId,
     ref: 'Reservation',
     required: false
   },
 
   // Helpful flag to distinguish POS/retail vs consultation payments
   isRetail: { type: Boolean, default: false },
  // If the owner has an account, we store the ref here (may be null for walk-ins)
  customer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },

  // Always store the display name (works for both registered owners and walk-ins)
  customerName: {
    type: String,
    required: true,
    trim: true
  },

  paidAt: { type: Date, default: Date.now },
  amount: { type: Number, required: true },

  // HR user who marked it paid
  by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },

  products: [lineItemSchema],
  services: [lineItemSchema]
}, { timestamps: true });

module.exports = mongoose.model('Payment', paymentSchema);
