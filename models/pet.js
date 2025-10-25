// models/pet.js
const mongoose = require('mongoose');

const PetSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  petName: { type: String, required: true },
  species: { type: String, required: true },
  breed: { type: String },
  birthday: { type: Date },

  // 🔁 Legacy single-field kept for back-compat (used by older UI bits)
  existingDisease: { type: String },

  // ✅ New: allow multiple diseases
  existingDiseases: { type: [String], default: [] },

  sex: { type: String },
  petPic: { type: String }, // URL or path for the pet picture
  addedFromReservation: { type: Boolean, default: false }
});

module.exports = mongoose.model('Pet', PetSchema);
