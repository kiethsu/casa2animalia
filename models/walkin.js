const mongoose = require('mongoose');

const WalkInSchema = new mongoose.Schema(
  {
    // Either a real account owner...
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },

    // ...or a plain-text walk-in name (we keep this even for account owners as denormalized display)
    ownerName: { type: String, trim: true },

    // Pet name is always required (select existing or type new)
    petName: { type: String, required: true, trim: true },

    // Front-end sends this as a hidden field:
    // true  = existing pet chosen from list (meta fields hidden)
    // false = "+ New Pet…" (meta fields shown & required)
    isExistingPet: { type: Boolean, default: true },

    // Meta fields — required only when it's a NEW pet
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
    // “Existing Disease” select in the form (or “Other” text merged server-side)
    disease: {
      type: String,
      trim: true,
      required: function () { return this.isExistingPet === false; }
    },

    // Optional extras you already had
    birthday: { type: Date },
    cellphone: { type: String, trim: true },
    address: { type: String, trim: true },

    // Visit info
    service: { type: String, required: true, trim: true },
    concerns: { type: String, trim: true },
    date: { type: Date, required: true },
    time: { type: String, required: true, trim: true },

    // If this walk-in came from an existing reservation (optional)
    reservation: { type: mongoose.Schema.Types.ObjectId, ref: 'Reservation' }
  },
  { timestamps: true }
);

/**
 * Require at least one of: owner (ObjectId) OR ownerName (string)
 * This lets you save true walk-ins that don’t have a User account,
 * while still supporting linked accounts.
 */
WalkInSchema.pre('validate', function (next) {
  if (!this.owner && !this.ownerName) {
    return next(new Error('Either owner (account) or ownerName (walk-in) is required.'));
  }
  next();
});

/**
 * Normalize disease if your route sends `existingDisease` + optional `otherDisease`.
 * (If you already handle this in your controller, you can remove this.)
 */
WalkInSchema.pre('validate', function (next) {
  // If the controller put the raw fields onto the doc:
  //   this.existingDisease and this.otherDisease (not defined in schema)
  // we merge them into disease.
  if (!this.disease) {
    const ex = this.existingDisease;
    const other = this.otherDisease;
    if (typeof ex === 'string' && ex.trim()) {
      this.disease = ex === 'Other' ? (other || '').trim() : ex.trim();
    } else if (typeof other === 'string' && other.trim()) {
      this.disease = other.trim();
    }
  }
  next();
});

module.exports = mongoose.model('WalkIn', WalkInSchema);
