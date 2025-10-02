// models/user.js
const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  username:     { type: String, required: true, unique: true },
  email:        { type: String, required: true, unique: true },
  password:     { type: String, required: true },
  verified:     { type: Boolean, default: false },
  role:         { type: String, enum: ["Admin", "Doctor", "HR", "Customer"], default: "Customer" },
  profilePic:   { type: String },
  address:      { type: String },
  cellphone:    { type: String },
  otpEnabled:   { type: Boolean, default: false },

  // suspension / cancellation tracking
  cancelCount:  { type: Number, default: 0 },
  isSuspended:  { type: Boolean, default: false },
  suspendedAt:  { type: Date },

  // NEW: names the user has deleted from "My Pets"
  // (so clinic PetList rows with these names won’t reappear in My Pets)
  hiddenPetNames: { type: [String], default: [] }
});

module.exports = mongoose.model("User", UserSchema);
