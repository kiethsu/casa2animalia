const mongoose = require("mongoose");

const DoctorSchema = new mongoose.Schema({
  name: { type: String, default: "" },
  description: { type: String, default: "" },
  pic: { type: String, default: "" }
});

const AboutSchema = new mongoose.Schema({
  aboutDescription: { type: String, default: "" },
  doctors: [DoctorSchema],
  services: { type: [String], default: [] }
});

module.exports = mongoose.model("About", AboutSchema);