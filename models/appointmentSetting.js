// models/appointmentSetting.js
const mongoose = require('mongoose');

const AppointmentSettingSchema = new mongoose.Schema({
  startTime: { type: String, default: "08:00" },
  endTime: { type: String, default: "17:00" },
  limitPerHour: { type: Number, default: 5 }
});

module.exports = mongoose.model('AppointmentSetting', AppointmentSettingSchema);