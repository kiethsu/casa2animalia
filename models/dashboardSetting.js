const mongoose = require('mongoose');

const dashboardSettingSchema = new mongoose.Schema({
  quickGuide: {
    type: String,
    default: "Quick Guide"  // set a default value if needed
  },
  welcomeText: {
    type: String,
    default: "Manage your appointments and keep track of your pet’s health easily."
  },
  videoUrl: {
    type: String,
    default: ""
  }
});

module.exports = mongoose.model('DashboardSetting', dashboardSettingSchema);