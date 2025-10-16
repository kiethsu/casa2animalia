// models/petDetailsSettings.js
const mongoose = require('mongoose');

const PetDetailsSettingsSchema = new mongoose.Schema(
  {
    // 0 = unlimited
    followUpDailyLimit: { type: Number, default: 0, min: 0 },
  },
  {
    collection: 'pet_details_settings',
    timestamps: true,
  }
);

// Convenience: always have exactly one settings document.
PetDetailsSettingsSchema.statics.getSingleton = async function () {
  let doc = await this.findOne().lean();
  if (doc) return await this.findById(doc._id); // return hydrated doc
  return await this.create({}); // creates with defaults
};

module.exports = mongoose.model('PetDetailsSettings', PetDetailsSettingsSchema);
