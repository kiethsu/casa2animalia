const mongoose = require('mongoose');

const PetDetailsSettingSchema = new mongoose.Schema({
  species: { type: [String], default: [] },
  speciesBreeds: { type: Object, default: {} },
  diseases: { type: [String], default: [] },
  services: { type: [String], default: [] }
}, { timestamps: true });

module.exports = mongoose.models.PetDetailsSetting ||
  mongoose.model('PetDetailsSetting', PetDetailsSettingSchema);