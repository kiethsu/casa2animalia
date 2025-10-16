const mongoose = require('mongoose');
const PetDetailsSettingSchema = new mongoose.Schema({
  species: { type: [String], default: [] },
  speciesBreeds: { type: Object, default: {} },

  // Global fallback list (keep existing data working)
  diseases: { type: [String], default: [] },

  // NEW: per-species disease mapping, e.g. { "Dog": ["Parvo", "Distemper"], "Cat": ["FIV"] }
  speciesDiseases: { type: Object, default: {} },

  services: { type: [String], default: [] }
}, { timestamps: true });


module.exports = mongoose.models.PetDetailsSetting ||
  mongoose.model('PetDetailsSetting', PetDetailsSettingSchema);
