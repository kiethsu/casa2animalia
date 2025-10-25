const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ServiceSchema = new Schema({
  category:    { type: Schema.Types.ObjectId, ref: 'ServiceCategory', required: true },
  serviceName: { type: String, required: true, trim: true },
  weight:      { type: String, required: true, trim: true },
  dosage:      { type: String, required: true, trim: true },

  // NEW: peso-based pricing fields
  basePrice:   { type: Number, required: true, min: 0 },
  markup:      { type: Number, required: true, min: 0, default: 0 },

  // Selling price (auto: basePrice + markup)
  price:       { type: Number, required: true, min: 0 }
}, { timestamps: true });

// Keep selling price always correct
ServiceSchema.pre('validate', function(next){
  const b = Number(this.basePrice || 0);
  const m = Number(this.markup || 0);
  this.price = b + m;
  next();
});

module.exports = mongoose.model('Service', ServiceSchema);
