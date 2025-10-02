const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ServiceSchema = new Schema({
  category: { type: Schema.Types.ObjectId, ref: 'ServiceCategory', required: true },
  serviceName: { type: String, required: true },
  weight: { type: String, required: true },
  dosage: { type: String, required: true },
  price: { type: Number, required: true }
}, { timestamps: true });

module.exports = mongoose.model('Service', ServiceSchema);
