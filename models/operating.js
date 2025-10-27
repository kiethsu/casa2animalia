// models/operating.js
const mongoose = require('mongoose');

const ReceiptSchema = new mongoose.Schema(
  {
    filename:     { type: String, required: true },        // saved filename on disk
    originalName: { type: String, required: true },        // original uploaded name
    mimeType:     { type: String, required: true },        // e.g., image/png, application/pdf
    size:         { type: Number, required: true },        // bytes
    url:          { type: String, required: true },        // public URL: /receipts/<filename>
  },
  { _id: false }
);

const OperatingSchema = new mongoose.Schema(
  {
    type:    { type: String, required: true, trim: true }, // type of expense
    amount:  { type: Number, required: true, min: 0 },     // PHP amount
    receipts:{ type: [ReceiptSchema], default: [] }        // multiple receipts
  },
  { timestamps: true }
);

module.exports = mongoose.model('Operating', OperatingSchema);
