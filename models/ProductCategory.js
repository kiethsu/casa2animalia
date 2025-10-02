// models/ProductCategory.js
const mongoose = require("mongoose");

const ProductCategorySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      unique: true,
    }
  },
  { timestamps: true }
);

// Case-insensitive uniqueness helper
ProductCategorySchema.index({ name: 1 }, { unique: true });

module.exports = mongoose.model("ProductCategory", ProductCategorySchema);
