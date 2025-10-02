// models/inventory.js
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const InventorySchema = new Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },
    // Category is now free-form so you can add new ones from the UI
    category: {
      type: String,
      required: true,
      trim: true
    },

    // Base cost of the item (₱)
    basePrice: {
      type: Number,
      required: true,
      min: 0
    },

    // Markup in PESOS (₱), not percent
    markup: {
      type: Number,
      required: true,
      min: 0,
      default: 0
    },

    // Selling price (auto-computed as basePrice + markup)
    price: {
      type: Number,
      required: true,
      min: 0
    },

    // Per-unit expiration dates (one date per unit in stock)
    expirationDates: [
      {
        type: Date
      }
    ],

    // Already-expired unit dates (for analytics/loss tracking)
    expiredDates: [
      {
        type: Date
      }
    ],

    // Current stock quantity
    quantity: {
      type: Number,
      required: true,
      min: 0
    },

    // Count of expired units (redundant but handy for quick queries)
    expiredCount: {
      type: Number,
      default: 0,
      min: 0
    }
  },
  { timestamps: true }
);

/**
 * Ensure price is always basePrice + markup (markup in pesos).
 * We do this on validate (create/save) and on findOneAndUpdate.
 */
InventorySchema.pre("validate", function (next) {
  const b = Number(this.basePrice || 0);
  const m = Number(this.markup || 0);
  this.price = b + m;
  next();
});

InventorySchema.pre("findOneAndUpdate", async function (next) {
  try {
    const update = this.getUpdate() || {};
    // Support both $set and direct assignment updates
    const $set = update.$set || update;

    let basePrice = $set.basePrice;
    let markup = $set.markup;

    // If either field wasn't provided in the update, fetch current doc to fill in
    if (basePrice === undefined || markup === undefined) {
      const doc = await this.model.findOne(this.getQuery()).lean();
      if (doc) {
        if (basePrice === undefined) basePrice = doc.basePrice || 0;
        if (markup === undefined) markup = doc.markup || 0;
      } else {
        // No existing doc; bail gracefully
        return next();
      }
    }

    // Compute selling price in pesos
    $set.price = Number(basePrice || 0) + Number(markup || 0);

    // Reassign back to the update payload
    if (update.$set) update.$set = $set;
    else this.setUpdate($set);

    next();
  } catch (err) {
    next(err);
  }
});

module.exports = mongoose.model("Inventory", InventorySchema);
