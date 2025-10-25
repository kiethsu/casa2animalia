// models/inventory.js
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const InventorySchema = new Schema(
  {
    name: { type: String, required: true, trim: true },

    // Category is free-form so you can add new ones from the UI
    category: { type: String, required: true, trim: true },

    // Date when this item/batch was purchased/added
    purchaseDate: { type: Date, default: Date.now }, // <-- NEW

    // Base cost of the item (₱)
    basePrice: { type: Number, required: true, min: 0 },

    // Markup in PESOS (₱), not percent
    markup: { type: Number, required: true, min: 0, default: 0 },

    // Selling price (auto-computed as basePrice + markup)
    price: { type: Number, required: true, min: 0 },

    // Per-unit expiration dates (one date per unit in stock)
    expirationDates: [{ type: Date }],

    // Already-expired unit dates (for analytics/loss tracking)
    expiredDates: [{ type: Date }],

    // Current stock quantity (represents SELLABLE units)
    quantity: { type: Number, required: true, min: 0 },

    // Count of expired units (redundant but handy for quick queries)
    expiredCount: { type: Number, default: 0, min: 0 }
  },
  { timestamps: true }
);

/* ------------------------- Small helpers ------------------------- */

function toDateArray(arr) {
  if (!Array.isArray(arr)) return [];
  return arr
    .map(d => new Date(d))
    .filter(d => !isNaN(d.getTime()));
}

function splitByToday(dates) {
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const stillGood = [];
  const newlyExpired = [];
  for (const d of toDateArray(dates)) {
    // Treat dates <= today as expired (day-of is considered unsellable)
    if (d <= today) newlyExpired.push(d);
    else stillGood.push(d);
  }
  return { stillGood, newlyExpired };
}

/* --------------------- Keep price always correct --------------------- */
// Ensure price is always basePrice + markup (markup in pesos).
// We do this on validate (create/save) and also recompute in findOneAndUpdate.
InventorySchema.pre("validate", function (next) {
  const b = Number(this.basePrice || 0);
  const m = Number(this.markup || 0);
  this.price = b + m;
  next();
});

/* ------------- Roll expiries + set sellable quantity on save ------------- */
InventorySchema.pre("save", function (next) {
  try {
    const { stillGood, newlyExpired } = splitByToday(this.expirationDates);
    const prevExpired = toDateArray(this.expiredDates);
    const combinedExpired = prevExpired.concat(newlyExpired);

    // Persist normalized state
    this.expirationDates = stillGood;
    this.expiredDates = combinedExpired;
    this.expiredCount = combinedExpired.length;

    // If per-unit dates exist, quantity = count of non-expired units.
    // If no dates exist (legacy), keep provided quantity but clamp >= 0.
    if (toDateArray(this.expirationDates).length || toDateArray(this.expiredDates).length) {
      this.quantity = Math.max(0, stillGood.length);
    } else {
      this.quantity = Math.max(0, Number(this.quantity || 0));
    }

    next();
  } catch (err) {
    next(err);
  }
});

/* ---- Roll expiries + set sellable quantity + recompute price on update ---- */
InventorySchema.pre("findOneAndUpdate", async function (next) {
  try {
    const update = this.getUpdate() || {};
    const $set = update.$set || {};

    // Load current doc for merging/rollover decisions
    const doc = await this.model.findOne(this.getQuery()).lean();
    if (!doc) return next();

    // Price recompute (peso markup)
    let basePrice = $set.basePrice;
    let markup = $set.markup;
    if (basePrice === undefined) basePrice = doc.basePrice || 0;
    if (markup === undefined) markup = doc.markup || 0;
    $set.price = Number(basePrice || 0) + Number(markup || 0);

    // Normalize expirations whether or not the updater sent new ones
    // Prefer the array provided in the update; else use existing doc's array.
    const candidateExp = $set.expirationDates !== undefined
      ? $set.expirationDates
      : doc.expirationDates;

    const { stillGood, newlyExpired } = splitByToday(candidateExp);
    const priorExpired = toDateArray(doc.expiredDates);
    const combinedExpired = priorExpired.concat(newlyExpired);

    $set.expirationDates = stillGood;
    $set.expiredDates = combinedExpired;
    $set.expiredCount = combinedExpired.length;

    // Quantity logic:
    // - If there are per-unit dates in play, quantity = stillGood.length.
    // - Otherwise (no dates at all), keep incoming or existing quantity (clamped).
    const hadAnyDates =
      toDateArray(candidateExp).length > 0 || priorExpired.length > 0;

    let newQty;
    if (hadAnyDates) {
      newQty = stillGood.length;
    } else {
      const incomingQty =
        $set.quantity !== undefined ? Number($set.quantity) : Number(doc.quantity || 0);
      newQty = incomingQty;
    }
    $set.quantity = Math.max(0, Number(newQty || 0));

    // Write back to update payload
    if (update.$set) update.$set = $set;
    else this.setUpdate($set);

    next();
  } catch (err) {
    next(err);
  }
});

module.exports = mongoose.model("Inventory", InventorySchema);
