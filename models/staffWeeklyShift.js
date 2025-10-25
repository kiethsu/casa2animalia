// models/staffWeeklyShift.js
const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Weekly shift template scoped to a specific calendar month.
 * - yearMonth: 'YYYY-MM' (required)
 * - weekday: ISO 1..7 (Mon..Sun)
 * - time stored as minutes-from-midnight
 */
const StaffWeeklyShiftSchema = new Schema(
  {
    staff:        { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    yearMonth:    {
      type: String,
      required: true,
      match: [/^\d{4}-(0[1-9]|1[0-2])$/, 'yearMonth must be YYYY-MM'],
      index: true
    },
    weekday:      { type: Number, required: true, min: 1, max: 7, index: true }, // 1..7
    startMinutes: { type: Number, required: true, min: 0, max: 1439 },
    endMinutes:   { type: Number, required: true, min: 1,  max: 1440 },
    note:         { type: String, trim: true, maxlength: 1000 },
    active:       { type: Boolean, default: true },

    createdBy:    { type: Schema.Types.ObjectId, ref: 'User' },
    updatedBy:    { type: Schema.Types.ObjectId, ref: 'User' }
  },
  { timestamps: true }
);

/** Utility: coerce "YYYY-M" -> "YYYY-MM" (and trim extraneous input) */
function normalizeYearMonth(v) {
  if (!v) return v;
  // allow 'YYYY-M' or 'YYYY-MM'
  const m1 = String(v).trim().match(/^(\d{4})-(\d{1,2})$/);
  if (m1) {
    const yyyy = m1[1];
    const mm   = String(parseInt(m1[2], 10)).padStart(2, '0');
    return `${yyyy}-${mm}`;
  }
  // keep only first 7 chars if it already matches 'YYYY-MM...'
  if (/^\d{4}-(0[1-9]|1[0-2])/.test(v)) return String(v).trim().slice(0, 7);
  return v;
}

/** Normalize + validate before saving */
StaffWeeklyShiftSchema.pre('validate', function(next){
  // normalize yearMonth formatting
  if (this.yearMonth) this.yearMonth = normalizeYearMonth(this.yearMonth);
  if (!this.yearMonth) return next(new Error('yearMonth (YYYY-MM) is required.'));

  // coerce minutes to integers
  if (typeof this.startMinutes === 'number') this.startMinutes = Math.floor(this.startMinutes);
  if (typeof this.endMinutes   === 'number') this.endMinutes   = Math.floor(this.endMinutes);

  // validate range
  if (!(this.startMinutes < this.endMinutes)) {
    return next(new Error('endMinutes must be greater than startMinutes.'));
  }
  next();
});

/**
 * Check overlap for staff + weekday + yearMonth:
 * Two intervals [start, end) and [sMin, eMin) overlap when:
 *   start < eMin && end > sMin
 */
StaffWeeklyShiftSchema.statics.hasOverlap = async function(
  staffId, weekday, sMin, eMin, yearMonth, excludeId = null
){
  const ym = normalizeYearMonth(yearMonth);
  const filter = {
    staff: staffId,
    weekday,
    yearMonth: ym,
    startMinutes: { $lt: eMin },
    endMinutes:   { $gt: sMin },
    active: true
  };
  if (excludeId) filter._id = { $ne: excludeId };
  return !!(await this.exists(filter));
};

// Helpful query indexes
StaffWeeklyShiftSchema.index({ staff: 1, yearMonth: 1, weekday: 1 });
StaffWeeklyShiftSchema.index({ staff: 1, yearMonth: 1 });

// Prevent duplicate ACTIVE shifts with the exact same window (allows duplicates if old ones are inactive)
StaffWeeklyShiftSchema.index(
  { staff: 1, yearMonth: 1, weekday: 1, startMinutes: 1, endMinutes: 1 },
  {
    unique: true,
    partialFilterExpression: { active: true }
  }
);

module.exports = mongoose.model('StaffWeeklyShift', StaffWeeklyShiftSchema);
