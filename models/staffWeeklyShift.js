// models/staffShift.js
const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * StaffShift
 * - Stores one shift for a Doctor or HR user.
 * - Frontend sends:
 *    staffId: ObjectId (User)
 *    date:    'YYYY-MM-DD' (local clinic day key)
 *    start:   ISO string (e.g., '2025-10-20T08:00:00.000Z')
 *    end:     ISO string (e.g., '2025-10-20T12:00:00.000Z')
 *    note:    optional text
 */
const StaffShiftSchema = new Schema(
  {
    staff:   { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    date:    { type: String, required: true, trim: true }, // local day key (YYYY-MM-DD)
    start:   { type: Date, required: true, index: true },
    end:     { type: Date, required: true, index: true },

    status:  { type: String, enum: ['Scheduled', 'Completed', 'Cancelled'], default: 'Scheduled' },
    note:    { type: String, trim: true, maxlength: 1000 },
    location:{ type: String, trim: true, maxlength: 200 },

    createdBy: { type: Schema.Types.ObjectId, ref: 'User' }, // who created it (optional)
    updatedBy: { type: Schema.Types.ObjectId, ref: 'User' }  // who last edited (optional)
  },
  { timestamps: true }
);

// Basic validations
StaffShiftSchema.pre('validate', function(next) {
  if (!this.start || !this.end) return next(new Error('Start and End are required.'));
  if (this.start >= this.end)   return next(new Error('End time must be after start time.'));

  if (!this.date) {
    // Fallback: build YYYY-MM-DD from "start" in server local time
    const d = new Date(this.start);
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    this.date = `${y}-${m}-${dd}`;
  }
  next();
});

/**
 * Check if a shift overlaps an existing shift for the same staff.
 * Overlap logic: (existing.start < newEnd) && (existing.end > newStart)
 */
StaffShiftSchema.statics.hasOverlap = async function(staffId, newStart, newEnd, excludeId = null) {
  const filter = {
    staff: staffId,
    start: { $lt: newEnd },
    end:   { $gt: newStart }
  };
  if (excludeId) filter._id = { $ne: excludeId };
  return !!(await this.exists(filter));
};

// Helpful indexes for queries
StaffShiftSchema.index({ staff: 1, date: 1 });
StaffShiftSchema.index({ date: 1, start: 1 });

module.exports = mongoose.model('StaffShift', StaffShiftSchema);
