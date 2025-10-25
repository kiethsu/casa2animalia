// controllers/petHistory.js
const mongoose = require('mongoose');
const { isValidObjectId } = mongoose;

const PetList = require('../models/petlist');
const Reservation = require('../models/reservation');
const Pet = require('../models/pet');

async function getPetHistory(req, res) {
  try {
    const { petId, petName, ownerId, ownerName } = req.query;

    if (!petId && !petName) {
      return res.json({ success: false, message: 'petId or petName is required' });
    }

    // Safe query building
    let query;
    if (petId) {
      if (!isValidObjectId(petId)) {
        return res.json({ success: false, message: 'Invalid petId' });
      }
      query = { _id: petId };
    } else if (ownerId && isValidObjectId(ownerId)) {
      query = { petName, owner: ownerId };
    } else if (ownerName && ownerName.trim()) {
      query = { petName, ownerName: ownerName.trim() };
    } else {
      query = { petName };
    }

    const entry = await PetList.findOne(query)
      .populate({
        path: 'consultationHistory.consultation',
        populate: [{
          path: 'reservation',
          select: 'date doctor schedule disease',
          populate: { path: 'doctor', select: 'username' }
        }]
      })
      .lean();

    if (!entry) {
      return res.json({ success: false, message: 'PetList entry not found.' });
    }

    // Pet meta (account -> Pet doc; walk-in -> latest reservation quick meta)
    const petMeta = { name: entry.petName, species: '', breed: '', sex: '' };
    try {
      if (entry.owner) {
        const petDoc = await Pet.findOne(
          { owner: entry.owner, petName: entry.petName },
          'species breed sex'
        ).lean();
        if (petDoc) {
          petMeta.species = petDoc.species || '';
          petMeta.breed   = petDoc.breed   || '';
          petMeta.sex     = petDoc.sex     || '';
        }
      } else {
        const latestCh = (entry.consultationHistory || [])
          .slice()
          .sort((a, b) => new Date(b.addedAt) - new Date(a.addedAt))[0];
        if (latestCh?.reservation) {
          const r = await Reservation.findById(latestCh.reservation, 'species breed sex').lean();
          if (r) {
            petMeta.species = r.species || '';
            petMeta.breed   = r.breed   || '';
            petMeta.sex     = r.sex     || '';
          }
        }
      }
    } catch (_) {}

    // Build normalized history
    const history = (entry.consultationHistory || [])
      .map(ch => {
        const c    = ch.consultation || {};
        const resv = c.reservation   || {};

        const diseaseRaw =
              Array.isArray(c.diseases)         ? c.diseases
            : c.disease                         ? [c.disease]
            : Array.isArray(c.existingDiseases) ? c.existingDiseases
            : c.existingDisease                 ? [c.existingDisease]
            : resv.disease                      ? [resv.disease]
            : [];

        const diseases = diseaseRaw
          .map(x => String(x || '').trim())
          .filter(Boolean)
          .filter((v, i, a) => a.findIndex(z => z.toLowerCase() === v.toLowerCase()) === i)
          .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

        return {
          id:         c._id,
          date:       c.createdAt || ch.addedAt,
          doctor:     resv.doctor || null,
          notes:      c.notes || c.consultationNotes || '',
          physical:   c.physicalExam || { weight: '', temperature: '', observations: '' },
          diagnosis:  c.diagnosis || '',
          diseases,
          services:   (c.services || []).map(s => ({
                        category:    s.category    || 'Uncategorized',
                        serviceName: s.serviceName || '',
                        details:     s.details     || '',
                        file:        s.file        || null
                      })),
          medications:(c.medications || []).map(m => ({
                        name:     m.name     || m.medicationName || '',
                        dosage:   m.dosage   || '',
                        remarks:  m.remarks  || '',
                        quantity: m.quantity || 0
                      })),
          confinement:c.confinementStatus || [],
          nextSchedule: resv.schedule
            ? { date: resv.schedule.scheduleDate, details: resv.schedule.scheduleDetails }
            : null
        };
      })
      .sort((a, b) => new Date(b.date) - new Date(a.date));

    return res.json({ success: true, pet: petMeta, history });
  } catch (err) {
    console.error('getPetHistory failed:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
}

module.exports = { getPetHistory };
