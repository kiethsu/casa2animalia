// adminRoutes.js
const express = require("express");
const path = require("path");
const multer = require("multer");
const adminController = require("../controllers/adminController");
const DashboardSetting = require('../models/dashboardSetting');
const Joi = require('joi');
const Inventory = require("../models/inventory");
const router = express.Router();
const Service = require("../models/service");
const ServiceCategory = require("../models/serviceCategory");
const mongoose = require("mongoose");
const Payment = require('../models/Payment');
const PetList = require('../models/petlist');
const salesReportController = require("../controllers/salesReportController");

// Helper middleware for validating request bodies
function validateRequest(schema) {
  return (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    next();
  };
}

// Define schemas for input validation
const createAccountSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  role: Joi.string().valid("Doctor", "HR").required(),
});

const resetAccountSchema = Joi.object({
  userId: Joi.string().required(),
  newEmail: Joi.string().email().optional().allow(''),
  newPassword: Joi.string().min(8).optional().allow(''),
});

const deleteAccountSchema = Joi.object({
  userId: Joi.string().required()
});

const updateOtpSettingSchema = Joi.object({
  userId: Joi.string().required(),
  otpEnabled: Joi.boolean().required()
});

// Configure Multer storage for profile image uploads.
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Make sure "public/uploads" folder exists
    cb(null, path.join(__dirname, "../public/uploads"));
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, "profile-" + Date.now() + ext);
  }
});
const upload = multer({ storage });

// -------------------- Admin API Endpoints --------------------

// Create Account route with input validation
router.post(
  "/create-account",
  validateRequest(createAccountSchema),
  adminController.createAccount
);

// Get accounts, reset account, delete account
router.get("/api/accounts", adminController.getAccounts);
router.put("/reset-account", validateRequest(resetAccountSchema), adminController.resetAccount);
router.delete("/delete-account", validateRequest(deleteAccountSchema), adminController.deleteAccount);
router.get("/profile/:userId", adminController.getAccountProfile);

// Update OTP Verification Setting for Admin
router.post(
  "/update-otp-setting",
  validateRequest(updateOtpSettingSchema),
  adminController.updateOTPSetting
);

// -------------------- Admin View Routes --------------------
router.get("/dashboard", (req, res) => {
  res.render("dashboard");
});
router.get("/accounts-view", (req, res) => {
  res.render("accounts");
});
// In adminRoutes.js, update the profile view route:
router.get("/profile", async (req, res) => {
  try {
    // For example, if the admin's email is known:
    const adminUser = await require("../models/user").findOne({ email: "smartvetclinic17@gmail.com" }).lean();
    if (!adminUser) {
      return res.status(404).send("Admin user not found.");
    }
    res.render("profile", { user: adminUser });
  } catch (error) {
    console.error("Error fetching admin profile:", error);
    res.status(500).send("Server error");
  }
});

// Replace your current /petlist route with:
router.get("/petlist", async (req, res) => {
  try {
    const entries = await PetList.find()
      .populate('owner', 'username')
      .lean();
    res.render("petlist", { entries });
  } catch (err) {
    console.error("Error fetching pet list:", err);
    res.status(500).send("Server error");
  }
});

router.get('/get-pet-history', async (req, res) => {
  const { petId, petName, ownerId } = req.query;
  if (!petId && !petName) {
    return res.json({ success: false, message: 'petId or petName is required' });
  }
  try {
    const entry = await PetList.findOne(
      petId
        ? { _id: petId }
        : { owner: ownerId, petName }
    )
    .populate({
      path: 'consultationHistory.consultation',
      populate: {
        path: 'reservation',
        select: 'date schedule doctor',
        populate: { path: 'doctor', select: 'username' }
      }
    })
    .lean();

    if (!entry) {
      return res.json({ success: false, message: 'PetList entry not found.' });
    }

    const history = entry.consultationHistory
      .map(ch => {
        const c   = ch.consultation || {};
        const resv = c.reservation || {};
        return {
          id:         c._id,
          date:       c.createdAt || ch.addedAt,
          doctor:     resv.doctor || null,
          notes:      c.notes || c.consultationNotes || '',
          physical:   c.physicalExam || {},
          diagnosis:  c.diagnosis || '',
          services:   c.services || [],
          medications:c.medications || [],
          confinement:c.confinementStatus || [],
          nextSchedule: resv.schedule
            ? {
                date:    resv.schedule.scheduleDate,
                details: resv.schedule.scheduleDetails
              }
            : null
        };
      })
      .sort((a, b) => new Date(b.date) - new Date(a.date));

    return res.json({ success: true, history });
  } catch (err) {
    console.error('Error fetching pet history for admin:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.get("/generate-report", adminController.generateReport);
router.get("/peak-day-of-week", adminController.getPeakDayOfWeek);

router.get("/predict-appointments", adminController.predictAppointments);
router.post("/update-profile", upload.single("profilePic"), adminController.updateProfile);

// Dashboard stats
router.get("/get-dashboard-stats", adminController.getDashboardStats);

// Render the Inventory view
router.get("/inventory", (req, res) => {
  res.render("inventory"); // Ensure views/inventory.ejs exists.
});

// API route to list all inventory items
router.get("/inventory/list", async (req, res) => {
  try {
    const items = await Inventory.find().lean();
    res.json(items);
  } catch (error) {
    res.status(500).json({ message: "Error fetching inventory items" });
  }
});

// ─── Add a New Inventory Item ───────────────────────────────────────
// ─── Add a New Inventory Item ───────────────────────────────────────
router.post("/inventory/add", async (req, res) => {
  try {
    const { name, category, basePrice, markup, quantity } = req.body;

    const bPrice = parseFloat(basePrice) || 0;
    const mAmt   = parseFloat(markup)    || 0;  // pesos
    const qty    = parseInt(quantity, 10) || 0;

    // NEW: peso-based price
    const finalPrice = Math.round((bPrice + mAmt) * 100) / 100;

    // ... expiration handling unchanged ...
    let expirationDates = req.body["expirationDates[]"] || req.body.expirationDates;
    if (expirationDates) {
      if (!Array.isArray(expirationDates)) expirationDates = [expirationDates];
      expirationDates = expirationDates
        .map(s => new Date(s))
        .filter(d => !isNaN(d.getTime()));
    } else {
      expirationDates = [];
    }

    const today = new Date(); today.setHours(0,0,0,0);
    const validDates = [], alreadyExpired = [];
    expirationDates.forEach(d => (d < today ? alreadyExpired : validDates).push(d));

    const newItem = new Inventory({
      name,
      category,
      basePrice:    bPrice,
      markup:       mAmt,         // pesos stored
      price:        finalPrice,   // base + markup
      quantity:     qty,
      expirationDates: validDates,
      expiredDates:    alreadyExpired,
      expiredCount:    alreadyExpired.length
    });

    await newItem.save();
    res.json({ message: "Inventory item added successfully" });
  } catch (error) {
    console.error("Error adding inventory item:", error);
    res.status(500).json({ message: "Error adding inventory item" });
  }
});

// API route to fetch a single inventory item by ID
router.get("/inventory/item/:id", async (req, res) => {
  try {
    const item = await Inventory.findById(req.params.id).lean();
    res.json(item);
  } catch (error) {
    res.status(500).json({ message: "Error fetching inventory item" });
  }
});

// ─── Edit an Inventory Item ─────────────────────────────────────────
router.post("/inventory/edit", async (req, res) => {
  try {
    const { id, name, category, basePrice, markup, quantity } = req.body;

    const bPrice = parseFloat(basePrice) || 0;
    const mAmt   = parseFloat(markup)    || 0; // pesos
    const qty    = parseInt(quantity, 10) || 0;

    // NEW: peso-based price
    const finalPrice = Math.round((bPrice + mAmt) * 100) / 100;

    // expiration parsing unchanged ...
    let expirationDates = req.body["expirationDates[]"] || req.body.expirationDates;
    if (expirationDates) {
      if (!Array.isArray(expirationDates)) expirationDates = [expirationDates];
      expirationDates = expirationDates
        .map(s => new Date(s))
        .filter(d => !isNaN(d.getTime()));
    } else {
      expirationDates = [];
    }

    const today = new Date(); today.setHours(0,0,0,0);
    const validDates = [], alreadyExpired = [];
    expirationDates.forEach(d => (d < today ? alreadyExpired : validDates).push(d));

    const existing = await Inventory.findById(id).lean();
    if (!existing) return res.status(404).json({ message: "Item not found" });

    const combinedExpiredDates = [
      ...existing.expiredDates.map(d => new Date(d)),
      ...alreadyExpired
    ];
    const newExpiredCount = combinedExpiredDates.length;

    await Inventory.findByIdAndUpdate(id, {
      name,
      category,
      basePrice:       bPrice,
      markup:          mAmt,        // pesos stored
      price:           finalPrice,  // base + markup
      quantity:        qty,
      expirationDates: validDates,
      expiredDates:    combinedExpiredDates,
      expiredCount:    newExpiredCount
    });

    res.json({ message: "Inventory item updated successfully" });
  } catch (error) {
    console.error("Error updating inventory item:", error);
    res.status(500).json({ message: "Error updating inventory item" });
  }
});


// API route to delete an inventory item
router.post("/inventory/delete", async (req, res) => {
  try {
    const { id } = req.body;
    await Inventory.findByIdAndDelete(id);
    res.json({ message: "Inventory item deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting inventory item" });
  }
});

// -------------------- Service Category Routes --------------------
router.get("/services/categories/list", async (req, res) => {
  try {
    const categories = await ServiceCategory.find().lean();
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: "Error fetching categories" });
  }
});
router.post("/services/categories/add", async (req, res) => {
  try {
    const { name } = req.body;
    const newCategory = new ServiceCategory({ name });
    await newCategory.save();
    res.json({ message: "Category added successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error adding category" });
  }
});
router.post("/services/categories/delete", async (req, res) => {
  try {
    await ServiceCategory.findByIdAndDelete(req.body.id);
    res.json({ message: "Category deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting category" });
  }
});

// -------------------- Service Item Routes --------------------
// Render the Services view
router.get("/services", (req, res) => {
  res.render("services");
});
router.get("/services/list", async (req, res) => {
  try {
    const services = await Service.find().lean();
    for (let svc of services) {
      if (mongoose.Types.ObjectId.isValid(svc.category)) {
        const cat = await ServiceCategory.findById(svc.category).lean();
        svc.categoryName = cat ? cat.name : "Unknown";
      } else {
        svc.categoryName = "Invalid Category";
      }
    }
    res.json(services);
  } catch (error) {
    console.error("Error fetching services:", error);
    res.status(500).json({ message: "Error fetching services", error: error.message });
  }
});
router.post("/services/add", async (req, res) => {
  try {
    const { category, serviceName, weight, dosage, price } = req.body;
    const newService = new Service({ category, serviceName, weight, dosage, price });
    await newService.save();
    res.json({ message: "Service added successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error adding service" });
  }
});
router.get("/services/item/:id", async (req, res) => {
  try {
    const service = await Service.findById(req.params.id).lean();
    res.json(service);
  } catch (error) {
    res.status(500).json({ message: "Error fetching service item" });
  }
});
router.post("/services/edit", async (req, res) => {
  try {
    const { id, category, serviceName, weight, dosage, price } = req.body;
    await Service.findByIdAndUpdate(id, { category, serviceName, weight, dosage, price });
    res.json({ message: "Service updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating service" });
  }
});
router.post("/services/delete", async (req, res) => {
  try {
    await Service.findByIdAndDelete(req.body.id);
    res.json({ message: "Service deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting service" });
  }
});

router.get('/inventory-stats', adminController.getInventoryStats);

// Sales Report page
router.get("/sales-report", (req, res) => {
  res.render("sales-report");
});

// ─── Shared (Dashboard) data endpoints (keep these on adminController) ───
router.get('/get-categories', adminController.getCategories);
router.get("/get-sales-by-category", adminController.getSalesByCategory);
router.get("/get-sales-by-product",  adminController.getSalesByProduct);
router.get("/get-sales-by-service",  adminController.getSalesByService);
router.get('/expired-products',       adminController.getExpiredProducts);
router.get("/downloadSalesExcel",     adminController.downloadSalesExcel);
router.get("/downloadSalesCSV",       adminController.downloadSalesCSV);
router.get("/download-sales-report.pdf", adminController.downloadSalesPDF);
router.get('/get-top-category',       adminController.getTopCategory);

// ─── Namespaced Sales Report endpoints (NO collisions) ────────────────────
router.get("/report/get-sales-kpis",        salesReportController.getSalesKPIs);
router.get("/report/get-sales-by-product",  salesReportController.getSalesByProduct);
router.get("/report/get-sales-by-service",  salesReportController.getSalesByService);
router.get("/report/get-sales-by-category", salesReportController.getSalesByCategory);
router.get("/report/expired-products",      salesReportController.getExpiredProducts);

// (Optional) if you want separate categories endpoint for report:
// router.get("/report/get-categories",        salesReportController.getProductCategories);
router.get('/report/top-profit-items', salesReportController.getTopProfitItems);
router.get('/report/expiring-soon', salesReportController.getExpiringSoon);

// Slow movers (no sales in range)
router.get('/report/slow-movers', salesReportController.getSlowMovers);
// Excel export (filter-aware)
router.get('/report/export-excel', salesReportController.exportExcel);
router.get('/categories', adminController.listCategories);
router.post('/categories', adminController.addCategory);
router.patch('/categories/:id', adminController.renameCategory);
router.delete('/categories/:id', adminController.deleteCategory);
module.exports = router;
