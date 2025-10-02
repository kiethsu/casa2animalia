// settingsRoutes.js
const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const AppointmentSetting = require('../models/appointmentSetting');
const DashboardSetting = require('../models/dashboardSetting');
const PetDetailsSetting = require('../models/petDetailsSetting');
const petDetailsController = require('../controllers/petDetailsController');
const Joi = require('joi');
const adminController = require("../controllers/adminController");
const path = require("path");
const multer = require("multer");

// Helper middleware for validation
function validateRequest(schema, property = 'body') {
  return (req, res, next) => {
    const { error } = schema.validate(req[property]);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    next();
  };
}

// Schema for dashboard settings update
const dashboardSettingsSchema = Joi.object({
  quickGuide: Joi.string().optional().allow(""),
  welcomeText: Joi.string().optional().allow(""),
  videoUrl: Joi.string().uri().optional().allow("")
});

// API endpoint to get the appointment limit
router.get('/appointmentLimit', async (req, res) => {
  try {
    let setting = await AppointmentSetting.findOne();
    if (!setting) {
      setting = await AppointmentSetting.create({});
    }
    res.json({ limit: setting.limitPerHour });
  } catch (error) {
    console.error("Error fetching appointment setting:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Pet Details Settings Page
router.get('/pet-details', authMiddleware, async (req, res) => {
  try {
    let petDetails = await PetDetailsSetting.findOne().lean();
    if (!petDetails) {
      petDetails = { species: [], speciesBreeds: {}, diseases: [], services: [] };
    }
    res.render('petdetails', { petDetails });
  } catch (error) {
    console.error("Error fetching pet details:", error);
    res.status(500).send("Server error");
  }
});

// Pet Details Endpoints
router.post('/add-species', authMiddleware, petDetailsController.addSpecies);
router.post('/delete-species', authMiddleware, petDetailsController.deleteSpecies);
router.post('/add-breed', authMiddleware, petDetailsController.addBreed);
router.post('/add-disease', authMiddleware, petDetailsController.addDisease);
router.post('/delete-disease', authMiddleware, petDetailsController.deleteDisease);
router.post('/add-service', authMiddleware, petDetailsController.addService);
router.post('/delete-service', authMiddleware, petDetailsController.deleteService);
router.post('/update-breeds', authMiddleware, petDetailsController.updateBreeds);

// Dashboard Settings Routes
router.get('/dashboardsetting', authMiddleware, async (req, res) => {
  try {
    let dashboardSetting = await DashboardSetting.findOne().lean();
    if (!dashboardSetting) {
      dashboardSetting = {};
    }
    res.render('dashboardsetting', { dashboardSetting, username: req.user.username });
  } catch (error) {
    console.error("Error fetching dashboard settings:", error);
    res.status(500).send("Server error");
  }
});

router.post('/update-dashboardsetting', validateRequest(dashboardSettingsSchema), async (req, res) => {
  try {
    const { quickGuide, welcomeText, videoUrl } = req.body;
    let setting = await DashboardSetting.findOne();
    if (setting) {
      setting.quickGuide = quickGuide;
      setting.welcomeText = welcomeText;
      setting.videoUrl = videoUrl;
      await setting.save();
    } else {
      setting = new DashboardSetting({ quickGuide, welcomeText, videoUrl });
      await setting.save();
    }
    res.redirect('/settings/dashboardsetting');
  } catch (error) {
    console.error("Error updating dashboard settings:", error);
    res.status(500).send("Server error");
  }
});

// Multer configuration for doctor picture uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, "../public/uploads"));
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, "doctor-" + Date.now() + ext);
  }
});
const upload = multer({ storage });

// GET the About content (using the controller method)
router.get("/about", authMiddleware, adminController.getAbout);

// POST to update the About content
router.post("/update-about", authMiddleware, upload.single("doctorPic"), adminController.updateAbout);

// GET Contact page (ensure contact.ejs and any includes exist)
router.get("/contact", authMiddleware, (req, res) => {
  res.render("contact");
});
// At the bottom of settingsRoutes.js, after your /update-about route
router.post("/delete-doctor", authMiddleware, adminController.deleteDoctor);

module.exports = router;