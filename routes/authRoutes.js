const express = require("express");
const {
  sendOTP,
  verifyOTPAndRegister,
  login,
  verifyAdminOTP,
  checkUsernameAvailability,
  checkEmailAvailability,
  sendResetOTP,
  verifyResetOTP,
  resetPassword,
  refreshToken
} = require("../controllers/authController");
const Joi = require('joi');

const router = express.Router();

// Helper middleware for validating request bodies or queries
function validateRequest(schema, property = 'body') {
  return (req, res, next) => {
    const { error } = schema.validate(req[property]);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    next();
  };
}

// Define schemas
const emailSchema = Joi.object({
  email: Joi.string().email().required()
});

const verifyRegisterSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  password: Joi.string().min(8).required(),
  email: Joi.string().email().required(),
  otp: Joi.string().length(6).required()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
  captchaResponse: Joi.string().required()
});

const adminOtpSchema = Joi.object({
  email: Joi.string().email().required(),
  otp: Joi.string().required()
});

const resetPasswordSchema = Joi.object({
  email: Joi.string().email().required(),
  newPassword: Joi.string().min(8).required()
});

// New schema for verify reset OTP that validates both email and otp
const verifyResetOtpSchema = Joi.object({
  email: Joi.string().email().required(),
  otp: Joi.string().length(6).required()
});

// Authentication & Registration Routes
router.post("/send-otp", validateRequest(emailSchema), sendOTP);
router.post("/verify-register", validateRequest(verifyRegisterSchema), verifyOTPAndRegister);
router.post("/login", validateRequest(loginSchema), login);
router.post("/verify-admin-otp", validateRequest(adminOtpSchema), verifyAdminOTP);

// Refresh Token Endpoint (no validation needed here)
router.post("/refresh-token", refreshToken);

// Username & Email Availability Check (validation on query parameter)
const usernameQuerySchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required()
});
const emailQuerySchema = Joi.object({
  email: Joi.string().email().required()
});
router.get("/check-username", validateRequest(usernameQuerySchema, 'query'), checkUsernameAvailability);
router.get("/check-email", validateRequest(emailQuerySchema, 'query'), checkEmailAvailability);

// Password Reset Routes
router.post("/send-reset-otp", validateRequest(emailSchema), sendResetOTP);
router.post("/verify-reset-otp", validateRequest(verifyResetOtpSchema), verifyResetOTP);
router.post("/reset-password", validateRequest(resetPasswordSchema), resetPassword);

module.exports = router;