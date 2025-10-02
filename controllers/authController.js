// authController.js
const nodemailer = require("nodemailer");
const User = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const Joi = require("joi"); // <-- Added for input validation

// In-memory stores (for demo only)
let otpStore = {};       // For registration OTP
let resetOtpStore = {};  // For password reset OTP
let adminOtpStore = {};  // For admin login OTP
let otpCooldown = {};     // { email: lastSentMs }
let resetOtpCooldown = {}; // optional: throttle for password-reset OTPs

// In-memory login attempt counter (for demo only)
const loginAttempts = {};  // e.g. { "admin@example.com": { count: 0, lockoutStart: Date } }
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 5 * 60 * 1000; // 5 minutes

// Configure Brevo SMTP
const transporter = nodemailer.createTransport({
  host: "smtp-relay.brevo.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_EMAIL,
    pass: process.env.SMTP_PASS
  }
});

/**
 * validateCaptcha: Validate the reCAPTCHA response using Google API.
 */
async function validateCaptcha(captchaResponse) {
  const secretKey = process.env.GOOGLE_RECAPTCHA_SECRET;
  try {
    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaResponse}`
    );
    return response.data.success;
  } catch (err) {
    console.error("reCAPTCHA validation error:", err);
    return false;
  }
}

// =========================
// SEND OTP (Registration)
// =========================
exports.sendOTP = async (req, res) => {
  const { email } = req.body;
  const normalizedEmail = email.trim().toLowerCase();
  const ADMIN_EMAIL = "smartvetclinic17@gmail.com";

  try {
    if (normalizedEmail === ADMIN_EMAIL) {
      return res.status(400).json({ message: "Admin email cannot be used for registration!" });
    }

    // === NEW: Cooldown guard (before generating/sending the OTP) ===
    const now = Date.now();
    const COOLDOWN_MS = 60 * 1000; // 60 seconds
    const last = otpCooldown[normalizedEmail] || 0;
    if (now - last < COOLDOWN_MS) {
      const wait = Math.ceil((COOLDOWN_MS - (now - last)) / 1000);
      return res.status(429).json({ message: `Please wait ${wait}s before requesting another OTP.` });
    }
    otpCooldown[normalizedEmail] = now;
    // ===============================================================

    const existingUser = await User.findOne({ email: { $regex: `^${normalizedEmail}$`, $options: "i" } });
    if (existingUser) {
      return res.status(400).json({ message: "This email is already registered! Please log in." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    otpStore[normalizedEmail] = otp;

    const mailOptions = {
      from: `"SmartVet" <dehe.marquez.au@phinmaed.com>`,
      to: normalizedEmail,
      subject: "Your OTP Verification Code",
      text: `Your OTP code is: ${otp}. It expires in 5 minutes.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        // NEW: clear cooldown if send failed so the user can retry
        delete otpCooldown[normalizedEmail];
        console.error("SMTP ERROR:", error);
        return res.status(500).json({ message: "Failed to send OTP. Check SMTP settings." });
      }
      console.log("Email sent: " + info.response);
      res.status(200).json({ message: "OTP sent. Check your email!" });
    });
  } catch (error) {
    // (Optional) also clear on unexpected errors
    delete otpCooldown[normalizedEmail];
    console.error("Error Sending OTP:", error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
};


// ================================
// Verify OTP & Register User
// ================================
exports.verifyOTPAndRegister = async (req, res) => {
  const { username, password, email, otp } = req.body;
  const normalizedEmail = email.trim().toLowerCase();
  const normalizedUsername = username.trim().toLowerCase();
  const ADMIN_EMAIL = "smartvetclinic17@gmail.com";

  if (normalizedEmail === ADMIN_EMAIL) {
    return res.status(400).json({ message: "Admin email cannot be used for user registration!" });
  }

  if (!otpStore[normalizedEmail] || otpStore[normalizedEmail] !== parseInt(otp)) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  try {
    const existingUser = await User.findOne({ email: { $regex: `^${normalizedEmail}$`, $options: "i" } });
    if (existingUser) {
      return res.status(400).json({ message: "This email is already registered! Please log in." });
    }

    const existingUsername = await User.findOne({ username: { $regex: `^${normalizedUsername}$`, $options: "i" } });
    if (existingUsername) {
      return res.status(400).json({ message: "This username is already taken! Please choose another one." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username: normalizedUsername,
      password: hashedPassword,
      email: normalizedEmail,
      verified: true
    });
    await newUser.save();

    delete otpStore[normalizedEmail];

    res.status(200).json({ message: "Successfully registered!", success: true });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Registration failed" });
  }
};

// ================================
// SEND OTP for Admin Login
// ================================
exports.sendAdminOTP = async (req, res) => {
  const { email } = req.body;
  const normalizedEmail = email.trim().toLowerCase();
  try {
    const user = await User.findOne({ email: normalizedEmail });
    if (!user || user.role !== "Admin") {
      return res.status(400).json({ message: "Admin account not found!" });
    }
    const otp = (Math.floor(100000 + Math.random() * 900000)).toString();
    adminOtpStore[normalizedEmail] = otp;
    console.log("Stored Admin OTP:", otp);
    const mailOptions = {
      from: `"SmartVet" <dehe.marquez.au@phinmaed.com>`,
      to: normalizedEmail,
      subject: "Admin OTP Verification",
      text: `Your OTP for admin login is: ${otp}. It expires in 5 minutes.`
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("SMTP ERROR:", error);
        return res.status(500).json({ message: "Failed to send OTP. Check SMTP settings." });
      }
      console.log("Admin OTP sent:", info.response);
      res.status(200).json({ message: "Admin OTP sent. Check your email!" });
    });
  } catch (error) {
    console.error("Error Sending Admin OTP:", error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
};

// ================================
// LOGIN (with CAPTCHA & Role-Specific Cookie Names)
// ================================
exports.login = async (req, res) => {
  const { email, password, captchaResponse } = req.body;
  const normalizedEmail = email.trim().toLowerCase();
  const FAILED_ATTEMPTS_THRESHOLD = 3;
  const LOCKOUT_DURATION = 5 * 60 * 1000; // 5 minutes in milliseconds

  if (!loginAttempts[normalizedEmail]) {
    loginAttempts[normalizedEmail] = { count: 0, lockoutStart: null };
  }
  const attempt = loginAttempts[normalizedEmail];
  const now = new Date();

  if (attempt.lockoutStart && now - attempt.lockoutStart < LOCKOUT_DURATION) {
    console.log(`User ${normalizedEmail} is locked out.`);
    return res.status(429).json({ message: "Too many failed attempts. Please try again in 5 minutes." });
  } else if (attempt.lockoutStart && now - attempt.lockoutStart >= LOCKOUT_DURATION) {
    attempt.count = 0;
    attempt.lockoutStart = null;
  }

  try {
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      attempt.count++;
      if (attempt.count >= FAILED_ATTEMPTS_THRESHOLD) {
        attempt.lockoutStart = now;
      }
      console.log(`User not found. New attempt count for ${normalizedEmail}: ${attempt.count}`);
      return res.status(400).json({ emailError: "Invalid Gmail" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      attempt.count++;
      if (attempt.count >= FAILED_ATTEMPTS_THRESHOLD) {
        attempt.lockoutStart = now;
      }
      console.log(`Password mismatch. New attempt count for ${normalizedEmail}: ${attempt.count}`);
      return res.status(400).json({ passwordError: "Password did not match!" });
    }

    attempt.count = 0;
    attempt.lockoutStart = null;

    console.log("User role:", user.role, "OTP enabled:", user.otpEnabled);
    if (user.role === "Admin" && user.otpEnabled) {
      await exports.sendAdminOTP({ body: { email: normalizedEmail } });
      return res.status(200).json({ message: "Admin OTP sent. Check your email!", requireOTP: true });
    }

    let redirectPath = "/customer-dashboard";
    if (user.role === "Doctor") redirectPath = "/doctor-dashboard";
    else if (user.role === "HR") redirectPath = "/hr-dashboard";
    else if (user.role === "Admin") redirectPath = "/admin-dashboard";

    // For testing: Access token expires in 1 minute
    const accessToken = jwt.sign(
      { userId: user._id, username: user.username, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    // Refresh token remains long-lived (e.g. 7 days)
    const refreshToken = jwt.sign(
      { userId: user._id, username: user.username, email: user.email, role: user.role },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );
    // Role-specific access token cookie (expires in 1 minute for testing)
   const isProd = process.env.NODE_ENV === "production";
const accessCookieName = user.role.toLowerCase() + "_token";
res.cookie(accessCookieName, accessToken, {
  httpOnly: true,
  maxAge: 60 * 60 * 1000,
  path: "/",
  sameSite: "lax",
  secure: isProd
});
// --- ADD THIS: set refresh token cookie (7 days) ---
res.cookie("refreshToken", refreshToken, {
  httpOnly: true,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: "/",
  sameSite: "lax",
  secure: isProd
});

    // Send login notification email
    const mailOptions = {
      from: `"SmartVet" <dehe.marquez.au@phinmaed.com>`,
      to: normalizedEmail,
      subject: "Login Notification",
      text: `You have just logged in. If this wasn't you, please contact support immediately.`
    };
    
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Failed to send login notification email:", error);
      } else {
        console.log("Login notification email sent:", info.response);
      }
    });

    res.status(200).json({ message: "Login successful!", redirect: redirectPath });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed!" });
  }
};


// ================================
// VERIFY ADMIN OTP
// ================================
exports.verifyAdminOTP = async (req, res) => {
  const { email, otp } = req.body;
  const normalizedEmail = email.trim().toLowerCase();

  console.log("Stored Admin OTP:", adminOtpStore[normalizedEmail]);
  console.log("Received OTP:", otp);

  if (!adminOtpStore[normalizedEmail] || adminOtpStore[normalizedEmail] !== otp) {
    return res.status(400).json({ message: "Invalid OTP" });
  }
  delete adminOtpStore[normalizedEmail];
  const user = await User.findOne({ email: normalizedEmail });
  if (!user) {
    return res.status(400).json({ message: "User not found." });
  }
  if (user.role !== "Admin") {
    return res.status(403).json({ message: "Not an Admin user." });
  }
  const accessToken = jwt.sign(
    { userId: user._id, username: user.username, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
const isProd = process.env.NODE_ENV === "production";
res.cookie("admin_token", accessToken, {
  httpOnly: true,
  maxAge: 60 * 60 * 1000,
  path: "/",
  sameSite: "lax",
  secure: isProd
});
  return res.status(200).json({
    message: "OTP verified! You are now logged in as Admin. Redirecting...",
    redirect: "/admin-dashboard"
  });
};

// ================================
// Check Username & Email Availability and other functions...
// ================================

// ---------- UPDATED: Check Username Availability with Joi Validation ----------
const usernameSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
});

exports.checkUsernameAvailability = async (req, res) => {
  const { username } = req.query;
  if (!username) {
    return res.status(400).json({ available: false, message: "Username is required!" });
  }

  // Validate the username using Joi
  const { error } = usernameSchema.validate({ username });
  if (error) {
    return res.status(400).json({ available: false, message: error.details[0].message });
  }

  try {
    const normalizedUsername = username.trim().toLowerCase();
    const existingUser = await User.findOne({ username: { $regex: `^${normalizedUsername}$`, $options: "i" } });
    if (existingUser) {
      return res.status(400).json({ available: false, message: "Username is already taken!" });
    }
    res.status(200).json({ available: true, message: "Username is available!" });
  } catch (error) {
    console.error("❌ Error checking username:", error);
    res.status(500).json({ available: false, message: "Server error, try again later." });
  }
};

// ================================
// Check Email Availability
// ================================
exports.checkEmailAvailability = async (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ available: false, message: "Email is required!" });
  }
  try {
    const normalizedEmail = email.trim().toLowerCase();
    const ADMIN_EMAIL = "smartvetclinic17@gmail.com";
    if (normalizedEmail === ADMIN_EMAIL) {
      return res.status(400).json({ available: false, message: "This email cannot be used for registration!" });
    }
    const existingUser = await User.findOne({ email: { $regex: `^${normalizedEmail}$`, $options: "i" } });
    if (existingUser) {
      return res.status(400).json({ available: false, message: "This email is already registered! Please log in." });
    }
    res.status(200).json({ available: true, message: "Email is available!" });
  } catch (error) {
    console.error("❌ Error checking email:", error);
    res.status(500).json({ available: false, message: "Server error, try again later." });
  }
};

// ================================
// SEND OTP for Password Reset (All Users)
// ================================
// ================================
// SEND OTP for Password Reset (All Users) — with cooldown
// ================================
exports.sendResetOTP = async (req, res) => {
  const { email } = req.body;
  const normalizedEmail = email.trim().toLowerCase();

  if (!normalizedEmail.includes("@gmail.com")) {
    return res.status(400).json({ message: "Invalid Gmail address! Please enter a valid @gmail.com email." });
  }

  try {
    // 1) Make sure the account exists first
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(400).json({ message: "This email is not registered!" });
    }

    // 2) Cooldown guard — before generating/sending OTP
    const now = Date.now();
    const COOLDOWN_MS = 60 * 1000; // 60 seconds
    const last = resetOtpCooldown[normalizedEmail] || 0;
    if (now - last < COOLDOWN_MS) {
      const wait = Math.ceil((COOLDOWN_MS - (now - last)) / 1000);
      return res.status(429).json({ message: `Please wait ${wait}s before requesting another OTP.` });
    }
    resetOtpCooldown[normalizedEmail] = now;

    // 3) Generate and send OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    resetOtpStore[normalizedEmail] = otp;

    const mailOptions = {
      from: `"SmartVet" <dehe.marquez.au@phinmaed.com>`,
      to: normalizedEmail,
      subject: "Password Reset OTP",
      text: `Your OTP for password reset is: ${otp}. It expires in 5 minutes.`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        // IMPORTANT: clear cooldown on SMTP failure so the user can retry
        delete resetOtpCooldown[normalizedEmail];
        console.error("❌ SMTP ERROR:", error);
        return res.status(500).json({ message: "Failed to send OTP. Check SMTP settings." });
      }
      console.log("✅ Reset OTP sent: " + info.response);
      res.status(200).json({ message: "OTP sent. Check your email!" });
    });
  } catch (error) {
    // Also clear cooldown on unexpected error
    delete resetOtpCooldown[normalizedEmail];
    console.error("❌ Error sending reset OTP:", error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
};


// ================================
// VERIFY RESET OTP
// ================================
exports.verifyResetOTP = async (req, res) => {
  const { email, otp } = req.body;
  const normalizedEmail = email.trim().toLowerCase();
  if (!resetOtpStore[normalizedEmail] || resetOtpStore[normalizedEmail] !== otp) {
    return res.status(400).json({ message: "Invalid OTP" });
  }
  delete resetOtpStore[normalizedEmail];
  res.status(200).json({ message: "OTP verified! You can now reset your password." });
};

// ================================
// RESET PASSWORD
// ================================
exports.resetPassword = async (req, res) => {
  const { email, newPassword } = req.body;
  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) {
      return res.status(400).json({ message: "User not found!" });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    res.status(200).json({ message: "Password reset successfully! You can now log in." });
  } catch (error) {
    console.error("❌ Error resetting password:", error);
    res.status(500).json({ message: "Password reset failed." });
  }
};

// ================================
// REFRESH TOKEN Endpoint (Unified Refresh Token Cookie)
// ================================
exports.refreshToken = async (req, res) => {
  console.log("Incoming cookies:", req.cookies);  // Debug log
  const refreshToken = req.cookies["refreshToken"];
  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token provided" });
  }
  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const newAccessToken = jwt.sign(
      {
        userId: decoded.userId,
        username: decoded.username,
        email: decoded.email,
        role: decoded.role
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" } // You can test with "1h" or "1m" as needed
    );
    const cookieName = decoded.role.toLowerCase() + "_token";
const isProd = process.env.NODE_ENV === "production";
res.cookie(cookieName, newAccessToken, {
  httpOnly: true,
  maxAge: 60 * 60 * 1000,
  path: "/",
  sameSite: "lax",
  secure: isProd
});
    res.status(200).json({ message: "Access token refreshed" });
  } catch (error) {
    console.error("Refresh token error:", error);
    return res.status(401).json({ message: "Invalid refresh token" });
  }
};
