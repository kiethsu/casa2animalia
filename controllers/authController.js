// controllers/authController.js
const nodemailer = require("nodemailer");
const User = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const Joi = require("joi");

// ================================
// In-memory stores (demo only)
// ================================
let otpStore = {};            // Registration OTP
let resetOtpStore = {};       // Password reset OTP
let adminOtpStore = {};       // Admin login OTP
let otpCooldown = {};         // { email: lastSentMs }
let resetOtpCooldown = {};    // { email: lastSentMs }

const loginAttempts = {};     // { email: { count, lockoutStart } }
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 5 * 60 * 1000; // 5 minutes

// ================================
// SMTP Transport (Brevo)
// ================================
const transporter = nodemailer.createTransport({
  host: "smtp-relay.brevo.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_EMAIL,
    pass: process.env.SMTP_PASS
  }
});

// ================================
/** Helpers: mail + captcha + utils */
// ================================
const MAIL_FROM =
  process.env.SMTP_FROM ||
  `"SmartVet" <${process.env.SMTP_EMAIL || "dehe.marquez.au@phinmaed.com"}>`;

// Accept either env name for compatibility
const BREVO_KEY = process.env.BREVO_API_KEY || process.env.BREVO_SMS_API_KEY;
const hasBrevoApi = !!BREVO_KEY;

let transporterVerified = false;
async function ensureTransporterVerified() {
  if (transporterVerified) return;
  try {
    await transporter.verify();
    transporterVerified = true;
    console.log("[MAIL] SMTP transporter verified OK");
  } catch (e) {
    console.error("[MAIL] SMTP transporter verify FAILED:", fullErr(e));
  }
}
function fullErr(e) {
  return JSON.stringify(e, Object.getOwnPropertyNames(e));
}
function normEmail(v) {
  return (v || "").trim().toLowerCase();
}

/**
 * sendEmail: SMTP first, then fallback to Brevo HTTP API.
 */
async function sendEmail({ to, subject, text, html }) {
  await ensureTransporterVerified();

  // Try SMTP if configured
  if (process.env.SMTP_EMAIL && process.env.SMTP_PASS) {
    try {
      const info = await transporter.sendMail({
        from: MAIL_FROM,
        to,
        subject,
        text,
        html
      });
      console.log("[MAIL][SMTP] queued:", info.response || info);
      return { ok: true, via: "smtp", info };
    } catch (e) {
      console.error("[MAIL][SMTP] send FAILED:", fullErr(e));
      // fallthrough to API if available
    }
  } else {
    console.warn("[MAIL] SMTP creds missing; trying API fallback.");
  }

  // Fallback: Brevo HTTP API
  if (hasBrevoApi) {
    try {
      const senderEmail = (MAIL_FROM.match(/<(.+?)>/) || [])[1] || process.env.SMTP_EMAIL;
      const payload = {
        sender: { name: "SmartVet Clinic", email: senderEmail },
        to: [{ email: to }],
        subject,
        textContent: text,
        htmlContent: html || undefined
      };
      const resp = await axios.post(
        "https://api.brevo.com/v3/smtp/email",
        payload,
        { headers: { "api-key": BREVO_KEY, "Content-Type": "application/json" } }
      );
      console.log("[MAIL][API] queued:", resp.status, resp.data?.messageId || "");
      return { ok: true, via: "api", info: resp.data };
    } catch (e2) {
      console.error("[MAIL][API] send FAILED:", fullErr(e2));
      return { ok: false, via: "api", error: e2 };
    }
  }

  return { ok: false, via: "none", error: new Error("No mail transport available") };
}

/**
 * validateCaptcha: Verify Google reCAPTCHA.
 * If GOOGLE_RECAPTCHA_SECRET is missing, skip validation (returns true).
 */
async function validateCaptcha(captchaResponse) {
  const secretKey = process.env.GOOGLE_RECAPTCHA_SECRET;
  if (!secretKey) {
    console.warn("[CAPTCHA] Secret not set; skipping verification.");
    return true;
  }
  try {
    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaResponse}`
    );
    return !!response.data.success;
  } catch (err) {
    console.error("reCAPTCHA validation error:", fullErr(err));
    return false;
  }
}

// =========================
// SEND OTP (Registration)
// =========================
exports.sendOTP = async (req, res) => {
  const normalizedEmail = normEmail(req.body.email);
  const ADMIN_EMAIL = "smartvetclinic17@gmail.com";

  try {
    if (normalizedEmail === ADMIN_EMAIL) {
      return res.status(400).json({ message: "Admin email cannot be used for registration!" });
    }

    // Cooldown guard
    const now = Date.now();
    const COOLDOWN_MS = 60 * 1000;
    const last = otpCooldown[normalizedEmail] || 0;
    if (now - last < COOLDOWN_MS) {
      const wait = Math.ceil((COOLDOWN_MS - (now - last)) / 1000);
      return res.status(429).json({ message: `Please wait ${wait}s before requesting another OTP.` });
    }
    otpCooldown[normalizedEmail] = now;

    // Block if already registered
    const existingUser = await User.findOne({
      email: { $regex: `^${normalizedEmail}$`, $options: "i" }
    });
    if (existingUser) {
      return res.status(400).json({ message: "This email is already registered! Please log in." });
    }

    // Generate & send
    const otp = Math.floor(100000 + Math.random() * 900000);
    otpStore[normalizedEmail] = otp;

    const sendResult = await sendEmail({
      to: normalizedEmail,
      subject: "Your OTP Verification Code",
      text: `Your OTP code is: ${otp}. It expires in 5 minutes.`
    });

    if (!sendResult.ok) {
      delete otpCooldown[normalizedEmail];
      console.error("[SEND_OTP] failed via:", sendResult.via, "err:", fullErr(sendResult.error));
      return res.status(500).json({ message: "Failed to send OTP. Check SMTP/API settings." });
    }

    console.log(`[SEND_OTP] Sent via ${sendResult.via} to ${normalizedEmail}`);
    return res.status(200).json({ message: "OTP sent. Check your email!" });
  } catch (error) {
    delete otpCooldown[normalizedEmail];
    console.error("Error Sending OTP:", fullErr(error));
    return res.status(500).json({ message: "Failed to send OTP" });
  }
};

// ================================
// Verify OTP & Register User
// ================================
exports.verifyOTPAndRegister = async (req, res) => {
  const { username, password, email, otp } = req.body;
  const normalizedEmail = normEmail(email);
  const normalizedUsername = (username || "").trim().toLowerCase();
  const ADMIN_EMAIL = "smartvetclinic17@gmail.com";

  if (normalizedEmail === ADMIN_EMAIL) {
    return res.status(400).json({ message: "Admin email cannot be used for user registration!" });
  }

  if (!otpStore[normalizedEmail] || otpStore[normalizedEmail] !== parseInt(otp)) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  try {
    const existingUser = await User.findOne({
      email: { $regex: `^${normalizedEmail}$`, $options: "i" }
    });
    if (existingUser) {
      return res.status(400).json({ message: "This email is already registered! Please log in." });
    }

    const existingUsername = await User.findOne({
      username: { $regex: `^${normalizedUsername}$`, $options: "i" }
    });
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

    return res.status(200).json({ message: "Successfully registered!", success: true });
  } catch (error) {
    console.error("Registration error:", fullErr(error));
    return res.status(500).json({ message: "Registration failed" });
  }
};

// ================================
// SEND OTP for Admin Login
// ================================
exports.sendAdminOTP = async (req, res) => {
  const normalizedEmail = normEmail(req.body.email);
  try {
    const user = await User.findOne({ email: normalizedEmail });
    if (!user || user.role !== "Admin") {
      return res.status(400).json({ message: "Admin account not found!" });
    }

    const otp = (Math.floor(100000 + Math.random() * 900000)).toString();
    adminOtpStore[normalizedEmail] = otp;
    console.log("[ADMIN_OTP] Stored:", otp);

    const sendResult = await sendEmail({
      to: normalizedEmail,
      subject: "Admin OTP Verification",
      text: `Your OTP for admin login is: ${otp}. It expires in 5 minutes.`
    });

    if (!sendResult.ok) {
      console.error("[ADMIN_OTP] failed via:", sendResult.via, "err:", fullErr(sendResult.error));
      return res.status(500).json({ message: "Failed to send OTP. Check SMTP/API settings." });
    }

    console.log(`[ADMIN_OTP] Sent via ${sendResult.via} to ${normalizedEmail}`);
    return res.status(200).json({ message: "Admin OTP sent. Check your email!" });
  } catch (error) {
    console.error("Error Sending Admin OTP:", fullErr(error));
    return res.status(500).json({ message: "Failed to send OTP" });
  }
};

// ================================
// LOGIN (with CAPTCHA & Role-Specific Cookie Names)
// ================================
exports.login = async (req, res) => {
  const { email, password, captchaResponse } = req.body;
  const normalizedEmail = normEmail(email);
  const FAILED_ATTEMPTS_THRESHOLD = 3;
  const LOCK_MS = 5 * 60 * 1000;

  // Optional: verify reCAPTCHA (skips if secret is not set)
  const captchaOK = await validateCaptcha(captchaResponse);
  if (!captchaOK) {
    return res.status(400).json({ message: "CAPTCHA verification failed." });
  }

  if (!loginAttempts[normalizedEmail]) {
    loginAttempts[normalizedEmail] = { count: 0, lockoutStart: null };
  }
  const attempt = loginAttempts[normalizedEmail];
  const now = new Date();

  if (attempt.lockoutStart && now - attempt.lockoutStart < LOCK_MS) {
    return res.status(429).json({ message: "Too many failed attempts. Please try again in 5 minutes." });
  } else if (attempt.lockoutStart && now - attempt.lockoutStart >= LOCK_MS) {
    attempt.count = 0;
    attempt.lockoutStart = null;
  }

  try {
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      attempt.count++;
      if (attempt.count >= FAILED_ATTEMPTS_THRESHOLD) attempt.lockoutStart = now;
      return res.status(400).json({ emailError: "Invalid Gmail" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      attempt.count++;
      if (attempt.count >= FAILED_ATTEMPTS_THRESHOLD) attempt.lockoutStart = now;
      return res.status(400).json({ passwordError: "Password did not match!" });
    }

    // Success → reset attempts
    attempt.count = 0;
    attempt.lockoutStart = null;

    // Admin with OTP enabled: send OTP directly (do NOT call Express handler)
    if (user.role === "Admin" && user.otpEnabled) {
      const otp = (Math.floor(100000 + Math.random() * 900000)).toString();
      adminOtpStore[normalizedEmail] = otp;

      const sendResult = await sendEmail({
        to: normalizedEmail,
        subject: "Admin OTP Verification",
        text: `Your OTP for admin login is: ${otp}. It expires in 5 minutes.`
      });

      if (!sendResult.ok) {
        console.error("[LOGIN->ADMIN_OTP] send failed:", fullErr(sendResult.error));
        return res.status(500).json({ message: "Failed to send admin OTP." });
      }

      return res.status(200).json({ message: "Admin OTP sent. Check your email!", requireOTP: true });
    }

    // Issue tokens
    let redirectPath = "/customer-dashboard";
    if (user.role === "Doctor") redirectPath = "/doctor-dashboard";
    else if (user.role === "HR") redirectPath = "/hr-dashboard";
    else if (user.role === "Admin") redirectPath = "/admin-dashboard";

    const accessToken = jwt.sign(
      { userId: user._id, username: user.username, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    const refreshToken = jwt.sign(
      { userId: user._id, username: user.username, email: user.email, role: user.role },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    const isProd = process.env.NODE_ENV === "production";
    const accessCookieName = user.role.toLowerCase() + "_token";

    res.cookie(accessCookieName, accessToken, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000,
      path: "/",
      sameSite: "lax",
      secure: isProd
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
      sameSite: "lax",
      secure: isProd
    });

    // Fire-and-forget login notification email
    sendEmail({
      to: normalizedEmail,
      subject: "Login Notification",
      text: `You have just logged in. If this wasn't you, please contact support immediately.`
    }).catch(e => console.error("[LOGIN_NOTICE] failed:", fullErr(e)));

    return res.status(200).json({ message: "Login successful!", redirect: redirectPath });
  } catch (error) {
    console.error("Login error:", fullErr(error));
    return res.status(500).json({ error: "Login failed!" });
  }
};

// ================================
// VERIFY ADMIN OTP
// ================================
exports.verifyAdminOTP = async (req, res) => {
  const { email, otp } = req.body;
  const normalizedEmail = normEmail(email);

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
// Username & Email Availability
// ================================
const usernameSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
});

exports.checkUsernameAvailability = async (req, res) => {
  const { username } = req.query;
  if (!username) {
    return res.status(400).json({ available: false, message: "Username is required!" });
  }

  const { error } = usernameSchema.validate({ username });
  if (error) {
    return res.status(400).json({ available: false, message: error.details[0].message });
  }

  try {
    const normalizedUsername = (username || "").trim().toLowerCase();
    const existingUser = await User.findOne({
      username: { $regex: `^${normalizedUsername}$`, $options: "i" }
    });
    if (existingUser) {
      return res.status(400).json({ available: false, message: "Username is already taken!" });
    }
    return res.status(200).json({ available: true, message: "Username is available!" });
  } catch (error) {
    console.error("❌ Error checking username:", fullErr(error));
    return res.status(500).json({ available: false, message: "Server error, try again later." });
  }
};

exports.checkEmailAvailability = async (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ available: false, message: "Email is required!" });
  }
  try {
    const normalizedEmail = normEmail(email);
    const ADMIN_EMAIL = "smartvetclinic17@gmail.com";
    if (normalizedEmail === ADMIN_EMAIL) {
      return res.status(400).json({ available: false, message: "This email cannot be used for registration!" });
    }
    const existingUser = await User.findOne({
      email: { $regex: `^${normalizedEmail}$`, $options: "i" }
    });
    if (existingUser) {
      return res.status(400).json({ available: false, message: "This email is already registered! Please log in." });
    }
    return res.status(200).json({ available: true, message: "Email is available!" });
  } catch (error) {
    console.error("❌ Error checking email:", fullErr(error));
    return res.status(500).json({ available: false, message: "Server error, try again later." });
  }
};

// ================================
// SEND OTP for Password Reset (All Users) — with cooldown
// ================================
exports.sendResetOTP = async (req, res) => {
  const normalizedEmail = normEmail(req.body.email);

  if (!normalizedEmail.includes("@gmail.com")) {
    return res.status(400).json({ message: "Invalid Gmail address! Please enter a valid @gmail.com email." });
  }

  try {
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(400).json({ message: "This email is not registered!" });
    }

    // Cooldown guard
    const now = Date.now();
    const COOLDOWN_MS = 60 * 1000;
    const last = resetOtpCooldown[normalizedEmail] || 0;
    if (now - last < COOLDOWN_MS) {
      const wait = Math.ceil((COOLDOWN_MS - (now - last)) / 1000);
      return res.status(429).json({ message: `Please wait ${wait}s before requesting another OTP.` });
    }
    resetOtpCooldown[normalizedEmail] = now;

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    resetOtpStore[normalizedEmail] = otp;

    const sendResult = await sendEmail({
      to: normalizedEmail,
      subject: "Password Reset OTP",
      text: `Your OTP for password reset is: ${otp}. It expires in 5 minutes.`
    });

    if (!sendResult.ok) {
      delete resetOtpCooldown[normalizedEmail];
      console.error("[RESET_OTP] failed via:", sendResult.via, "err:", fullErr(sendResult.error));
      return res.status(500).json({ message: "Failed to send OTP. Check SMTP/API settings." });
    }

    console.log(`[RESET_OTP] Sent via ${sendResult.via} to ${normalizedEmail}`);
    return res.status(200).json({ message: "OTP sent. Check your email!" });
  } catch (error) {
    delete resetOtpCooldown[normalizedEmail];
    console.error("❌ Error sending reset OTP:", fullErr(error));
    return res.status(500).json({ message: "Failed to send OTP" });
  }
};

// ================================
// VERIFY RESET OTP
// ================================
exports.verifyResetOTP = async (req, res) => {
  const { email, otp } = req.body;
  const normalizedEmail = normEmail(email);
  if (!resetOtpStore[normalizedEmail] || resetOtpStore[normalizedEmail] !== otp) {
    return res.status(400).json({ message: "Invalid OTP" });
  }
  delete resetOtpStore[normalizedEmail];
  return res.status(200).json({ message: "OTP verified! You can now reset your password." });
};

// ================================
// RESET PASSWORD
// ================================
exports.resetPassword = async (req, res) => {
  const { email, newPassword } = req.body;
  try {
    const user = await User.findOne({ email: normEmail(email) });
    if (!user) {
      return res.status(400).json({ message: "User not found!" });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    return res.status(200).json({ message: "Password reset successfully! You can now log in." });
  } catch (error) {
    console.error("❌ Error resetting password:", fullErr(error));
    return res.status(500).json({ message: "Password reset failed." });
  }
};

// ================================
// REFRESH TOKEN Endpoint
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
      { expiresIn: "1h" }
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
    return res.status(200).json({ message: "Access token refreshed" });
  } catch (error) {
    console.error("Refresh token error:", fullErr(error));
    return res.status(401).json({ message: "Invalid refresh token" });
  }
};
