// middleware/authMiddleware.js
const jwt = require("jsonwebtoken");

// List the endpoints that do NOT require a token
const publicPaths = [
  "/auth/login",
  "/auth/send-otp",
  "/auth/verify-register",
  "/auth/verify-admin-otp",
  "/auth/refresh-token",
  "/auth/check-username",
  "/auth/check-email",
  "/auth/send-reset-otp",
  "/auth/verify-reset-otp",
  "/auth/reset-password"
];

module.exports = function (req, res, next) {
  if (publicPaths.some(path => req.originalUrl.startsWith(path))) {
    return next();
  }

  // Determine which cookie name to check based on the route prefix.
  let cookieName = "token"; // default fallback
  if (req.originalUrl.startsWith("/customer")) {
    cookieName = "customer_token";
  } else if (req.originalUrl.startsWith("/hr")) {
    cookieName = "hr_token";
  } else if (req.originalUrl.startsWith("/doctor")) {
    cookieName = "doctor_token";
  } else if (req.originalUrl.startsWith("/admin") || req.originalUrl.startsWith("/settings")) {
    cookieName = "admin_token";
  }

  // Retrieve the token from cookie or Authorization header
  const token =
    req.cookies[cookieName] ||
    (req.headers.authorization && req.headers.authorization.split(" ")[1]);

  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Token verification failed:", error);
    if (error.name === "TokenExpiredError") {
      res.clearCookie(cookieName);
      return res.status(401).json({
        message: "Token expired. Please log in again or refresh your token.",
      });
    }
    return res.status(401).json({ message: "Unauthorized: Invalid token" });
  }
};