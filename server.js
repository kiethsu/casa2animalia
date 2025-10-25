// server.js
require("dotenv").config();

const express       = require("express");
const mongoose      = require("mongoose");
const bodyParser    = require("body-parser");
const cors          = require("cors");
const cookieParser  = require("cookie-parser");
const path          = require("path");
const cron          = require("node-cron");
const session       = require("express-session");
const flash         = require("connect-flash");
const axios         = require("axios");          // SMS API
const nodemailer    = require("nodemailer");     // Email
const chatbotRoutes = require("./routes/chatbot");

// ★ HTTP + Socket.IO
const http    = require("http");
const { Server } = require("socket.io");

// Routes & middleware
const authRoutes      = require("./routes/authRoutes");
const adminRoutes     = require("./routes/adminRoutes");
const doctorRoutes    = require("./routes/doctorRoutes");
const hrRoutes        = require("./routes/hrRoutes");
const customerRoutes  = require("./routes/customerRoutes");
const authMiddleware  = require("./middleware/authMiddleware");
const settingRoutes   = require("./routes/settingRoutes");
const adminReservationRoutes = require('./routes/adminReservationRoutes');
// Models
const About           = require("./models/about");
const User            = require("./models/user");
const Reservation     = require("./models/reservation");
const ReservationMessage = require("./models/ReservationMessage"); // used by socket responder
const viewAsHr = require("./middleware/viewAsHr");
const app = express();

/* =========================
   Core middleware
   ========================= */
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || "a very secret key",
  resave: false,
  saveUninitialized: false,
});
app.use(sessionMiddleware);
app.use(flash());

// CORS (HTTP)
app.use(
  cors({
    origin: true,            // TIP: restrict to your front-end origin(s) in prod
    credentials: true,
  })
);

app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

// Views
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/* =========================
   Mongo
   ========================= */
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.connection.on("connected",   () => console.log("✅ MongoDB connected"));
mongoose.connection.on("error",       (err) => console.error("❌ MongoDB error:", err));
mongoose.connection.on("disconnected",() => console.warn("⚠️ MongoDB disconnected"));

/* =========================
   Static & cache rules
   ========================= */
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

app.use((req, res, next) => {
  if (/^\/(customer|doctor|hr|admin)/.test(req.path) || req.path.endsWith("-dashboard")) {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
  }
  next();
});

/* =========================
   Public landing + auth
   ========================= */
app.use("/", authRoutes);
app.get("/", async (_req, res) => {
  try {
    const aboutContent = await About.findOne();
    res.render("landing", { about: aboutContent });
  } catch (error) {
    console.error("Error loading landing page:", error);
    res.render("landing", { about: null });
  }
});

/* =========================
   HTTP server + Socket.IO
   ========================= */
const server = http.createServer(app);

const io = new Server(server, {
  transports: ["websocket", "polling"],
  cors: { origin: true, credentials: true }, // mirror HTTP CORS
});

// Share express-session with Socket.IO (if you need session inside socket handlers)
io.engine.use(sessionMiddleware);

// Make io available inside routes via req.app.get('io')
app.set("io", io);

// Socket handlers
io.on("connection", (socket) => {
  console.log("🔌 socket connected:", socket.id);

  // Join one or many rooms: { reservationId: "abc" } OR { reservationId: ["a","b"] }
  socket.on("join", ({ reservationId }) => {
    const ids = Array.isArray(reservationId) ? reservationId : [reservationId];
    ids
      .filter(Boolean)
      .map((id) => `reservation:${String(id)}`)
      .forEach((room) => {
        socket.join(room);
        console.log(`👥 ${socket.id} joined ${room}`);
      });
  });

  socket.on("leave", ({ reservationId }) => {
    const ids = Array.isArray(reservationId) ? reservationId : [reservationId];
    ids
      .filter(Boolean)
      .map((id) => `reservation:${String(id)}`)
      .forEach((room) => {
        socket.leave(room);
        console.log(`👋 ${socket.id} left ${room}`);
      });
  });

  // Customer clicks Confirm/Resched on Consult popup
  socket.on("reservation:respond", async ({ id, action }) => {
    try {
      const last = await ReservationMessage.findOne({ reservation: id }).sort({ createdAt: -1 });
      if (last) {
        last.status = "responded";
        last.response = action; // 'confirm' | 'resched'
        last.respondedBy = "customer";
        await last.save();
      }
      io.to(`reservation:${id}`).emit("reservation:response", { id, action });
      console.log(`📨 response broadcast to reservation:${id} ->`, action);
    } catch (e) {
      console.error("reservation:respond failed", e);
    }
  });

  socket.on("disconnect", (reason) => {
    console.log("❎ socket disconnected:", socket.id, reason);
  });
});

/* =========================
   Protected prefixes
   ========================= */
app.use(["/admin", "/doctor", "/hr", "/customer"], authMiddleware);

/* =========================
   Dashboards
   ========================= */
app.get("/customer-dashboard", authMiddleware, async (req, res) => {
  try {
    const userData   = await User.findById(req.user.userId);
    const username   = userData.username || userData.email;
    const profilePic = userData.profilePic || null;
    res.render("customer-dashboard", { username, profilePic });
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).send("Server error");
  }
});

app.get("/admin-dashboard",  authMiddleware, (_req, res) => res.render("admin-dashboard"));
app.get("/doctor-dashboard", authMiddleware, (req, res) => res.render("doctor-dashboard", { doctor: req.user }));
app.get("/hr-dashboard",     authMiddleware, async (req, res) => {
  try {
    const userData = await User.findById(req.user.userId);
    const username = userData.username || userData.email;
    res.render("hr-dashboard", { username });
  } catch (error) {
    console.error("Error fetching HR user data:", error);
    res.status(500).send("Server error");
  }
});

/* =========================
   Feature routes (order matters: io is set above)
   ========================= */
// AFTER (correct)
app.use(["/admin", "/doctor", "/hr", "/customer"], authMiddleware);

// mount the view-as middleware FIRST for /admin
app.use("/admin", viewAsHr);

// now all /admin routes can read req.viewAsHrId
app.use("/admin", adminRoutes);
app.use("/admin", doctorRoutes);
app.use("/admin", adminReservationRoutes);

// rest as-is
app.use("/doctor", doctorRoutes);
app.use("/hr", hrRoutes);
app.use("/customer", customerRoutes);
app.use("/settings", authMiddleware, settingRoutes);
app.use("/chatbot", chatbotRoutes);

/* =========================
   Cron jobs
   ========================= */
// Follow-Up reminders (every 2 hours at :00)
cron.schedule("0 */2 * * *", async () => {
  try {
    const now = new Date();
    console.log("Cron job triggered at:", now.toString());

    const today     = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const tomorrow  = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const endOfMonth   = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

    const reservations = await Reservation.find({
      status: "Done",
      "schedule.scheduleDate": { $gte: startOfMonth, $lte: endOfMonth },
    }).lean();

    for (const reservation of reservations) {
      const scheduleDate  = new Date(reservation.schedule.scheduleDate);
      const scheduledLocal= new Date(scheduleDate.getFullYear(), scheduleDate.getMonth(), scheduleDate.getDate());

      let notifType = "";
      if (scheduledLocal.getTime() === today.getTime())    notifType = "On Day";
      else if (scheduledLocal.getTime() === tomorrow.getTime()) notifType = "Near";
      if (!notifType) continue;

      const message = `Reminder (${notifType}): Your follow-up consultation is scheduled for ${scheduledLocal.toDateString()}. Details: ${reservation.schedule.scheduleDetails}`;
      const customer = await User.findById(reservation.owner);
      if (!customer) continue;

      if (customer.cellphone) {
        try {
          const smsResponse = await axios.post(
            "https://api.sendinblue.com/v3/transactionalSMS/sms",
            { sender: "SmartVet", recipient: customer.cellphone, content: message },
            { headers: { "api-key": process.env.BREVO_SMS_API_KEY, "Content-Type": "application/json" } }
          );
          console.log(`SMS sent to ${customer.cellphone}:`, smsResponse.data);
        } catch (smsError) {
          console.error(`SMS error for reservation ${reservation._id}:`, smsError.response ? smsError.response.data : smsError.message);
        }
      } else if (customer.email) {
        try {
          const transporter = nodemailer.createTransport({
            host: "smtp-relay.brevo.com",
            port: 587,
            secure: false,
            auth: { user: process.env.SMTP_EMAIL, pass: process.env.SMTP_PASS },
          });
          const mailOptions = {
            from: `"SmartVet Clinic" <dehe.marquez.au@phinmaed.com>`,
            to: customer.email,
            subject: "Follow-Up Consultation Reminder",
            text: message,
          };
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) console.error(`Email error for reservation ${reservation._id}:`, error);
            else console.log(`Email sent for reservation ${reservation._id}:`, info.response);
          });
        } catch (emailError) {
          console.error(`Email notification error for reservation ${reservation._id}:`, emailError);
        }
      }
    }
  } catch (error) {
    console.error("Cron job error:", error);
  }
});

// Clear canceled & stale approved (every minute)
cron.schedule("*/1 * * * *", async () => {
  try {
    const oneMinuteAgo = new Date(Date.now() - 1 * 60 * 1000);
    console.log("One minute ago:", oneMinuteAgo);

    const canceledResult = await Reservation.deleteMany({
      status: "Canceled",
      canceledAt: { $lte: oneMinuteAgo },
    });
    console.log(`Old canceled cleared: ${canceledResult.deletedCount}`);

    const staleApproved = await Reservation.find({
      status: "Approved",
      $or: [{ doctor: { $exists: false } }, { doctor: null }],
      createdAt: { $lte: oneMinuteAgo },
    });

    for (let res of staleApproved) {
      res.status = "Not Attended";
      res.canceledAt = new Date();
      await res.save();
    }
    console.log(`Stale approved marked Not Attended: ${staleApproved.length}`);
  } catch (error) {
    console.error("Error clearing old reservations:", error);
  }
});

/* =========================
   Logout
   ========================= */
app.get("/logout", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.clearCookie("doctor_token");
  res.clearCookie("customer_token");
  res.clearCookie("hr_token");
  res.clearCookie("admin_token");
  res.clearCookie("refreshToken");
  res.redirect("/");
});

/* =========================
   Health & error guards (optional)
   ========================= */
app.get("/_healthz", (_req, res) => res.status(200).send("ok"));

process.on("unhandledRejection", (err) => {
  console.error("UNHANDLED REJECTION:", err);
});
process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT EXCEPTION:", err);
});

/* =========================
   Start server (http + io)
   ========================= */
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server + Socket.IO running on port ${PORT}`));
