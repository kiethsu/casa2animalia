require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const path = require("path");
const cron = require('node-cron');
const session = require('express-session');
const flash   = require('connect-flash');
const axios = require('axios');         // For SMS API calls
const nodemailer = require('nodemailer'); // For sending emails
const chatbotRoutes = require("./routes/chatbot");

// Import routes and middleware
const authRoutes = require("./routes/authRoutes");
const adminRoutes = require("./routes/adminRoutes");
const doctorRoutes = require("./routes/doctorRoutes");
const hrRoutes = require("./routes/hrRoutes");
const customerRoutes = require("./routes/customerRoutes");
const authMiddleware = require("./middleware/authMiddleware");
const settingRoutes = require('./routes/settingRoutes');


// Import models
const About = require("./models/about");
const User = require("./models/user");
const Reservation = require("./models/reservation");

const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET || 'a very secret key',
  resave: false,
  saveUninitialized: false
}));
app.use(flash());


// Configure CORS for production (allowing all origins temporarily; update later with your client URL)
app.use(cors({
  origin: true,  // Allows all origins; change this to your client URL once available
  credentials: true,
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Set view engine and views folder
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Updated MongoDB connection with event listeners for debugging
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('✅ MongoDB connection established successfully');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.warn('⚠️ MongoDB disconnected');
});

// Serve static files (e.g., images in /public)
app.use(express.static(path.join(__dirname, "public")));
// make files in public/uploads downloadable via /uploads/...
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

// Do not cache any protected pages (prevents stale dashboards after logout)
app.use((req, res, next) => {
  if (/^\/(customer|doctor|hr|admin)/.test(req.path) || req.path.endsWith('-dashboard')) {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
  }
  next();
});

// Public landing page and auth endpoints
app.use("/", authRoutes); // login, registration, forgot password, etc.

app.get("/", async (req, res) => {
  try {
    const aboutContent = await About.findOne();
    res.render("landing", { about: aboutContent });
  } catch (error) {
    console.error("Error loading landing page:", error);
    res.render("landing", { about: null });
  }
});

// Protected Customer Dashboard route
app.get("/customer-dashboard", authMiddleware, async (req, res) => {
  try {
    const userData = await User.findById(req.user.userId);
    const username = userData.username || userData.email;
    const profilePic = userData.profilePic || null;
    res.render("customer-dashboard", { username, profilePic });
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).send("Server error");
  }
});

// Other routes
app.get("/admin-dashboard", (req, res) => res.render("admin-dashboard"));
app.use("/admin", adminRoutes);
app.get("/doctor-dashboard", authMiddleware, (req, res) => {
  res.render("doctor-dashboard", { doctor: req.user });
});
app.get("/hr-dashboard", authMiddleware, async (req, res) => {
  try {
    const userData = await User.findById(req.user.userId);
    const username = userData.username || userData.email;
    res.render("hr-dashboard", { username });
  } catch (error) {
    console.error("Error fetching HR user data:", error);
    res.status(500).send("Server error");
  }
});
app.use("/doctor", doctorRoutes);
app.use("/hr", hrRoutes);
app.use("/customer", customerRoutes);

// Settings routes (protected via authMiddleware)
app.use('/settings', settingRoutes);

// Daily Cron Job: Follow-Up Schedule Notifications (runs every 2 hours)
cron.schedule('0 */2 * * *', async () => {
  try {
    const now = new Date();
    console.log("Cron job triggered at:", now.toString());

    // Define today's and tomorrow's local dates (ignore time)
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const tomorrow = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);

    console.log("Today's date:", today.toDateString());
    console.log("Tomorrow's date:", tomorrow.toDateString());

    // Define the start and end of the current month.
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

    console.log("Checking for follow-up schedules in current month between:", startOfMonth.toISOString(), "and", endOfMonth.toISOString());

    // Query reservations with status 'Done' and with a follow-up schedule date in the current month.
    const reservations = await Reservation.find({
      status: 'Done',
      'schedule.scheduleDate': { $gte: startOfMonth, $lte: endOfMonth }
    }).lean();

    console.log(`Found ${reservations.length} reservations with follow-up schedules in the current month.`);

    // Process each reservation and decide notification type.
    for (const reservation of reservations) {
      // Convert the schedule date to a local date (discard time)
      const scheduleDate = new Date(reservation.schedule.scheduleDate);
      const scheduledLocal = new Date(scheduleDate.getFullYear(), scheduleDate.getMonth(), scheduleDate.getDate());
      console.log("Processing reservation:", reservation._id, "Scheduled on:", scheduledLocal.toDateString());

      let notifType = '';
      if (scheduledLocal.getTime() === today.getTime()) {
        notifType = "On Day";
      } else if (scheduledLocal.getTime() === tomorrow.getTime()) {
        notifType = "Near";
      }

      if (!notifType) {
        console.log("No notification needed for reservation:", reservation._id);
        continue;
      }

      const message = `Reminder (${notifType}): Your follow-up consultation is scheduled for ${scheduledLocal.toDateString()}. Details: ${reservation.schedule.scheduleDetails}`;
      
      const customer = await User.findById(reservation.owner);
      if (!customer) {
        console.log("No customer found for reservation:", reservation._id);
        continue;
      }

      // Attempt to send SMS if a cellphone exists
      if (customer.cellphone) {
        console.log(`Attempting to send SMS to: ${customer.cellphone} for reservation ${reservation._id}`);
        try {
          const smsResponse = await axios.post(
            'https://api.sendinblue.com/v3/transactionalSMS/sms',
            {
              sender: "SmartVet", // Must be a validated sender ID in Brevo.
              recipient: customer.cellphone,
              content: message
            },
            {
              headers: {
                'api-key': process.env.BREVO_SMS_API_KEY,
                'Content-Type': 'application/json'
              }
            }
          );
          console.log(`SMS sent to ${customer.cellphone} for reservation ${reservation._id}:`, smsResponse.data);
        } catch (smsError) {
          console.error(`Error sending SMS for reservation ${reservation._id}:`, smsError.response ? smsError.response.data : smsError.message);
        }
      } else if (customer.email) {
        console.log(`No cellphone provided, sending email to: ${customer.email} for reservation ${reservation._id}`);
        try {
          const transporter = nodemailer.createTransport({
            host: "smtp-relay.brevo.com",
            port: 587,
            secure: false,
            auth: {
              user: process.env.SMTP_EMAIL,
              pass: process.env.SMTP_PASS
            }
          });
          const mailOptions = {
            from: `"SmartVet Clinic" <dehe.marquez.au@phinmaed.com>`,
            to: customer.email,
            subject: "Follow-Up Consultation Reminder",
            text: message
          };
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error(`Error sending email for reservation ${reservation._id}:`, error);
            } else {
              console.log(`Email sent for reservation ${reservation._id}:`, info.response);
            }
          });
        } catch (emailError) {
          console.error(`Error in email notification for reservation ${reservation._id}:`, emailError);
        }
      }
    }
  } catch (error) {
    console.error("Error in follow-up schedule notification cron job:", error);
  }
});

// Cron Job: Clear canceled and unassigned approved reservations older than 1 minute (runs every minute)
cron.schedule('*/1 * * * *', async () => {
  try {
    const oneMinuteAgo = new Date(Date.now() - 1 * 60 * 1000);
    console.log("One minute ago:", oneMinuteAgo);

    // Delete canceled reservations older than 1 minute.
    const canceledResult = await Reservation.deleteMany({
      status: 'Canceled',
      canceledAt: { $lte: oneMinuteAgo }
    });
    console.log(`Old canceled reservations cleared: ${canceledResult.deletedCount} removed.`);

     // MARK stale approved (no doctor) after 1 minute as Not Attended
    const staleApproved = await Reservation.find({
      status: 'Approved',
      $or: [{ doctor: { $exists: false } }, { doctor: null }],
      createdAt: { $lte: oneMinuteAgo }
    });
    for (let res of staleApproved) {
      res.status     = 'Not Attended';
      res.canceledAt = new Date();           // optional timestamp
      await res.save();
   }
   console.log(`Stale approved without doctor: ${staleApproved.length} marked as Not Attended.`);
     
   } catch (error) {
     console.error("Error clearing old reservations:", error);
   }
 });
// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

// Additional routes and middleware
app.use("/chatbot", chatbotRoutes);
app.get('/logout', (req, res) => {
  res.set('Cache-Control', 'no-store'); // don't cache the redirect page
  res.clearCookie('doctor_token');
  res.clearCookie('customer_token');
  res.clearCookie('hr_token');
  res.clearCookie('admin_token');
  res.clearCookie('refreshToken');
  res.redirect('/');
});


