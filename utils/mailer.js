// utils/mailer.js
const nodemailer = require("nodemailer");
const axios = require("axios");

const isProd = process.env.NODE_ENV === "production";
const useAPI = process.env.MAIL_TRANSPORT === "api" || isProd; // prefer API in prod

// Local SMTP (works on your laptop)
const smtpTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp-relay.brevo.com",
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: { user: process.env.SMTP_EMAIL, pass: process.env.SMTP_PASS },
  connectionTimeout: 10_000,
  socketTimeout: 10_000,
});

async function sendViaAPI({ to, subject, text, html }) {
  const payload = {
    sender: { email: process.env.SENDER_EMAIL, name: process.env.SENDER_NAME || "SmartVet" },
    to: [{ email: to }],
    subject,
    textContent: text,
    htmlContent: html || undefined,
  };
  await axios.post("https://api.brevo.com/v3/smtp/email", payload, {
    headers: {
      "api-key": process.env.BREVO_API_KEY,
      "content-type": "application/json",
      accept: "application/json",
    },
    timeout: 12_000,
  });
}

async function sendMail({ to, subject, text, html }) {
  if (useAPI) return sendViaAPI({ to, subject, text, html });
  return smtpTransporter.sendMail({
    from: `"${process.env.SENDER_NAME || "SmartVet"}" <${process.env.SENDER_EMAIL}>`,
    to, subject, text, html,
  });
}

module.exports = { sendMail };
