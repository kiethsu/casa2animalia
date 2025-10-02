// routes/chatbot.js
const express = require("express");
const router = express.Router();
const { getReply } = require("../chatbot");


router.post("/chat", async (req, res) => {
    const { message, sessionId } = req.body;
    if (!message || !sessionId) {
      return res.status(400).json({ error: "Missing message or sessionId" });
    }
    try {
      const reply = await getReply(message, sessionId);
      res.json({ reply });
    } catch (err) {
      console.error("Chatbot error:", err);
      res.status(500).json({ error: "Error processing your message" });
    }
  });
  
module.exports = router;