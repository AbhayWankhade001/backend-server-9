import express from "express";
import { loginUser, verifyToken } from "../middleware/auth.js";

const router2 = express.Router();

// Login endpoint
router2.post("/login2", async (req, res) => {
  try {
    await loginUser(req, res);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Protected endpoint
router2.get("/protected", verifyToken, (req, res) => {
  // req.user and req.token are added by verifyToken middleware
  res.json({ message: "Hello, " + req.user.name });
});

export default router2;