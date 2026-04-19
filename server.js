const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-secret-change-in-production";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@example.com").toLowerCase().trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin@12345";
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/fyp_depression";

app.use(cors({ origin: FRONTEND_ORIGIN, credentials: false }));
app.use(express.json());

const QUESTIONS = [
  "I had little motivation to study or attend classes even when I knew it was important.",
  "I felt overwhelmed by my academic workload or assignments.",
  "I worried a lot about my future career or what will happen after graduation.",
  "I felt disconnected or lonely even when I was around friends or classmates.",
  "I had trouble concentrating on lectures, readings, or studying for more than a short time.",
  "I felt like I was not as good as other students or that I was falling behind.",
  "I lost interest in hobbies, sports, or activities that I used to enjoy.",
  "I felt tired or had low energy most of the day, even after sleeping.",
  "I had negative thoughts about myself (e.g., 'I am not smart enough' or 'I cannot do this').",
  "I felt hopeless about improving my situation or achieving my goals.",
];

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ["student", "admin"], default: "student" },
  },
  { timestamps: { createdAt: "createdAt", updatedAt: false } }
);

const assessmentSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    responses: {
      type: [Number],
      required: true,
      validate: (val) => Array.isArray(val) && val.length === QUESTIONS.length,
    },
    emotionalText: { type: String, required: true, trim: true },
    structuredScore: { type: Number, required: true },
    textBoost: { type: Number, required: true },
    finalScore: { type: Number, required: true },
    severity: { type: String, required: true },
    confidence: { type: Number, required: true },
    keywordHighlights: { type: [String], default: [] },
    riskSignals: { type: [String], default: [] },
    riskFlag: { type: Boolean, default: false },
    supportMessage: { type: String, required: true },
  },
  { timestamps: { createdAt: "createdAt", updatedAt: false } }
);

const User = mongoose.model("User", userSchema);
const Assessment = mongoose.model("Assessment", assessmentSchema);

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: "Missing token" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

async function adminOnly(req, res, next) {
  try {
    const currentUser = await User.findById(req.userId).lean();
    if (!currentUser) {
      return res.status(404).json({ message: "User not found." });
    }
    if (currentUser.role !== "admin") {
      return res.status(403).json({ message: "Admin access required." });
    }
    req.currentUser = currentUser;
    next();
  } catch (error) {
    return res.status(500).json({ message: "Server error." });
  }
}

function classifySeverity(score) {
  if (score <= 9) return "Minimal";
  if (score <= 14) return "Mild";
  if (score <= 21) return "Moderate";
  return "Severe";
}

function detectKeywords(text) {
  const terms = [
    "hopeless",
    "tired",
    "overwhelmed",
    "lonely",
    "anxious",
    "worthless",
    "stressed",
    "sad",
  ];
  const lower = text.toLowerCase();
  return terms.filter((term) => lower.includes(term));
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongPassword(password) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(password);
}

function detectRiskSignals(text) {
  const highRiskTerms = [
    "suicide",
    "self harm",
    "kill myself",
    "end my life",
    "no reason to live",
    "want to die",
  ];
  const lower = text.toLowerCase();
  return highRiskTerms.filter((term) => lower.includes(term));
}

async function ensureAdminUser() {
  const existingAdmin = await User.findOne({ email: ADMIN_EMAIL });
  if (!existingAdmin) {
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await User.create({
      name: "System Admin",
      email: ADMIN_EMAIL,
      passwordHash,
      role: "admin",
    });
    return;
  }

  if (existingAdmin.role !== "admin") {
    existingAdmin.role = "admin";
    await existingAdmin.save();
  }
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email, and password are required." });
    }
    const normalizedEmail = String(email).toLowerCase().trim();
    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: "Please provide a valid email address." });
    }
    if (!isStrongPassword(password)) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters and include uppercase, lowercase, and a number.",
      });
    }

    const existing = await User.findOne({ email: normalizedEmail }).lean();
    if (existing) {
      return res.status(409).json({ message: "User already exists with this email." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      name: String(name).trim(),
      email: normalizedEmail,
      passwordHash,
      role: "student",
    });

    const token = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { expiresIn: "7d" });
    res.status(201).json({
      token,
      user: { id: user._id.toString(), name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    res.status(500).json({ message: "Server error during registration." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    const normalizedEmail = String(email).toLowerCase().trim();
    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: "Please provide a valid email address." });
    }
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const token = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { expiresIn: "7d" });
    res.json({
      token,
      user: { id: user._id.toString(), name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    res.status(500).json({ message: "Server error during login." });
  }
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  User.findById(req.userId)
    .lean()
    .then((user) => {
      if (!user) return res.status(404).json({ message: "User not found." });
      return res.json({
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role || "student",
      });
    })
    .catch(() => res.status(500).json({ message: "Server error." }));
});

app.post("/api/assessments", authMiddleware, async (req, res) => {
  const { responses, emotionalText } = req.body;
  if (!Array.isArray(responses) || responses.length !== QUESTIONS.length) {
    return res.status(400).json({ message: `Exactly ${QUESTIONS.length} responses are required.` });
  }

  const validResponses = responses.every(
    (value) => Number.isInteger(value) && value >= 0 && value <= 3
  );
  if (!validResponses) {
    return res.status(400).json({ message: "Responses must be integers between 0 and 3." });
  }

  if (!emotionalText || String(emotionalText).trim().length < 30) {
    return res
      .status(400)
      .json({ message: "Please write at least 30 characters in emotional text." });
  }

  const structuredScore = responses.reduce((acc, current) => acc + current, 0);
  const normalizedText = String(emotionalText).trim();
  const keywords = detectKeywords(normalizedText);
  const riskSignals = detectRiskSignals(normalizedText);
  const textBoost = Math.min(3, keywords.length);
  const finalScore = Math.min(30, structuredScore + textBoost);
  const severity = classifySeverity(finalScore);
  const confidence = Math.min(97, 65 + Math.round((finalScore / 30) * 32));
  const riskFlag = severity === "Severe" || riskSignals.length > 0;
  const supportMessage = riskFlag
    ? "Your response suggests elevated distress. Please contact a trusted person or counselor immediately."
    : "No acute high-risk phrases detected in this response.";

  try {
    await Assessment.create({
      userId: req.userId,
      responses,
      emotionalText: normalizedText,
      structuredScore,
      textBoost,
      finalScore,
      severity,
      confidence,
      keywordHighlights: keywords,
      riskSignals,
      riskFlag,
      supportMessage,
    });

    res
      .status(201)
      .json({ message: "Assessment submitted successfully. Results are visible to admin only." });
  } catch (error) {
    res.status(500).json({ message: "Server error during assessment submission." });
  }
});

app.get("/api/assessments/history", authMiddleware, (req, res) => {
  return res.status(403).json({ message: "Results are visible to admin only." });
});

app.get("/api/admin/assessments", authMiddleware, adminOnly, (req, res) => {
  Assessment.find({})
    .sort({ createdAt: -1 })
    .populate("userId", "name email")
    .lean()
    .then((history) => {
      const enriched = history.map((entry) => ({
        id: entry._id.toString(),
        userId: entry.userId?._id?.toString?.() || "",
        responses: entry.responses,
        emotionalText: entry.emotionalText,
        structuredScore: entry.structuredScore,
        textBoost: entry.textBoost,
        finalScore: entry.finalScore,
        severity: entry.severity,
        confidence: entry.confidence,
        keywordHighlights: entry.keywordHighlights,
        riskSignals: entry.riskSignals,
        riskFlag: entry.riskFlag,
        supportMessage: entry.supportMessage,
        createdAt: entry.createdAt,
        student: entry.userId
          ? {
              id: entry.userId._id.toString(),
              name: entry.userId.name,
              email: entry.userId.email,
            }
          : null,
      }));
      return res.json(enriched);
    })
    .catch(() => res.status(500).json({ message: "Server error." }));
});

async function startServer() {
  try {
    await mongoose.connect(MONGO_URI);
    await ensureAdminUser();
    if (!process.env.JWT_SECRET) {
      console.warn("Warning: JWT_SECRET is not set. Using fallback development secret.");
    }
    if (!process.env.ADMIN_PASSWORD) {
      console.warn("Warning: ADMIN_PASSWORD is not set. Using default admin password.");
    }
    console.log("MongoDB connected.");
    app.listen(PORT, () => {
      console.log(`API running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error.message);
    process.exit(1);
  }
}

startServer();
