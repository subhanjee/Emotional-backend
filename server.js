const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomUUID } = require("crypto");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-secret-change-in-production";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@example.com").toLowerCase().trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin@12345";
const DB_PATH = path.join(__dirname, "db.json");

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

function ensureDb() {
  if (!fs.existsSync(DB_PATH)) {
    const initial = { users: [], assessments: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2), "utf-8");
  }
}

function readDb() {
  ensureDb();
  const raw = fs.readFileSync(DB_PATH, "utf-8");
  return JSON.parse(raw);
}

function writeDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), "utf-8");
}

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

function adminOnly(req, res, next) {
  const db = readDb();
  const currentUser = db.users.find((user) => user.id === req.userId);
  if (!currentUser) {
    return res.status(404).json({ message: "User not found." });
  }
  if (currentUser.role !== "admin") {
    return res.status(403).json({ message: "Admin access required." });
  }
  req.currentUser = currentUser;
  next();
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

async function ensureAdminAndRoles() {
  const db = readDb();
  let changed = false;

  db.users = db.users.map((user) => {
    const role = user.role || (user.email === ADMIN_EMAIL ? "admin" : "student");
    if (!user.role) changed = true;
    return { ...user, role };
  });

  const existingAdmin = db.users.find((user) => user.email === ADMIN_EMAIL);
  if (!existingAdmin) {
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    db.users.push({
      id: randomUUID(),
      name: "System Admin",
      email: ADMIN_EMAIL,
      passwordHash,
      role: "admin",
      createdAt: new Date().toISOString(),
    });
    changed = true;
  }

  if (changed) {
    writeDb(db);
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

    const db = readDb();

    if (db.users.some((u) => u.email === normalizedEmail)) {
      return res.status(409).json({ message: "User already exists with this email." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = {
      id: randomUUID(),
      name: String(name).trim(),
      email: normalizedEmail,
      passwordHash,
      role: "student",
      createdAt: new Date().toISOString(),
    };

    db.users.push(user);
    writeDb(db);

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.status(201).json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
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

    const db = readDb();
    const normalizedEmail = String(email).toLowerCase().trim();
    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: "Please provide a valid email address." });
    }
    const user = db.users.find((u) => u.email === normalizedEmail);

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role || "student" },
    });
  } catch (error) {
    res.status(500).json({ message: "Server error during login." });
  }
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  const db = readDb();
  const user = db.users.find((u) => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ message: "User not found." });
  }
  res.json({ id: user.id, name: user.name, email: user.email, role: user.role || "student" });
});

app.post("/api/assessments", authMiddleware, (req, res) => {
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

  const db = readDb();
  const assessment = {
    id: randomUUID(),
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
    createdAt: new Date().toISOString(),
  };

  db.assessments.push(assessment);
  writeDb(db);

  res.status(201).json({ message: "Assessment submitted successfully. Results are visible to admin only." });
});

app.get("/api/assessments/history", authMiddleware, (req, res) => {
  return res.status(403).json({ message: "Results are visible to admin only." });
});

app.get("/api/admin/assessments", authMiddleware, adminOnly, (req, res) => {
  const db = readDb();
  const history = db.assessments
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const usersById = Object.fromEntries(
    db.users.map((user) => [user.id, { id: user.id, name: user.name, email: user.email }])
  );
  const enriched = history.map((entry) => ({
    ...entry,
    student: usersById[entry.userId] || null,
  }));
  res.json(enriched);
});

app.listen(PORT, async () => {
  ensureDb();
  await ensureAdminAndRoles();
  if (!process.env.JWT_SECRET) {
    console.warn("Warning: JWT_SECRET is not set. Using fallback development secret.");
  }
  if (!process.env.ADMIN_PASSWORD) {
    console.warn("Warning: ADMIN_PASSWORD is not set. Using default admin password.");
  }
  console.log(`API running on http://localhost:${PORT}`);
});
