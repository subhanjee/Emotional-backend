const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/fyp_depression";
const DB_JSON_PATH = path.join(__dirname, "db.json");

const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true, lowercase: true, trim: true },
    passwordHash: String,
    role: { type: String, enum: ["student", "admin"], default: "student" },
    createdAt: Date,
  },
  { versionKey: false }
);

const assessmentSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    responses: [Number],
    emotionalText: String,
    structuredScore: Number,
    textBoost: Number,
    finalScore: Number,
    severity: String,
    confidence: Number,
    keywordHighlights: [String],
    riskSignals: [String],
    riskFlag: Boolean,
    supportMessage: String,
    createdAt: Date,
  },
  { versionKey: false }
);

const User = mongoose.model("User", userSchema);
const Assessment = mongoose.model("Assessment", assessmentSchema);

async function migrate() {
  if (!fs.existsSync(DB_JSON_PATH)) {
    console.log("No db.json found. Nothing to migrate.");
    return;
  }

  const json = JSON.parse(fs.readFileSync(DB_JSON_PATH, "utf-8"));
  const users = Array.isArray(json.users) ? json.users : [];
  const assessments = Array.isArray(json.assessments) ? json.assessments : [];
  const idMap = new Map();

  for (const sourceUser of users) {
    const normalizedEmail = String(sourceUser.email || "").toLowerCase().trim();
    if (!normalizedEmail) continue;

    const role = sourceUser.role === "admin" ? "admin" : "student";
    const passwordHash =
      sourceUser.passwordHash ||
      (await bcrypt.hash(process.env.ADMIN_PASSWORD || "Admin@12345", 10));

    const upserted = await User.findOneAndUpdate(
      { email: normalizedEmail },
      {
        name: sourceUser.name || "Unnamed User",
        email: normalizedEmail,
        passwordHash,
        role,
        createdAt: sourceUser.createdAt ? new Date(sourceUser.createdAt) : new Date(),
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    idMap.set(sourceUser.id, upserted._id);
  }

  for (const sourceAssessment of assessments) {
    const mappedUserId = idMap.get(sourceAssessment.userId);
    if (!mappedUserId) continue;

    const exists = await Assessment.findOne({
      userId: mappedUserId,
      createdAt: sourceAssessment.createdAt ? new Date(sourceAssessment.createdAt) : undefined,
      finalScore: sourceAssessment.finalScore,
      emotionalText: sourceAssessment.emotionalText,
    });
    if (exists) continue;

    await Assessment.create({
      userId: mappedUserId,
      responses: sourceAssessment.responses || [],
      emotionalText: sourceAssessment.emotionalText || "",
      structuredScore: sourceAssessment.structuredScore ?? 0,
      textBoost: sourceAssessment.textBoost ?? 0,
      finalScore: sourceAssessment.finalScore ?? 0,
      severity: sourceAssessment.severity || "Minimal",
      confidence: sourceAssessment.confidence ?? 65,
      keywordHighlights: sourceAssessment.keywordHighlights || [],
      riskSignals: sourceAssessment.riskSignals || [],
      riskFlag: Boolean(sourceAssessment.riskFlag),
      supportMessage:
        sourceAssessment.supportMessage || "No acute high-risk phrases detected in this response.",
      createdAt: sourceAssessment.createdAt ? new Date(sourceAssessment.createdAt) : new Date(),
    });
  }

  console.log(`Migrated users: ${users.length}, assessments: ${assessments.length}`);
}

(async () => {
  try {
    await mongoose.connect(MONGO_URI);
    await migrate();
    await mongoose.disconnect();
    console.log("Migration complete.");
  } catch (error) {
    console.error("Migration failed:", error.message);
    process.exit(1);
  }
})();
