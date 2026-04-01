import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';
import Stripe from 'stripe';
import path from 'path';
import { fileURLToPath } from 'url';
import { OAuth2Client } from 'google-auth-library';
import multer from 'multer';
import fs from 'fs';
import crypto from 'crypto';
import { Builder, Parser } from 'xml2js';
import forge from 'node-forge';
import PDFDocument from 'pdfkit';
import { createEmailNotifications } from './emailNotifications.js';
import {
  createSmartbillInvoiceFlow,
  isSmartbillConfigured,
  normalizeBillingTaxCode,
} from './services/smartbillService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3005; 

// --- CONFIGURARE PRODUCȚIE VS DEV ---
const MONGO_URI = process.env.MONGO_URI || '';
const JWT_SECRET = process.env.JWT_SECRET || 'secret-cheie-securizata-schimba-in-prod'; 
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || ''; 
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || ''; 
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3005';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM = process.env.RESEND_FROM || 'ESA Notify <support@event-smart-assistant.com>';
const EMAIL_OTP_TTL_MINUTES = Number(process.env.EMAIL_OTP_TTL_MINUTES || 10);
const EMAIL_OTP_COOLDOWN_SECONDS = Number(process.env.EMAIL_OTP_COOLDOWN_SECONDS || 60);
const EMAIL_OTP_MAX_ATTEMPTS = Number(process.env.EMAIL_OTP_MAX_ATTEMPTS || 5);
const PASSWORD_RESET_OTP_TTL_MINUTES = Number(process.env.PASSWORD_RESET_OTP_TTL_MINUTES || EMAIL_OTP_TTL_MINUTES);
const PASSWORD_RESET_OTP_COOLDOWN_SECONDS = Number(process.env.PASSWORD_RESET_OTP_COOLDOWN_SECONDS || EMAIL_OTP_COOLDOWN_SECONDS);
const PASSWORD_RESET_OTP_MAX_ATTEMPTS = Number(process.env.PASSWORD_RESET_OTP_MAX_ATTEMPTS || EMAIL_OTP_MAX_ATTEMPTS);
const EMAIL_WELCOME_ENABLED = process.env.EMAIL_WELCOME_ENABLED !== 'false';
const EMAIL_LOGIN_ALERT_ENABLED = process.env.EMAIL_LOGIN_ALERT_ENABLED !== 'false';
const EMAIL_LOGIN_ALERT_COOLDOWN_MINUTES = Number(process.env.EMAIL_LOGIN_ALERT_COOLDOWN_MINUTES || 180);
const EMAIL_LOGIN_ALERT_SKIP_NEW_ACCOUNT_MINUTES = Number(process.env.EMAIL_LOGIN_ALERT_SKIP_NEW_ACCOUNT_MINUTES || 180);
const STRIPE_SMARTBILL_DEBUG =
  process.env.STRIPE_SMARTBILL_DEBUG === 'true' || process.env.SMARTBILL_DEBUG === 'true';

// --- NETOPIA ---
const NETOPIA_SIGNATURE = process.env.NETOPIA_SIGNATURE || '';
const NETOPIA_SANDBOX   = process.env.NETOPIA_SANDBOX !== 'false'; // true by default
const APP_URL = (process.env.APP_URL || CLIENT_URL).replace(/\/$/, '');

// --- IMPORTANT: Pune acelasi ID aici pentru verificare (deși e opțional dacă folosești doar token decoder simplu, e recomandat pentru securitate) ---
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '780198284819-p7hf7nqagkhbe6ikp5r4t46kkaktqumc.apps.googleusercontent.com';

const stripe = new Stripe(STRIPE_SECRET_KEY);
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const emailNotifications = createEmailNotifications({
  apiKey: RESEND_API_KEY,
  from: RESEND_FROM,
  appName: 'WeddingPro',
  clientUrl: CLIENT_URL,
  logger: console,
});
app.use(helmet({ contentSecurityPolicy: false }));
// --- SECURITY MIDDLEWARE ---
// app.use(
//   helmet({
//     contentSecurityPolicy: {
//       directives: {
//         defaultSrc: ["'self'"],
//         scriptSrc: [
//           "'self'",
//           "'unsafe-inline'",
//           "'unsafe-eval'",
//           "https://esm.sh",
//           "https://accounts.google.com"
//         ],
//         styleSrc: [
//           "'self'",
//           "'unsafe-inline'",
//           "https://fonts.googleapis.com",
//           "https://accounts.google.com"
//         ],
//         fontSrc: [
//           "'self'",
//           "https://fonts.gstatic.com",
//           "https://cdnjs.cloudflare.com"
//         ],
//         imgSrc: ["'self'", "data:", "https://*", "https://lh3.googleusercontent.com"],
//         connectSrc: ["'self'", "https://*", "https://accounts.google.com"],
//         frameSrc: ["'self'", "https://accounts.google.com"],

//         formAction: [
//           "'self'",
//           "https://sandboxsecure.mobilpay.ro",
//           "https://secure.mobilpay.ro"
//         ]
//       }
//     }
//   })
// );

const normalizeOrigin = (value = '') => String(value || '').trim().replace(/\/$/, '');
const localhostOriginRegex = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i;

const allowedCorsOrigins = new Set([
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:5173',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:3001',
    'http://127.0.0.1:5173',
    'http://192.168.68.105:3000',
    'https://handmade-suggest-troops-handmade.trycloudflare.com',
    'https://event-smart-assistant.com',
    'https://www.event-smart-assistant.com',
].map(normalizeOrigin));

// Suportă un singur URL sau listă separată prin virgulă în CLIENT_URL
if (process.env.CLIENT_URL) {
    String(process.env.CLIENT_URL)
        .split(',')
        .map((raw) => normalizeOrigin(raw))
        .filter(Boolean)
        .forEach((origin) => allowedCorsOrigins.add(origin));
}

app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin) return callback(null, true); // server-to-server, curl, webhooks
            const normalizedOrigin = normalizeOrigin(origin);
            if (
                localhostOriginRegex.test(normalizedOrigin) ||
                allowedCorsOrigins.has(normalizedOrigin)
            ) {
                return callback(null, true);
            }
            return callback(new Error(`Not allowed by CORS: ${origin}`));
        },
        methods: ['GET', 'POST', 'DELETE', 'PUT'],
        credentials: true,
    })
);

// --- SCHEMAS ---
const SystemConfigSchema = new mongoose.Schema({
    key: { type: String, default: 'global_config', unique: true },
    invoiceCounter: { type: Number, default: 0 },
    limits: {
        free: {
            maxGuests: { type: Number, default: 1 },
            maxElements: { type: Number, default: 5 },
            maxCustomTasks: { type: Number, default: 3 },
            maxBudgetItems: { type: Number, default: 6 },
            maxCalculatorBudget: { type: Number, default: 500 }
        },
        basic: {
            maxGuests: { type: Number, default: 9999 },
            maxElements: { type: Number, default: 0 },
            maxCustomTasks: { type: Number, default: 0 },
            maxBudgetItems: { type: Number, default: 0 },
            maxCalculatorBudget: { type: Number, default: 0 }
        },
        premium: {
            maxGuests: { type: Number, default: 9999 },
            maxElements: { type: Number, default: 9999 },
            maxCustomTasks: { type: Number, default: 9999 },
            maxBudgetItems: { type: Number, default: 9999 },
            maxCalculatorBudget: { type: Number, default: 999999999 }
        }
    },
    pricing: {
        basicPrice: { type: Number, default: 1900 },
        premiumPrice: { type: Number, default: 4900 },
        oldPrice: { type: Number, default: 10000 },
        currency: { type: String, default: 'ron' }
    },
    servicesComingSoon: { type: Boolean, default: false }
});


// ── Template Defaults — setari globale per template (admin) ──────────────
const TemplateDefaultsSchema = new mongoose.Schema({
    templateId: { type: String, required: true, unique: true },
    colorTheme:             { type: String, default: 'default' },
    heroBgImage:            { type: String, default: null },
    heroBgImageMobile:      { type: String, default: null },
    heroContentImage:       { type: String, default: null },
    heroContentImageMobile: { type: String, default: null },
    castleIntroWelcome:     { type: String, default: 'WELCOME' },
    castleIntroSubtitle:    { type: String, default: 'into my little kingdom' },
    castleInviteTop:        { type: String, default: 'Cu multa bucurie va anuntam' },
    jungleHeaderText:       { type: String, default: 'Save The Date' },
    jungleOverlayText:      { type: String, default: 'Cu bucurie va invitam sa fiti parte din povestea noastra.' },
    jungleFooterText:       { type: String, default: '' },
    jungleIntroStyle:       { type: String, default: 'dissolve' },
    castleInviteMiddle:     { type: String, default: '' },
    castleInviteBottom:     { type: String, default: 'va fii botezata' },
    castleInviteTag:        { type: String, default: 'deschide portile' },
    videoUrl:               { type: String, default: null },
    introVariants:          { type: Object, default: {} },   // { [id]: { label, desktop, mobile } }
    defaultIntroVariant:    { type: String, default: null },
    updatedAt:              { type: Date, default: Date.now },
}, { strict: false });
const TemplateDefaults = mongoose.model('TemplateDefaults', TemplateDefaultsSchema);

const PaymentSchema = new mongoose.Schema({
    date: { type: Date, default: Date.now },
    amount: Number,
    invoiceId: String,      // ORD_... (referință internă)
    invoiceNumber: String,  // FACT-2026-0001 (număr fiscal)
    billingEmail: String,
    invoicePdfUrl: String,
    hostedInvoiceUrl: String,
    paymentMethod: String,
    planTarget: { type: String, enum: ['free', 'basic', 'premium'], default: 'premium' },
    status: { type: String, default: 'Paid' },
    relatedEventDate: Date,
    relatedEventName: String,
    billingFirstName: String,
    billingLastName: String,
    billingAddress: String,
    billingCity: String,
    billingSector: String,
    billingCounty: String,
    billingCountry: String,
    checkoutAddressSource: String,
    checkoutFirstName: String,
    checkoutLastName: String,
    checkoutPhone: String,
    checkoutEmail: String,
    checkoutCounty: String,
    checkoutCity: String,
    checkoutStreet: String,
    checkoutNumber: String,
    checkoutBlock: String,
    checkoutStaircase: String,
    checkoutFloor: String,
    checkoutApartment: String,
    checkoutPostalCode: String,
    checkoutLandmark: String,
    checkoutCountry: String,
    savedAddressSnapshot: Object,
    checkoutAddressSnapshot: Object,
});

const ArchivedSnapshotSchema = new mongoose.Schema({
    ownerId: String,
    createdAt: { type: Date, default: Date.now },
    data: Object // Stores the full dump: { profile, project, guests }
});

const UserSchema = new mongoose.Schema({
  user: { type: String, required: true, unique: true }, 
  pass: { type: String }, // Optional for Google Auth users
  authProvider: { type: String, default: 'local' }, // 'local' or 'google'
  googleId: String,
  emailVerified: { type: Boolean, default: true },
  emailVerification: {
    otpHash: String,
    otpExpiresAt: Date,
    lastSentAt: Date,
    verifyAttempts: { type: Number, default: 0 },
  },
  passwordReset: {
    otpHash: String,
    otpExpiresAt: Date,
    lastSentAt: Date,
    verifyAttempts: { type: Number, default: 0 },
    requestedAt: Date,
    lastResetAt: Date,
  },
  emailChange: {
    pendingEmail: String,
    otpHash: String,
    otpExpiresAt: Date,
    lastSentAt: Date,
    verifyAttempts: { type: Number, default: 0 },
    requestedAt: Date,
    confirmedAt: Date,
  },
  loginAlerts: {
    lastSentAt: Date,
    lastIp: String,
    lastUserAgent: String,
  },
  notifications: [{
    title: String,
    message: String,
    priority: { type: String, enum: ['normal', 'high'], default: 'normal' },
    createdAt: { type: Date, default: Date.now },
    createdBy: String,
    createdByRole: String,
    isRead: { type: Boolean, default: false },
    readAt: Date,
  }],
  activity: {
    lastLoginAt: Date,
    lastProfileUpdateAt: Date,
    lastProjectUpdateAt: Date,
    lastGuestsUpdateAt: Date,
    lastActionAt: Date,
    lastActionLabel: String,
  },
  plan: { type: String, default: 'free', enum: ['free', 'basic', 'premium'] },
  isAdmin: { type: Boolean, default: false }, 
  createdAt: { type: Date, default: Date.now }, 
  payments: [PaymentSchema],
  // History of past events
  archivedEvents: [{
      snapshotId: String, // ID referencing ArchivedSnapshot
      eventName: String,
      eventType: String,
      eventDate: Date,
      archivedAt: { type: Date, default: Date.now },
      guestCount: Number,
      totalSpent: Number
  }],
  profile: {
    isSetupComplete: { type: Boolean, default: false }, // NEW FLAG: Forces onboarding
    eventName: String, // Custom name: "Nunta Mariei si Ion"
    eventType: { type: String, default: 'wedding' },
    weddingDate: Date,
    guestEstimate: Number,
    partner1Name: String,
    partner2Name: String,
    firstName: String,
    lastName: String,
    phone: String,
    email: String, 
    address: String,
    city: String,
    county: String,
    country: String,
    shippingCounty: String,
    shippingCity: String,
    shippingStreet: String,
    shippingNumber: String,
    shippingBlock: String,
    shippingStaircase: String,
    shippingFloor: String,
    shippingApartment: String,
    shippingPostalCode: String,
    shippingLandmark: String,
    shippingCountry: String,
    eventRole: String,
    billingType: String,
    billingName: String,
    billingCompany: String,
    billingVatCode: String,
    billingRegNo: String,
    billingAddress: String,
    billingCity: String,
    billingSector: String,
    billingCounty: String,
    billingCountry: String,
    billingEmail: String,
    billingPhone: String,
    godparents: String,
    parents: String,
    locationName: String,
    locationAddress: String,
    eventTime: String,
    venueWazeLink: String,
    churchTime: String,
    churchLocationName: String,
    churchLocationAddress: String,
    churchWazeLink: String,
    civilTime: String,
    civilLocationName: String,
    civilLocationAddress: String,
    civilWazeLink: String,
    timeline: String,
    welcomeText: String,
    celebrationText: String,
    churchLabel: String,
    venueLabel: String,
    civilLabel: String,
    inviteSlug: { type: String, lowercase: true, trim: true },
    avatarUrl: String,
    // Flag-uri vizibilitate
    showWelcomeText: { type: Boolean, default: true },
    showCelebrationText: { type: Boolean, default: true },
    showCivil: { type: Boolean, default: true },
    showChurch: { type: Boolean, default: true },
    showVenue: { type: Boolean, default: true },
    showTimeline: { type: Boolean, default: true },
    showGodparents: { type: Boolean, default: true },
    showParents: { type: Boolean, default: true },
    // Câmpuri noi pentru invitație
    showCountdown: { type: Boolean, default: true },
    showRsvpButton: { type: Boolean, default: true },
    rsvpButtonText: { type: String, default: '' },
    customSections: { type: String, default: '[]' },
    // ── Hero styling ──────────────────────────────────────────────────────
    heroFontFamily:    String,
    heroNameSize:      Number,
    heroDateSize:      Number,
    heroTextColor:     String,
    heroAlign:         String,
    heroBgColor:       String,
    heroLetterSpacing: Number,
    heroLineHeight:    Number,
    // ── CastleMagic intro ─────────────────────────────────────────────────
    heroBgImage:         String,
    heroBgImageMobile:   String,
    castleIntroSubtitle: String,
    castleIntroWelcome:  String,
    castleInviteTop:     String,
    jungleHeaderText:    String,
    jungleOverlayText:   String,
    jungleFooterText:    String,
    jungleIntroStyle:    String,
    castleInviteMiddle:  String,
    castleInviteBottom:  String,
    castleInviteTag:     String,
    // ── Camp-uri salvate cu strict:false — trebuie declarate explicit ────────
    heroContentImage:       String,
    heroContentImageMobile: String,
    colorTheme:             String,
  }
}, { strict: false });

const ProjectSchema = new mongoose.Schema({
  ownerId: { type: String, required: true },
  name: { type: String, default: "Sala Principală" },
  slug: { type: String, default: "eveniment" },
  selectedTemplate: { type: String, default: "classic" },
  elements: { type: Array, default: [] },
  tasks: { type: Array, default: [] },
  budget: { type: Array, default: [] }, 
  totalBudget: { type: Number, default: 0 }, 
  updatedAt: { type: Date, default: Date.now }
});

const GuestSchema = new mongoose.Schema({
  ownerId: { type: String, required: true },
  name: { type: String, required: true },
  type: { type: String, default: 'adult' },
  token: { type: String, required: true, unique: true },
  status: { type: String, default: 'pending' },
  openedAt: Date,
  isSent: { type: Boolean, default: false }, // TRACKING: Daca a fost trimis
  source: { type: String, default: 'manual' }, 
  rsvp: {
    confirmedCount: { type: Number, default: 0 },
    adultsCount: { type: Number, default: 0 },
    childrenCount: { type: Number, default: 0 },
    hasChildren: { type: Boolean, default: false },
    message: String,
    dietary: String
  }
});

const User = mongoose.model('User', UserSchema);
const Project = mongoose.model('Project', ProjectSchema);
const Guest = mongoose.model('Guest', GuestSchema);
const ArchivedSnapshot = mongoose.model('ArchivedSnapshot', ArchivedSnapshotSchema);
const SystemConfig = mongoose.model('SystemConfig', SystemConfigSchema);

const InvitationTemplateSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    description: String,
    category: { type: String, default: 'wedding' },
    colors: [String],
    previewClass: String,
    elementsClass: String,
    thumbnailUrl: String,
    customStyles: String, // CSS string
    reactCode: String, // The actual React component code
    config: Object, // Extra config like font families, background positions, etc.
    isActive: { type: Boolean, default: true },
    isPremium: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const InvitationTemplate = mongoose.model('InvitationTemplate', InvitationTemplateSchema);

// ── Marketplace Service Schema ────────────────────────────────────────────────
const ServiceSchema = new mongoose.Schema({
    name:        { type: String, required: true },
    category:    { type: String, required: true, default: 'altele' },
    description: { type: String, default: '' },
    priceFrom:   { type: Number, default: 0 },
    priceTo:     { type: Number },
    priceUnit:   { type: String, default: 'total', enum: ['total','perPerson','perHour','negociabil'] },
    location:    { type: String, default: '' },
    phone:       { type: String },
    email:       { type: String },
    website:     { type: String },
    instagram:   { type: String },
    imageUrl:    { type: String },
    rating:      { type: Number, default: 5.0 },
    reviewCount: { type: Number, default: 0 },
    tags:        [String],
    featured:    { type: Boolean, default: false },
    available:   { type: Boolean, default: true },
    createdAt:   { type: Date, default: Date.now },
});
const Service = mongoose.model('Service', ServiceSchema);
// ── Service Requests Schema ───────────────────────────────────────────────────
const ServiceRequestSchema = new mongoose.Schema({
  serviceId:       { type: String, required: true },
  serviceName:     { type: String, required: true },
  serviceCategory: { type: String, default: '' },
  name:            { type: String, required: true },
  email:           { type: String, required: true },
  phone:           { type: String, required: true },
  address:         { type: String, default: '' },
  contactTime:     { type: String, default: 'Oricând' },
  budget:          { type: String, default: '' },
  gdprAccepted:    { type: Boolean, default: false },
  callApproved:    { type: Boolean, default: false },
  status:          { type: String, enum: ['pending','sent_to_provider','finalized'], default: 'pending' },
  notes:           { type: String, default: '' },
  createdAt:       { type: Date, default: Date.now },
});
const ServiceRequest = mongoose.model('ServiceRequest', ServiceRequestSchema);

const PLAN_RANK = { free: 0, basic: 1, premium: 2 };

function normalizePlan(value) {
  const plan = String(value || '').trim().toLowerCase();
  return plan === 'premium' || plan === 'basic' ? plan : 'free';
}

function planAtLeast(currentPlan, requestedPlan) {
  const current = normalizePlan(currentPlan);
  const target = normalizePlan(requestedPlan);
  return (PLAN_RANK[current] || 0) >= (PLAN_RANK[target] || 0) ? current : target;
}

function getUpgradeCharge(planPriceMap, currentPlanRaw, targetPlanRaw) {
  const currentPlan = normalizePlan(currentPlanRaw);
  const targetPlan = normalizePlan(targetPlanRaw);
  const currentRank = PLAN_RANK[currentPlan] || 0;
  const targetRank = PLAN_RANK[targetPlan] || 0;

  if (targetPlan === 'free') {
    return { ok: false, reason: 'invalid_target', message: 'Planul ales este invalid.' };
  }
  if (targetRank === currentRank) {
    return { ok: false, reason: 'same_plan', message: `Ai deja planul ${targetPlan} activ.` };
  }
  if (targetRank < currentRank) {
    return { ok: false, reason: 'downgrade_not_allowed', message: 'Ai deja un plan superior activ.' };
  }

  const safeNumber = (value) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  };

  const currentPrice = currentPlan === 'free' ? 0 : safeNumber(planPriceMap[currentPlan]);
  const targetPrice = safeNumber(planPriceMap[targetPlan]);
  const payableAmount = targetPrice - currentPrice;

  if (targetPrice <= 0) {
    return { ok: false, reason: 'target_price_invalid', message: 'Pretul planului selectat nu este configurat.' };
  }
  if (payableAmount <= 0) {
    return { ok: false, reason: 'no_difference', message: 'Nu exista diferenta de plata pentru planul selectat.' };
  }

  return {
    ok: true,
    currentPlan,
    targetPlan,
    currentPrice,
    targetPrice,
    payableAmount,
  };
}



const getConfig = async () => {
    let config = await SystemConfig.findOne({ key: 'global_config' });
    if (!config) {
        config = new SystemConfig();
        await config.save();
    } else {
        let changed = false;
        if (!config.limits?.basic) {
            config.limits.basic = {
                maxGuests: 9999,
                maxElements: 0,
                maxCustomTasks: 0,
                maxBudgetItems: 0,
                maxCalculatorBudget: 0,
            };
            changed = true;
        }
        if (typeof config.pricing?.basicPrice !== 'number') {
            config.pricing.basicPrice = 1900;
            changed = true;
        }
        if (changed) await config.save();
    }
    return config;
};

// --- HELPER: CHECK IF EVENT IS COMPLETED (24 HOURS AFTER) ---
const isEventCompleted = (weddingDate) => {
    if (!weddingDate) return false;
    const eventDate = new Date(weddingDate);
    // Expire 24 hours after the event date
    const oneDayAfter = new Date(eventDate);
    oneDayAfter.setDate(eventDate.getDate() + 1);
    return new Date() > oneDayAfter;
};

const isPastOrInvalidEventDate = (value) => {
    if (value === null || typeof value === 'undefined' || value === '') return false;
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return true;
    parsed.setHours(0, 0, 0, 0);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    return parsed < today;
};

// --- MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 
  if (!token) return res.sendStatus(401); 
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); 
    req.user = user; 
    next();
  });
};

const authenticateAdmin = async (req, res, next) => {
    authenticateToken(req, res, async () => {
        const user = await User.findById(req.user.userId);
        if (user && user.isAdmin) {
            next();
        } else {
            res.status(403).send({ error: 'Admin access required.' });
        }
    });
};

// --- NEW MIDDLEWARE: ENFORCE ACTIVE EVENT ONLY ---
// This middleware blocks write operations if the event is completed (past due + 1 day)
const ensureActiveEvent = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) return res.sendStatus(404);

        if (isEventCompleted(user.profile.weddingDate)) {
            return res.status(403).send({ 
                error: 'Event Finished', 
                message: 'Acest eveniment a expirat (Offline). Arhivează-l pentru a începe unul nou.' 
            });
        }
        next();
    } catch (e) {
        res.status(500).send({ error: 'Check Failed' });
    }
};

function splitDisplayName(fullName = '') {
  const tokens = String(fullName || '').trim().split(/\s+/).filter(Boolean);
  return {
    firstName: tokens[0] || '',
    lastName: tokens.slice(1).join(' '),
  };
}

function logStripeSmartbill(label, payload) {
  if (!STRIPE_SMARTBILL_DEBUG) return;
  if (typeof payload === 'undefined') {
    console.log(`[STRIPE->SMARTBILL][DEBUG] ${label}`);
    return;
  }
  console.log(`[STRIPE->SMARTBILL][DEBUG] ${label}`, payload);
}

function normalizeCountryName(country = '') {
  const raw = String(country || '').trim();
  if (!raw) return '';
  if (raw.toUpperCase() === 'RO') return 'Romania';
  return raw;
}

function normalizeLocationKey(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/\./g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function isBucharestCity(city = '') {
  const key = normalizeLocationKey(city);
  return ['bucuresti', 'bucharest', 'municipiul bucuresti', 'mun bucuresti'].includes(key);
}

function normalizeSectorName(sector = '') {
  const raw = String(sector || '').trim();
  if (!raw) return '';
  const m = raw.match(/([1-6])/);
  if (!m) return '';
  return `Sector ${m[1]}`;
}

function toSmartbillLocality({
  billingType = 'individual',
  city = '',
  sector = '',
  country = '',
}) {
  const normalizedCountry = normalizeCountryName(country || '');
  const normalizedCity = String(city || '').trim();
  const normalizedSector = normalizeSectorName(sector || '');
  const isRomania = ['romania', 'ro'].includes(String(normalizedCountry || '').toLowerCase());
  if (billingType === 'company' && isRomania && isBucharestCity(normalizedCity)) {
    return normalizedSector || '';
  }
  return normalizedCity;
}

function normalizeCountyName(county = '', country = '') {
  const raw = String(county || '').trim();
  if (!raw) return '';
  const isRomania = ['romania', 'ro'].includes(String(country || '').trim().toLowerCase());
  if (!isRomania) return raw;

  const key = raw
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/\./g, '')
    .replace(/\s+/g, ' ')
    .trim();

  const countyMap = {
    'mun bucuresti': 'Bucuresti',
    'municipiul bucuresti': 'Bucuresti',
    bucuresti: 'Bucuresti',
    bucharest: 'Bucuresti',
    ilfov: 'Ilfov',
    timis: 'Timis',
    cluj: 'Cluj',
    iasi: 'Iasi',
    constanta: 'Constanta',
    brasov: 'Brasov',
    sibiu: 'Sibiu',
    bihor: 'Bihor',
    dolj: 'Dolj',
    prahova: 'Prahova',
    galati: 'Galati',
    braila: 'Braila',
    mures: 'Mures',
    maramures: 'Maramures',
    suceava: 'Suceava',
    arges: 'Arges',
  };

  if (countyMap[key]) return countyMap[key];

  return raw
    .split(/\s+/)
    .map((part) => (part ? part.charAt(0).toUpperCase() + part.slice(1).toLowerCase() : ''))
    .join(' ');
}

function inferRomanianCounty(city = '', country = '') {
  const isRomania = ['romania', 'ro'].includes(String(country || '').trim().toLowerCase());
  if (!isRomania) return '';
  const key = String(city || '')
    .trim()
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');

  const cityToCounty = {
    bucuresti: 'Bucuresti',
    bucharest: 'Bucuresti',
    'cluj-napoca': 'Cluj',
    'cluj napoca': 'Cluj',
    cluj: 'Cluj',
    iasi: 'Iasi',
    timisoara: 'Timis',
    constanta: 'Constanta',
    brasov: 'Brasov',
    sibiu: 'Sibiu',
    oradea: 'Bihor',
    craiova: 'Dolj',
    ploiesti: 'Prahova',
    galati: 'Galati',
    braila: 'Braila',
    'targu mures': 'Mures',
    'targu-mures': 'Mures',
    'baia mare': 'Maramures',
    'baia-mare': 'Maramures',
    suceava: 'Suceava',
    pitesti: 'Arges',
  };
  return cityToCounty[key] || '';
}

function sanitizeInputText(value = '', max = 180) {
  return String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max);
}

function normalizeRoPhone(phone = '') {
  return String(phone || '').trim().replace(/\s+/g, '');
}

function isValidRoPhone(phone = '') {
  const digits = String(phone || '').replace(/\D/g, '');
  if (!digits) return false;
  if (digits.length === 10 && digits.startsWith('0')) return true;
  if (digits.length === 11 && digits.startsWith('40')) return true;
  if (digits.length === 12 && digits.startsWith('400')) return true;
  return false;
}

function isValidRoPostalCode(postalCode = '') {
  return /^\d{6}$/.test(String(postalCode || '').trim());
}

function normalizeShippingAddressParts(input = {}) {
  const country = normalizeCountryName(input.shippingCountry || input.country || 'Romania') || 'Romania';
  const city = sanitizeInputText(input.shippingCity || input.city || '', 120);
  const countyFromInput = sanitizeInputText(input.shippingCounty || input.county || '', 120);
  const county = isBucharestCity(city)
    ? 'Bucuresti'
    : (normalizeCountyName(countyFromInput, country) || inferRomanianCounty(city, country));

  return {
    shippingCounty: county,
    shippingCity: city,
    shippingStreet: sanitizeInputText(input.shippingStreet || '', 160),
    shippingNumber: sanitizeInputText(input.shippingNumber || '', 32),
    shippingBlock: sanitizeInputText(input.shippingBlock || '', 32),
    shippingStaircase: sanitizeInputText(input.shippingStaircase || '', 32),
    shippingFloor: sanitizeInputText(input.shippingFloor || '', 32),
    shippingApartment: sanitizeInputText(input.shippingApartment || '', 32),
    shippingPostalCode: sanitizeInputText(input.shippingPostalCode || '', 16),
    shippingLandmark: sanitizeInputText(input.shippingLandmark || '', 240),
    shippingCountry: country,
  };
}

function isShippingAddressComplete(parts = {}) {
  return Boolean(
    sanitizeInputText(parts.shippingCounty || '') &&
    sanitizeInputText(parts.shippingCity || '') &&
    sanitizeInputText(parts.shippingStreet || '') &&
    sanitizeInputText(parts.shippingNumber || '') &&
    isValidRoPostalCode(parts.shippingPostalCode || ''),
  );
}

function composeShippingAddressLine(parts = {}) {
  const streetLine = [
    sanitizeInputText(parts.shippingStreet || ''),
    sanitizeInputText(parts.shippingNumber || ''),
  ].filter(Boolean).join(' ');
  const extra = [
    parts.shippingBlock ? `Bl. ${sanitizeInputText(parts.shippingBlock || '')}` : '',
    parts.shippingStaircase ? `Sc. ${sanitizeInputText(parts.shippingStaircase || '')}` : '',
    parts.shippingFloor ? `Et. ${sanitizeInputText(parts.shippingFloor || '')}` : '',
    parts.shippingApartment ? `Ap. ${sanitizeInputText(parts.shippingApartment || '')}` : '',
  ].filter(Boolean).join(', ');
  const locality = [
    sanitizeInputText(parts.shippingCity || ''),
    sanitizeInputText(parts.shippingCounty || ''),
    sanitizeInputText(parts.shippingCountry || 'Romania'),
  ].filter(Boolean).join(', ');
  const postal = isValidRoPostalCode(parts.shippingPostalCode || '')
    ? `Cod postal ${sanitizeInputText(parts.shippingPostalCode || '')}`
    : '';
  const landmark = sanitizeInputText(parts.shippingLandmark || '');
  return [streetLine, extra, locality, postal, landmark ? `Reper: ${landmark}` : '']
    .filter(Boolean)
    .join(' | ');
}

function getProfileShippingAddress(profile = {}) {
  const normalized = normalizeShippingAddressParts({
    shippingCounty: profile?.shippingCounty || profile?.county || '',
    shippingCity: profile?.shippingCity || profile?.city || '',
    shippingStreet: profile?.shippingStreet || '',
    shippingNumber: profile?.shippingNumber || '',
    shippingBlock: profile?.shippingBlock || '',
    shippingStaircase: profile?.shippingStaircase || '',
    shippingFloor: profile?.shippingFloor || '',
    shippingApartment: profile?.shippingApartment || '',
    shippingPostalCode: profile?.shippingPostalCode || '',
    shippingLandmark: profile?.shippingLandmark || '',
    shippingCountry: profile?.shippingCountry || profile?.country || 'Romania',
  });
  if (!normalized.shippingStreet && profile?.address) {
    normalized.shippingStreet = sanitizeInputText(profile.address, 160);
  }
  return normalized;
}

function getCheckoutContactAndAddress({ billing = {}, profile = {}, emailFallback = '' }) {
  const firstName = sanitizeInputText(
    billing.firstName || profile?.firstName || splitDisplayName(profile?.billingName || '').firstName || '',
    80,
  );
  const lastName = sanitizeInputText(
    billing.lastName || profile?.lastName || splitDisplayName(profile?.billingName || '').lastName || '',
    120,
  );
  const email = sanitizeInputText(
    billing.email || profile?.billingEmail || profile?.email || emailFallback || '',
    180,
  ).toLowerCase();
  const phone = normalizeRoPhone(billing.phone || profile?.billingPhone || profile?.phone || '');
  const profileShipping = getProfileShippingAddress(profile);
  const shippingAddress = normalizeShippingAddressParts({
    shippingCounty: billing.county || billing.shippingCounty || profileShipping.shippingCounty,
    shippingCity: billing.city || billing.shippingCity || profileShipping.shippingCity,
    shippingStreet: billing.street || billing.shippingStreet || profileShipping.shippingStreet,
    shippingNumber: billing.number || billing.shippingNumber || profileShipping.shippingNumber,
    shippingBlock: billing.block || billing.shippingBlock || profileShipping.shippingBlock,
    shippingStaircase: billing.staircase || billing.shippingStaircase || profileShipping.shippingStaircase,
    shippingFloor: billing.floor || billing.shippingFloor || profileShipping.shippingFloor,
    shippingApartment: billing.apartment || billing.shippingApartment || profileShipping.shippingApartment,
    shippingPostalCode: billing.postalCode || billing.shippingPostalCode || profileShipping.shippingPostalCode,
    shippingLandmark: billing.landmark || billing.shippingLandmark || profileShipping.shippingLandmark,
    shippingCountry: billing.country || billing.shippingCountry || profileShipping.shippingCountry || 'Romania',
  });

  const sourceRaw = sanitizeInputText(billing.addressSource || billing.source || '', 40).toLowerCase();
  const addressSource = sourceRaw === 'saved_account' ? 'saved_account' : 'manual_entry';

  return {
    firstName,
    lastName,
    email,
    phone,
    addressSource,
    shippingAddress,
    profileShipping,
  };
}

function getSmartbillBillingFromProfile(profile = {}, emailFallback = '') {
  const billingType = String(profile?.billingType || '').trim() === 'company' ? 'company' : 'individual';
  const billingName = String(profile?.billingName || '').trim();
  const billingCompany = String(profile?.billingCompany || '').trim();
  const city = String(profile?.billingCity || profile?.city || '').trim();
  const sector = normalizeSectorName(profile?.billingSector || '');
  const country = normalizeCountryName(profile?.billingCountry || profile?.country || 'Romania');
  const countyRaw = String(profile?.billingCounty || profile?.county || '').trim();
  const county = normalizeCountyName(countyRaw, country) || inferRomanianCounty(city, country);
  const address = String(profile?.billingAddress || profile?.address || '').trim();
  const smartbillCity = toSmartbillLocality({
    billingType,
    city,
    sector,
    country,
  });
  const normalizedTaxCode = normalizeBillingTaxCode({
    billingType,
    vatCode: profile?.billingVatCode || '',
  });
  return {
    type: billingType,
    name: billingName || [profile?.firstName, profile?.lastName].filter(Boolean).join(' ').trim() || 'Client',
    company: billingCompany,
    vatCode: normalizedTaxCode,
    regNo: String(profile?.billingRegNo || '').trim(),
    address,
    city: smartbillCity || city,
    sector,
    county,
    country,
    email: String(profile?.billingEmail || profile?.email || emailFallback || '').trim(),
    phone: String(profile?.billingPhone || profile?.phone || '').trim(),
  };
}

function buildEmailAttachmentFromFile(filePath, filename = 'factura.pdf') {
  if (!filePath) return null;
  try {
    if (!fs.existsSync(filePath)) return null;
    const fileBuffer = fs.readFileSync(filePath);
    return {
      filename,
      content: fileBuffer.toString('base64'),
    };
  } catch (error) {
    console.error('[EMAIL] Failed preparing invoice attachment:', error.message);
    return null;
  }
}

function resolveLocalUploadPathFromPublicUrl(publicUrl = '') {
  const normalized = String(publicUrl || '').trim();
  if (!normalized.startsWith('/uploads/')) return '';
  return path.join(process.cwd(), normalized.replace(/^\/+/, ''));
}

// --- STRIPE WEBHOOK ---
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error(`❌ Webhook Signature Error: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.client_reference_id;
    const customerEmail = session.customer_details?.email;
    const amountTotal = session.amount_total ? session.amount_total / 100 : 0;
    const meta = session.metadata || {};
    const targetPlan = normalizePlan(meta.targetPlan || 'premium');
    const invoiceRef = session.invoice || session.id;
    logStripeSmartbill('Checkout session completed', {
      eventId: event.id,
      sessionId: session.id,
      userId,
      targetPlan,
      amountTotal,
      customerEmail,
      stripeInvoiceId: session.invoice || null,
      paymentStatus: session.payment_status,
      metadataKeys: Object.keys(meta || {}),
      smartbillConfigured: isSmartbillConfigured(),
    });

    if (session.payment_status !== 'paid') {
      logStripeSmartbill('Skipping webhook update because payment is not paid yet', {
        sessionId: session.id,
        invoiceRef,
        paymentStatus: session.payment_status,
      });
      return res.json({ received: true, skipped: 'payment_not_paid' });
    }

    try {
        let invoicePdfUrl = null;
        let hostedInvoiceUrl = null;
        let invoiceNumber = '';
        let invoiceEmailData = null;

        if (session.invoice) {
            try {
                const invoice = await stripe.invoices.retrieve(session.invoice);
                invoicePdfUrl = invoice.invoice_pdf;
                hostedInvoiceUrl = invoice.hosted_invoice_url;
            } catch (invErr) {
                console.error("⚠️ Failed to retrieve invoice details:", invErr.message);
            }
        }

        const user = await User.findById(userId);
        const alreadyPaid = await User.exists({
          _id: userId,
          'payments.invoiceId': invoiceRef,
          'payments.status': 'Paid',
        });
        if (alreadyPaid) {
          logStripeSmartbill('Skipping duplicate paid webhook', { userId, invoiceRef });
          return res.json({ received: true, duplicate: true });
        }

        const stripeAddress = session.customer_details?.address || {};
        const stripeStreet = [stripeAddress.line1, stripeAddress.line2].filter(Boolean).join(', ').trim();
        const relatedEventDate = user?.profile?.weddingDate;
        const relatedEventName = user?.profile?.eventName || 'Eveniment Nedenumit';
        const billingEmail = (meta.billingEmail || customerEmail || '').trim();
        const checkoutAddressSource = String(meta.checkoutAddressSource || '').trim() === 'saved_account'
          ? 'saved_account'
          : 'manual_entry';
        const checkoutFirstName = String(meta.checkoutFirstName || user?.profile?.firstName || '').trim();
        const checkoutLastName = String(meta.checkoutLastName || user?.profile?.lastName || '').trim();
        const checkoutPhone = String(meta.checkoutPhone || user?.profile?.phone || '').trim();
        const checkoutEmail = String(meta.checkoutEmail || billingEmail || '').trim();
        const checkoutAddress = normalizeShippingAddressParts({
          shippingCounty: meta.checkoutCounty || user?.profile?.shippingCounty || user?.profile?.county || '',
          shippingCity: meta.checkoutCity || user?.profile?.shippingCity || user?.profile?.city || '',
          shippingStreet: meta.checkoutStreet || user?.profile?.shippingStreet || stripeStreet || '',
          shippingNumber: meta.checkoutNumber || user?.profile?.shippingNumber || '',
          shippingBlock: meta.checkoutBlock || user?.profile?.shippingBlock || '',
          shippingStaircase: meta.checkoutStaircase || user?.profile?.shippingStaircase || '',
          shippingFloor: meta.checkoutFloor || user?.profile?.shippingFloor || '',
          shippingApartment: meta.checkoutApartment || user?.profile?.shippingApartment || '',
          shippingPostalCode: meta.checkoutPostalCode || user?.profile?.shippingPostalCode || '',
          shippingLandmark: meta.checkoutLandmark || user?.profile?.shippingLandmark || '',
          shippingCountry: meta.checkoutCountry || user?.profile?.shippingCountry || user?.profile?.country || 'Romania',
        });
        const savedAddressSnapshot = normalizeShippingAddressParts({
          shippingCounty: meta.accountCounty || user?.profile?.shippingCounty || user?.profile?.county || '',
          shippingCity: meta.accountCity || user?.profile?.shippingCity || user?.profile?.city || '',
          shippingStreet: meta.accountStreet || user?.profile?.shippingStreet || '',
          shippingNumber: meta.accountNumber || user?.profile?.shippingNumber || '',
          shippingBlock: meta.accountBlock || user?.profile?.shippingBlock || '',
          shippingStaircase: meta.accountStaircase || user?.profile?.shippingStaircase || '',
          shippingFloor: meta.accountFloor || user?.profile?.shippingFloor || '',
          shippingApartment: meta.accountApartment || user?.profile?.shippingApartment || '',
          shippingPostalCode: meta.accountPostalCode || user?.profile?.shippingPostalCode || '',
          shippingLandmark: meta.accountLandmark || user?.profile?.shippingLandmark || '',
          shippingCountry: meta.accountCountry || user?.profile?.shippingCountry || user?.profile?.country || 'Romania',
        });
        const billingType = (meta.billingType || '').trim() === 'company' ? 'company' : 'individual';
        const billingName = (meta.billingName || '').trim();
        const billingCompany = (meta.billingCompany || '').trim();
        const billingVatCode = normalizeBillingTaxCode({
          billingType,
          vatCode: (meta.billingVatCode || '').trim(),
        });
        const billingCountry = normalizeCountryName(
          meta.billingCountry || stripeAddress.country || user?.profile?.billingCountry || user?.profile?.country || 'Romania',
        );
        const billingCity = (meta.billingCity || stripeAddress.city || user?.profile?.billingCity || user?.profile?.city || '').trim();
        const billingSector = normalizeSectorName(meta.billingSector || user?.profile?.billingSector || '');
        const billingCountyRaw = (meta.billingCounty || stripeAddress.state || user?.profile?.billingCounty || user?.profile?.county || '').trim();
        const billingCounty = isBucharestCity(billingCity)
          ? 'Bucuresti'
          : (normalizeCountyName(billingCountyRaw, billingCountry) || inferRomanianCounty(billingCity, billingCountry));
        const billingRegNo = (meta.billingRegNo || user?.profile?.billingRegNo || '').trim();
        const smartbillCity = toSmartbillLocality({
          billingType,
          city: billingCity,
          sector: billingSector,
          country: billingCountry,
        }) || billingCity;
        const composedCheckoutAddress = composeShippingAddressLine(checkoutAddress);
        const baseAddress = (meta.billingAddress || composedCheckoutAddress || stripeStreet || user?.profile?.billingAddress || user?.profile?.address || '').trim();
        const billingAddress =
          baseAddress || [billingCity, billingCounty, billingCountry].filter(Boolean).join(', ');
        const displayName = billingCompany || billingName;
        const { firstName: billingFirstName, lastName: billingLastName } = splitDisplayName(displayName);

        if (isSmartbillConfigured()) {
          try {
            logStripeSmartbill('SmartBill flow input', {
              billingType,
              billingName: billingName || displayName || 'Client',
              billingCompany,
              billingVatCode: billingVatCode ? `${billingVatCode.slice(0, 3)}***` : '',
              baseAddress,
              billingCity,
              billingSector,
              billingCounty,
              billingRegNo,
              billingCountry: billingCountry || 'Romania',
              billingEmail,
              amount: amountTotal,
            });
            const smartbillResult = await createSmartbillInvoiceFlow({
              billing: {
                type: billingType,
                name: billingName || displayName || 'Client',
                company: billingCompany,
                vatCode: billingVatCode,
                regNo: billingRegNo,
                address: baseAddress,
                city: smartbillCity,
                sector: billingSector,
                county: billingCounty,
                country: billingCountry || 'Romania',
                email: billingEmail,
                phone: (meta.billingPhone || '').trim(),
              },
              amount: amountTotal,
              currency: 'RON',
              description: targetPlan === 'basic' ? 'Wedding Planner Basic' : 'Wedding Planner Premium',
              sendEmail: false,
            });
            if (smartbillResult?.enabled) {
              invoiceNumber = smartbillResult.invoiceNumber || '';
              if (smartbillResult.pdfPublicUrl) {
                invoicePdfUrl = smartbillResult.pdfPublicUrl;
              }
              invoiceEmailData = {
                pdfFilePath: smartbillResult.pdfFilePath || '',
                pdfFileName: smartbillResult.pdfFileName || '',
              };
              logStripeSmartbill('SmartBill flow success', {
                invoiceNumber,
                pdfPublicUrl: smartbillResult.pdfPublicUrl || null,
                clientTaxCode: billingVatCode ? `${billingVatCode.slice(0, 3)}***` : '',
              });
            }
          } catch (smartbillErr) {
            console.error('[SMARTBILL] Stripe checkout invoice failed:', smartbillErr.message);
            logStripeSmartbill('SmartBill flow error', {
              message: smartbillErr.message,
              stack: smartbillErr.stack,
            });
          }
        } else {
          logStripeSmartbill('SmartBill skipped (missing env config)');
        }

        const newPayment = {
            date: new Date(),
            amount: amountTotal,
            invoiceId: invoiceRef,
            invoiceNumber,
            billingEmail,
            billingFirstName,
            billingLastName,
            billingAddress,
            billingCity,
            billingSector,
            billingCounty,
            billingCountry,
            checkoutAddressSource,
            checkoutFirstName,
            checkoutLastName,
            checkoutPhone,
            checkoutEmail,
            checkoutCounty: checkoutAddress.shippingCounty,
            checkoutCity: checkoutAddress.shippingCity,
            checkoutStreet: checkoutAddress.shippingStreet,
            checkoutNumber: checkoutAddress.shippingNumber,
            checkoutBlock: checkoutAddress.shippingBlock,
            checkoutStaircase: checkoutAddress.shippingStaircase,
            checkoutFloor: checkoutAddress.shippingFloor,
            checkoutApartment: checkoutAddress.shippingApartment,
            checkoutPostalCode: checkoutAddress.shippingPostalCode,
            checkoutLandmark: checkoutAddress.shippingLandmark,
            checkoutCountry: checkoutAddress.shippingCountry || 'Romania',
            savedAddressSnapshot: {
              county: savedAddressSnapshot.shippingCounty,
              city: savedAddressSnapshot.shippingCity,
              street: savedAddressSnapshot.shippingStreet,
              number: savedAddressSnapshot.shippingNumber,
              block: savedAddressSnapshot.shippingBlock,
              staircase: savedAddressSnapshot.shippingStaircase,
              floor: savedAddressSnapshot.shippingFloor,
              apartment: savedAddressSnapshot.shippingApartment,
              postalCode: savedAddressSnapshot.shippingPostalCode,
              landmark: savedAddressSnapshot.shippingLandmark,
              country: savedAddressSnapshot.shippingCountry || 'Romania',
            },
            checkoutAddressSnapshot: {
              county: checkoutAddress.shippingCounty,
              city: checkoutAddress.shippingCity,
              street: checkoutAddress.shippingStreet,
              number: checkoutAddress.shippingNumber,
              block: checkoutAddress.shippingBlock,
              staircase: checkoutAddress.shippingStaircase,
              floor: checkoutAddress.shippingFloor,
              apartment: checkoutAddress.shippingApartment,
              postalCode: checkoutAddress.shippingPostalCode,
              landmark: checkoutAddress.shippingLandmark,
              country: checkoutAddress.shippingCountry || 'Romania',
            },
            invoicePdfUrl: invoicePdfUrl,
            hostedInvoiceUrl: hostedInvoiceUrl,
            paymentMethod: 'stripe_card',
            planTarget: targetPlan,
            status: 'Paid',
            relatedEventDate: relatedEventDate,
            relatedEventName: relatedEventName // Store the name for history
        };

        const profileBillingSet = {};
        profileBillingSet['profile.billingType'] = billingType;
        if (billingName) profileBillingSet['profile.billingName'] = billingName;
        if (billingCompany) profileBillingSet['profile.billingCompany'] = billingCompany;
        if (billingVatCode) profileBillingSet['profile.billingVatCode'] = billingVatCode;
        if (meta.billingRegNo) profileBillingSet['profile.billingRegNo'] = meta.billingRegNo;
        if (baseAddress) profileBillingSet['profile.billingAddress'] = baseAddress;
        if (billingCity) profileBillingSet['profile.billingCity'] = billingCity;
        if (billingSector) profileBillingSet['profile.billingSector'] = billingSector;
        if (billingCounty) profileBillingSet['profile.billingCounty'] = billingCounty;
        if (billingCountry) profileBillingSet['profile.billingCountry'] = billingCountry;
        if (billingEmail) {
            profileBillingSet['profile.billingEmail'] = billingEmail;
            profileBillingSet['profile.email'] = billingEmail;
        }
        if (meta.billingPhone) profileBillingSet['profile.billingPhone'] = meta.billingPhone;
        profileBillingSet['profile.firstName'] = checkoutFirstName || user?.profile?.firstName || '';
        profileBillingSet['profile.lastName'] = checkoutLastName || user?.profile?.lastName || '';
        profileBillingSet['profile.phone'] = checkoutPhone || user?.profile?.phone || '';
        if (isShippingAddressComplete(checkoutAddress)) {
          profileBillingSet['profile.address'] = composedCheckoutAddress || user?.profile?.address || '';
          profileBillingSet['profile.city'] = checkoutAddress.shippingCity || user?.profile?.city || '';
          profileBillingSet['profile.county'] = checkoutAddress.shippingCounty || user?.profile?.county || '';
          profileBillingSet['profile.country'] = checkoutAddress.shippingCountry || user?.profile?.country || 'Romania';
          profileBillingSet['profile.shippingCounty'] = checkoutAddress.shippingCounty || '';
          profileBillingSet['profile.shippingCity'] = checkoutAddress.shippingCity || '';
          profileBillingSet['profile.shippingStreet'] = checkoutAddress.shippingStreet || '';
          profileBillingSet['profile.shippingNumber'] = checkoutAddress.shippingNumber || '';
          profileBillingSet['profile.shippingBlock'] = checkoutAddress.shippingBlock || '';
          profileBillingSet['profile.shippingStaircase'] = checkoutAddress.shippingStaircase || '';
          profileBillingSet['profile.shippingFloor'] = checkoutAddress.shippingFloor || '';
          profileBillingSet['profile.shippingApartment'] = checkoutAddress.shippingApartment || '';
          profileBillingSet['profile.shippingPostalCode'] = checkoutAddress.shippingPostalCode || '';
          profileBillingSet['profile.shippingLandmark'] = checkoutAddress.shippingLandmark || '';
          profileBillingSet['profile.shippingCountry'] = checkoutAddress.shippingCountry || 'Romania';
        }

        const nextPlan = planAtLeast(user?.plan || 'free', targetPlan);
        await User.findByIdAndUpdate(userId, {
            $set: {
                plan: nextPlan,
                ...profileBillingSet,
            },
            $push: { payments: newPayment },
        });
        logStripeSmartbill('DB update done', {
          userId,
          nextPlan,
          invoiceNumber,
          invoicePdfUrl,
          paymentMethod: newPayment.paymentMethod,
        });

        if (billingEmail && invoiceNumber) {
          const attachment = buildEmailAttachmentFromFile(
            invoiceEmailData?.pdfFilePath,
            invoiceEmailData?.pdfFileName || `${invoiceNumber}.pdf`,
          );
          const invoicePublicUrl = invoicePdfUrl
            ? (String(invoicePdfUrl).startsWith('http') ? invoicePdfUrl : `${CLIENT_URL}${invoicePdfUrl}`)
            : '';
          const sent = await emailNotifications.sendBillingInvoiceEmail({
            email: billingEmail,
            name: displayName || [user?.profile?.firstName, user?.profile?.lastName].filter(Boolean).join(' ').trim(),
            invoiceNumber,
            amount: amountTotal,
            currency: 'RON',
            issueDate: new Date(),
            eventName: relatedEventName || '',
            invoiceUrl: invoicePublicUrl,
            attachments: attachment ? [attachment] : [],
          });
          logStripeSmartbill('Invoice email sent via emailNotifications', {
            sent,
            hasAttachment: Boolean(attachment),
            invoiceNumber,
            billingEmail,
          });
        } else {
          logStripeSmartbill('Invoice email skipped (missing email or invoice number)', {
            billingEmail,
            invoiceNumber,
          });
        }
    } catch (dbError) {
        console.error('❌ Database Update Failed:', dbError);
        logStripeSmartbill('DB update error', {
          message: dbError.message,
          stack: dbError.stack,
        });
    }
  }

  res.json({ received: true });
});

// --- STANDARD MIDDLEWARE ---
app.use(morgan(':remote-addr - :method :url :status :res[content-length] - :response-time ms'));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    skip: (req) => {
        const authHeader = req.headers['authorization'];
        return authHeader && authHeader.startsWith('Bearer ');
    },
    message: 'Prea multe cereri de la acest IP.'
});
// app.use('/api/', limiter);

// ─── Default wedding blocks — used on setup AND when customSections is empty ──
const WEDDING_DEFAULT_BLOCKS = JSON.stringify([

                // ════════════════════════════════════════════════════════
                // FOTO 1 — Cuplu hero (arc + fade jos) — ca în preview
                // ════════════════════════════════════════════════════════
                {
                    id: "block-photo-1",
                    type: "photo",
                    show: true,
                    imageData: "https://picsum.photos/seed/terra-w1/400/533",
                    altText: "Fotografie cuplu",
                    aspectRatio: "3:4",
                    photoClip: "arch",
                    photoMasks: ["fade-b"]
                },

                // ════════════════════════════════════════════════════════
                // CITAT
                // ════════════════════════════════════════════════════════
                {
                    id: "block-quote-1",
                    type: "quote",
                    show: true,
                    content: "Dragostea noastră s-a născut în Dios, crește în Cristos și va rămâne prin harul Său.",
                    label: "1 Corinteni 13:4"
                },

                // ════════════════════════════════════════════════════════
                // MUZICĂ
                // ════════════════════════════════════════════════════════
                {
                    id: "block-music-1",
                    type: "music",
                    show: true,
                    musicTitle: "Cântecul nostru",
                    musicArtist: "Artist",
                    musicUrl: "",
                    musicType: "none"
                },

                // ════════════════════════════════════════════════════════
                // COUNTDOWN — dark section
                // ════════════════════════════════════════════════════════
                {
                    id: "block-countdown-1",
                    type: "countdown",
                    show: true
                },

                // ════════════════════════════════════════════════════════
                // CALENDAR
                // ════════════════════════════════════════════════════════
                {
                    id: "block-calendar-1",
                    type: "calendar",
                    show: true
                },

                // ════════════════════════════════════════════════════════
                // FOTO 2 — Landscape romantic
                // ════════════════════════════════════════════════════════
                {
                    id: "block-photo-2",
                    type: "photo",
                    show: true,
                    imageData: "https://picsum.photos/seed/terra-w2/800/450",
                    altText: "Fotografie romantic",
                    aspectRatio: "16:9",
                    photoClip: "rounded",
                    photoMasks: []
                },

                // ════════════════════════════════════════════════════════
                // FOTO 3 — Portret vertical
                // ════════════════════════════════════════════════════════
                {
                    id: "block-photo-3",
                    type: "photo",
                    show: true,
                    imageData: "https://picsum.photos/seed/terra-w3/400/533",
                    altText: "Fotografie portret",
                    aspectRatio: "3:4",
                    photoClip: "rounded",
                    photoMasks: []
                },

                // ════════════════════════════════════════════════════════
                // PĂRINȚI
                // ════════════════════════════════════════════════════════
                {
                    id: "block-parents-1",
                    type: "parents",
                    show: true,
                    sectionTitle: "Părinții Noștri",
                    content: "Cu drag și recunoștință, alături de părinții noștri:"
                },

                // ════════════════════════════════════════════════════════
                // NAȘI
                // ════════════════════════════════════════════════════════
                {
                    id: "block-godparents-1",
                    type: "godparents",
                    show: true,
                    sectionTitle: "Nașii Noștri",
                    content: "Alături de nașii noștri, care ne-au călăuzit pașii:"
                },

                // ════════════════════════════════════════════════════════
                // LOCAȚII
                // ════════════════════════════════════════════════════════
                {
                    id: "block-loc-civil",
                    type: "location",
                    show: true,
                    label: "Cununie Civilă",
                    time: "12:00",
                    locationName: "Starea Civilă",
                    locationAddress: "Str. Exemplu nr. 1, Oraș",
                    wazeLink: ""
                },
                {
                    id: "block-loc-church",
                    type: "location",
                    show: true,
                    label: "Cununie Religioasă",
                    time: "14:00",
                    locationName: "Biserica Sfânta Maria",
                    locationAddress: "Str. Bisericii nr. 5, Oraș",
                    wazeLink: ""
                },
                {
                    id: "block-loc-party",
                    type: "location",
                    show: true,
                    label: "Petrecere",
                    time: "18:00",
                    locationName: "Salon Grand Ballroom",
                    locationAddress: "Str. Petrecerii nr. 10, Oraș",
                    wazeLink: ""
                },

                // ════════════════════════════════════════════════════════
                // FOTO 4 — Cerc cu vignetă
                // ════════════════════════════════════════════════════════
                {
                    id: "block-photo-4",
                    type: "photo",
                    show: true,
                    imageData: "https://picsum.photos/seed/terra-w4/400/400",
                    altText: "Fotografie",
                    aspectRatio: "1:1",
                    photoClip: "circle",
                    photoMasks: ["vignette"]
                },

                // ════════════════════════════════════════════════════════
                // COD VESTIMENTAR
                // ════════════════════════════════════════════════════════
                {
                    id: "block-dresscode-1",
                    type: "dresscode",
                    show: true,
                    sectionTitle: "Cod vestimentar",
                    label: "Elegant",
                    content: "Doamne: Vă rugăm să evitați culorile alb, bej și roșu.\nDomni: Vă rugăm să evitați culoarea bej și tonurile similare."
                },

                // ════════════════════════════════════════════════════════
                // CADOURI
                // ════════════════════════════════════════════════════════
                {
                    id: "block-gift-1",
                    type: "gift",
                    show: true,
                    sectionTitle: "Sugestie de cadou",
                    content: "Cel mai frumos cadou este prezența voastră. Dacă doriți un detaliu, vă lăsăm mai jos o opțiune.",
                    iban: "RO00 BANK 0000 0000 0000 0000",
                    ibanName: "Camila & Sebastián"
                },

                // ════════════════════════════════════════════════════════
                // FĂRĂ COPII
                // ════════════════════════════════════════════════════════
                {
                    id: "block-nokids-1",
                    type: "nokids",
                    show: true,
                    sectionTitle: "Eveniment fără copii",
                    content: "Nunta noastră va fi un eveniment pentru adulți. Vă rugăm să luați în considerare îngrijirea copiilor în această zi specială. Vă mulțumim pentru înțelegere!"
                },

                // ════════════════════════════════════════════════════════
                // FOTO 5 — Final blob
                // ════════════════════════════════════════════════════════
                {
                    id: "block-photo-5",
                    type: "photo",
                    show: true,
                    imageData: "https://picsum.photos/seed/terra-w5/400/533",
                    altText: "Fotografie finală",
                    aspectRatio: "3:4",
                    photoClip: "blob",
                    photoMasks: ["fade-b"]
                },

                // ════════════════════════════════════════════════════════
                // MULȚUMIRE
                // ════════════════════════════════════════════════════════
                {
                    id: "block-thankyou-1",
                    type: "thankyou",
                    show: true,
                    content: "Vă așteptăm cu drag!",
                    label: "ESPERAMOS CONTAR CON SU PRESENCIA"
                }


]);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// --- MONGODB CONNECTION ---
mongoose.connect(MONGO_URI)
  .then(() => { console.log('✅ Connected to MongoDB'); seedServices(); })
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// --- UTILS ---
const generateToken = () => Math.random().toString(36).substring(2, 10) + Math.random().toString(36).substring(2, 10);
const normalizeEmail = (email = '') => String(email).trim().toLowerCase();
const normalizeText = (value = '') => String(value ?? '').trim();
const generateEmailOtp = () => String(Math.floor(100000 + Math.random() * 900000));
const hashEmailOtp = (email, otp) =>
  crypto
    .createHash('sha256')
    .update(`${JWT_SECRET}|${normalizeEmail(email)}|${otp}`)
    .digest('hex');

const getUserDisplayName = (userDoc) =>
  userDoc?.profile?.firstName ||
  userDoc?.profile?.partner1Name ||
  userDoc?.profile?.eventName ||
  userDoc?.user ||
  'prietene';

const computeDaysUntilDate = (dateValue) => {
  if (!dateValue) return null;
  const target = new Date(dateValue);
  if (Number.isNaN(target.getTime())) return null;
  const now = new Date();
  target.setHours(12, 0, 0, 0);
  now.setHours(12, 0, 0, 0);
  return Math.round((target.getTime() - now.getTime()) / 86400000);
};

async function pushUserNotification(userId, payload = {}) {
  const title = String(payload.title || '').trim();
  const message = String(payload.message || '').trim();
  if (!title || !message) return false;

  const priority = String(payload.priority || '').toLowerCase() === 'high' ? 'high' : 'normal';
  const createdBy = String(payload.createdBy || '').trim();
  const createdByRole = String(payload.createdByRole || '').trim();
  const now = new Date();

  await User.findByIdAndUpdate(userId, {
    $push: {
      notifications: {
        $each: [{
          title: title.slice(0, 180),
          message: message.slice(0, 3000),
          priority,
          createdAt: now,
          createdBy: createdBy.slice(0, 120),
          createdByRole: createdByRole.slice(0, 60),
          isRead: false,
        }],
        $position: 0,
      },
    },
    $set: {
      'activity.lastActionAt': now,
      'activity.lastActionLabel': 'Notificare noua primita',
    },
  });

  return true;
}

async function sendEmailVerificationOtp(email, otp) {
  return emailNotifications.sendVerificationOtp({
    email,
    otp,
    ttlMinutes: EMAIL_OTP_TTL_MINUTES,
  });
}

async function sendPasswordResetOtp(email, otp, name = '') {
  return emailNotifications.sendPasswordResetOtp({
    email,
    name,
    otp,
    ttlMinutes: PASSWORD_RESET_OTP_TTL_MINUTES,
  });
}

// --- ROUTES ---

// AUTH LOCAL
// OTP email verification flow (kept before legacy routes so it takes precedence)
app.post('/api/register', async (req, res) => {
  try {
    const body = req.body || {};
    const user = normalizeEmail(body.user);
    const { pass } = body;
    const firstName = normalizeText(body.firstName);
    const lastName = normalizeText(body.lastName);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!user || !emailRegex.test(user)) {
      return res.status(400).send({ error: 'Adresa de email este obligatorie si trebuie sa fie valida.' });
    }
    if (!pass || pass.length < 6) {
      return res.status(400).send({ error: 'Parola trebuie sa aiba minim 6 caractere.' });
    }
    if (!firstName || !lastName) {
      return res.status(400).send({ error: 'Prenumele si numele sunt obligatorii.' });
    }

    const existingUser = await User.findOne({ user });
    if (existingUser) {
      if (existingUser.authProvider === 'local' && existingUser.emailVerified === false) {
        return res.status(400).send({
          error: 'Acest cont exista, dar emailul nu este inca verificat.',
          code: 'EMAIL_NOT_VERIFIED',
          email: existingUser.user,
        });
      }
      return res.status(400).send({ error: 'Cont deja existent pentru acest email.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(pass, salt);
    const otp = generateEmailOtp();
    const otpExpiresAt = new Date(Date.now() + EMAIL_OTP_TTL_MINUTES * 60 * 1000);
    const isFirstUser = (await User.countDocuments({})) === 0;

    const newUser = new User({
      user,
      pass: hashedPassword,
      authProvider: 'local',
      emailVerified: false,
      emailVerification: {
        otpHash: hashEmailOtp(user, otp),
        otpExpiresAt,
        lastSentAt: new Date(),
        verifyAttempts: 0,
      },
      plan: 'free',
      isAdmin: isFirstUser,
      profile: {
        email: user,
        isSetupComplete: false,
        eventType: 'wedding',
        guestEstimate: 150,
        firstName,
        lastName,
      },
    });

    await newUser.save();
    const sent = await sendEmailVerificationOtp(user, otp);
    if (!sent) {
      await User.findByIdAndDelete(newUser._id);
      return res.status(500).send({ error: 'Nu am putut trimite emailul de verificare. Incearca din nou.' });
    }

    return res.send({
      success: true,
      requiresEmailVerification: true,
      email: user,
      message: 'Ti-am trimis un cod OTP pe email. Verifica inbox-ul pentru activare.',
    });
  } catch (error) {
    return res.status(500).send({ error: 'Server error' });
  }
});

app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const user = normalizeEmail(req.body?.user);
    if (!user) return res.status(400).send({ error: 'Email invalid.' });

    const foundUser = await User.findOne({ user });
    if (!foundUser) return res.status(404).send({ error: 'Contul nu a fost gasit.' });
    if (foundUser.authProvider !== 'local') {
      return res.status(400).send({ error: 'Acest cont nu foloseste autentificare locala.' });
    }
    if (foundUser.emailVerified !== false) {
      return res.status(400).send({ error: 'Emailul este deja verificat.' });
    }

    const lastSentAt = foundUser.emailVerification?.lastSentAt
      ? new Date(foundUser.emailVerification.lastSentAt).getTime()
      : 0;
    const elapsed = Date.now() - lastSentAt;
    const cooldownMs = EMAIL_OTP_COOLDOWN_SECONDS * 1000;
    if (lastSentAt && elapsed < cooldownMs) {
      const retryAfter = Math.ceil((cooldownMs - elapsed) / 1000);
      return res.status(429).send({
        error: `Poti solicita un nou cod peste ${retryAfter} secunde.`,
        retryAfter,
      });
    }

    const otp = generateEmailOtp();
    foundUser.emailVerification = {
      otpHash: hashEmailOtp(user, otp),
      otpExpiresAt: new Date(Date.now() + EMAIL_OTP_TTL_MINUTES * 60 * 1000),
      lastSentAt: new Date(),
      verifyAttempts: 0,
    };
    await foundUser.save();

    const sent = await sendEmailVerificationOtp(user, otp);
    if (!sent) {
      return res.status(500).send({ error: 'Nu am putut retrimite codul OTP.' });
    }

    return res.send({ success: true, message: 'Cod OTP retrimis pe email.' });
  } catch (error) {
    return res.status(500).send({ error: 'Server error' });
  }
});

app.post('/api/auth/request-password-reset', async (req, res) => {
  try {
    const user = normalizeEmail(req.body?.user);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!user || !emailRegex.test(user)) {
      return res.status(400).send({ error: 'Adresa de email este obligatorie si trebuie sa fie valida.' });
    }

    const foundUser = await User.findOne({ user });
    if (!foundUser) {
      return res.send({
        success: true,
        message: 'Daca exista un cont cu acest email, am trimis codul OTP pentru resetare.',
      });
    }

    if (foundUser.authProvider === 'google' && !foundUser.pass) {
      return res.status(400).send({
        error: 'Acest cont foloseste autentificarea Google. Conecteaza-te cu Google.',
        code: 'GOOGLE_AUTH_ACCOUNT',
      });
    }

    const nowMs = Date.now();
    const resetData = foundUser.passwordReset || {};
    const lastSentMs = resetData.lastSentAt ? new Date(resetData.lastSentAt).getTime() : 0;
    const cooldownMs = PASSWORD_RESET_OTP_COOLDOWN_SECONDS * 1000;
    if (lastSentMs && nowMs - lastSentMs < cooldownMs) {
      const retryInSeconds = Math.max(1, Math.ceil((cooldownMs - (nowMs - lastSentMs)) / 1000));
      return res.status(429).send({
        error: `Te rugam sa astepti ${retryInSeconds} secunde inainte sa ceri un cod nou.`,
        code: 'OTP_COOLDOWN',
        retryInSeconds,
      });
    }

    const otp = generateEmailOtp();
    const otpHash = hashEmailOtp(user, otp);
    foundUser.passwordReset = {
      otpHash,
      otpExpiresAt: new Date(nowMs + PASSWORD_RESET_OTP_TTL_MINUTES * 60 * 1000),
      lastSentAt: new Date(nowMs),
      verifyAttempts: 0,
      requestedAt: new Date(nowMs),
      lastResetAt: resetData.lastResetAt,
    };
    await foundUser.save();

    const sent = await sendPasswordResetOtp(foundUser.user, otp, getUserDisplayName(foundUser));
    if (!sent) {
      return res.status(500).send({ error: 'Nu am putut trimite emailul de resetare. Incearca din nou.' });
    }

    return res.send({
      success: true,
      message: 'Am trimis codul OTP pentru resetarea parolei.',
    });
  } catch (error) {
    return res.status(500).send({ error: 'Server error' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const user = normalizeEmail(req.body?.user);
    const otp = String(req.body?.otp || '').trim();
    const newPassword = String(req.body?.newPassword || '');
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!user || !emailRegex.test(user)) {
      return res.status(400).send({ error: 'Adresa de email este invalida.' });
    }
    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).send({ error: 'Cod OTP invalid.' });
    }
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).send({ error: 'Parola trebuie sa aiba minim 6 caractere.' });
    }

    const foundUser = await User.findOne({ user });
    if (!foundUser) return res.status(404).send({ error: 'Contul nu a fost gasit.' });
    if (foundUser.authProvider === 'google' && !foundUser.pass) {
      return res.status(400).send({ error: 'Acest cont foloseste autentificarea Google.' });
    }

    const resetData = foundUser.passwordReset || {};
    if (!resetData.otpHash || !resetData.otpExpiresAt) {
      return res.status(400).send({ error: 'Nu exista OTP activ pentru resetare. Solicita un cod nou.' });
    }
    if (new Date(resetData.otpExpiresAt).getTime() < Date.now()) {
      foundUser.passwordReset = {
        ...resetData,
        otpHash: undefined,
        otpExpiresAt: undefined,
      };
      await foundUser.save();
      return res.status(400).send({ error: 'Codul OTP a expirat. Solicita un cod nou.' });
    }

    const attempts = Number(resetData.verifyAttempts || 0);
    if (attempts >= PASSWORD_RESET_OTP_MAX_ATTEMPTS) {
      return res.status(429).send({
        error: 'Ai depasit numarul maxim de incercari. Solicita un cod nou.',
        code: 'OTP_MAX_ATTEMPTS',
      });
    }

    const incomingHash = hashEmailOtp(user, otp);
    if (incomingHash !== resetData.otpHash) {
      foundUser.passwordReset = { ...resetData, verifyAttempts: attempts + 1 };
      await foundUser.save();
      return res.status(400).send({ error: 'Cod OTP incorect.', code: 'OTP_INVALID' });
    }

    const salt = await bcrypt.genSalt(10);
    foundUser.pass = await bcrypt.hash(newPassword, salt);
    foundUser.passwordReset = {
      otpHash: undefined,
      otpExpiresAt: undefined,
      lastSentAt: undefined,
      verifyAttempts: 0,
      requestedAt: undefined,
      lastResetAt: new Date(),
    };
    await foundUser.save();

    await pushUserNotification(foundUser._id, {
      title: 'Parola schimbata',
      message: 'Parola contului a fost schimbata cu succes. Daca nu ai facut tu aceasta actiune, schimba parola imediat.',
      priority: 'high',
      createdBy: 'Sistem',
      createdByRole: 'system',
    });

    try {
      const requestIp = String(req.headers['x-forwarded-for'] || '')
        .split(',')[0]
        .trim() || req.socket?.remoteAddress || '';
      const requestUserAgent = String(req.headers['user-agent'] || '');
      await emailNotifications.sendPasswordChangedEmail({
        email: foundUser.user,
        name: getUserDisplayName(foundUser),
        changedAt: new Date(),
        ip: requestIp,
        userAgent: requestUserAgent,
      });
    } catch (emailError) {
      console.error('[EMAIL] Password changed email failed:', emailError);
    }

    return res.send({
      success: true,
      message: 'Parola a fost resetata cu succes. Te poti autentifica.',
    });
  } catch (error) {
    return res.status(500).send({ error: 'Server error' });
  }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const currentPassword = String(req.body?.currentPassword || '');
    const newPassword = String(req.body?.newPassword || '');

    if (!currentPassword) {
      return res.status(400).send({ error: 'Parola curenta este obligatorie.' });
    }
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).send({ error: 'Parola noua trebuie sa aiba minim 6 caractere.' });
    }

    const foundUser = await User.findById(req.user.userId);
    if (!foundUser) return res.status(404).send({ error: 'Contul nu a fost gasit.' });

    if (foundUser.authProvider === 'google' && !foundUser.pass) {
      return res.status(400).send({
        error: 'Acest cont foloseste autentificarea Google. Foloseste resetare prin email.',
        code: 'GOOGLE_AUTH_ACCOUNT',
      });
    }

    const passwordMatches = await bcrypt.compare(currentPassword, String(foundUser.pass || ''));
    if (!passwordMatches) {
      return res.status(400).send({ error: 'Parola curenta este incorecta.' });
    }

    const salt = await bcrypt.genSalt(10);
    foundUser.pass = await bcrypt.hash(newPassword, salt);
    foundUser.passwordReset = {
      otpHash: undefined,
      otpExpiresAt: undefined,
      lastSentAt: undefined,
      verifyAttempts: 0,
      requestedAt: undefined,
      lastResetAt: new Date(),
    };
    await foundUser.save();

    await pushUserNotification(foundUser._id, {
      title: 'Parola schimbata',
      message: 'Parola contului a fost schimbata din panoul Account. Daca nu ai facut tu aceasta actiune, schimba parola imediat.',
      priority: 'high',
      createdBy: 'Sistem',
      createdByRole: 'system',
    });

    try {
      const requestIp = String(req.headers['x-forwarded-for'] || '')
        .split(',')[0]
        .trim() || req.socket?.remoteAddress || '';
      const requestUserAgent = String(req.headers['user-agent'] || '');
      await emailNotifications.sendPasswordChangedEmail({
        email: foundUser.user,
        name: getUserDisplayName(foundUser),
        changedAt: new Date(),
        ip: requestIp,
        userAgent: requestUserAgent,
      });
    } catch (emailError) {
      console.error('[EMAIL] Account change-password email failed:', emailError);
    }

    return res.send({
      success: true,
      message: 'Parola a fost schimbata cu succes.',
    });
  } catch (error) {
    return res.status(500).send({ error: 'Server error' });
  }
});

app.post('/api/auth/request-email-change', authenticateToken, async (req, res) => {
  try {
    const newEmail = normalizeEmail(req.body?.newEmail);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!newEmail || !emailRegex.test(newEmail)) {
      return res.status(400).send({ error: 'Adresa de email noua este invalida.' });
    }

    const foundUser = await User.findById(req.user.userId);
    if (!foundUser) return res.status(404).send({ error: 'Contul nu a fost gasit.' });

    const currentEmail = normalizeEmail(foundUser.user || foundUser.profile?.email || '');
    if (newEmail === currentEmail) {
      return res.status(400).send({ error: 'Noul email este identic cu emailul actual.' });
    }

    const existingEmailOwner = await User.findOne({
      user: newEmail,
      _id: { $ne: foundUser._id },
    });
    if (existingEmailOwner) {
      return res.status(400).send({ error: 'Exista deja un cont cu acest email.' });
    }

    const changeData = foundUser.emailChange || {};
    const lastSentMs = changeData.lastSentAt ? new Date(changeData.lastSentAt).getTime() : 0;
    const cooldownMs = EMAIL_OTP_COOLDOWN_SECONDS * 1000;
    if (lastSentMs && Date.now() - lastSentMs < cooldownMs) {
      const retryInSeconds = Math.max(1, Math.ceil((cooldownMs - (Date.now() - lastSentMs)) / 1000));
      return res.status(429).send({
        error: `Te rugam sa astepti ${retryInSeconds} secunde inainte sa ceri un cod nou.`,
        code: 'OTP_COOLDOWN',
        retryInSeconds,
      });
    }

    const otp = generateEmailOtp();
    foundUser.emailChange = {
      pendingEmail: newEmail,
      otpHash: hashEmailOtp(newEmail, otp),
      otpExpiresAt: new Date(Date.now() + EMAIL_OTP_TTL_MINUTES * 60 * 1000),
      lastSentAt: new Date(),
      verifyAttempts: 0,
      requestedAt: new Date(),
      confirmedAt: changeData.confirmedAt,
    };
    await foundUser.save();

    const sent = await sendEmailVerificationOtp(newEmail, otp);
    if (!sent) {
      return res.status(500).send({ error: 'Nu am putut trimite codul OTP pe noul email.' });
    }

    return res.send({
      success: true,
      pendingEmail: newEmail,
      message: 'Am trimis codul OTP pe noua adresa de email.',
    });
  } catch (error) {
    return res.status(500).send({ error: 'Server error' });
  }
});

app.post('/api/auth/confirm-email-change', authenticateToken, async (req, res) => {
  try {
    const otp = String(req.body?.otp || '').trim();
    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).send({ error: 'Cod OTP invalid.' });
    }

    const foundUser = await User.findById(req.user.userId);
    if (!foundUser) return res.status(404).send({ error: 'Contul nu a fost gasit.' });

    const changeData = foundUser.emailChange || {};
    const pendingEmail = normalizeEmail(changeData.pendingEmail || '');
    if (!pendingEmail || !changeData.otpHash || !changeData.otpExpiresAt) {
      return res.status(400).send({ error: 'Nu exista o schimbare de email in asteptare.' });
    }

    if (new Date(changeData.otpExpiresAt).getTime() < Date.now()) {
      foundUser.emailChange = {
        ...changeData,
        otpHash: undefined,
        otpExpiresAt: undefined,
      };
      await foundUser.save();
      return res.status(400).send({ error: 'Codul OTP a expirat. Solicita un cod nou.' });
    }

    const attempts = Number(changeData.verifyAttempts || 0);
    if (attempts >= EMAIL_OTP_MAX_ATTEMPTS) {
      return res.status(429).send({
        error: 'Ai depasit numarul maxim de incercari. Solicita un cod nou.',
        code: 'OTP_MAX_ATTEMPTS',
      });
    }

    const incomingHash = hashEmailOtp(pendingEmail, otp);
    if (incomingHash !== changeData.otpHash) {
      foundUser.emailChange = { ...changeData, verifyAttempts: attempts + 1 };
      await foundUser.save();
      return res.status(400).send({ error: 'Cod OTP incorect.', code: 'OTP_INVALID' });
    }

    const existingEmailOwner = await User.findOne({
      user: pendingEmail,
      _id: { $ne: foundUser._id },
    });
    if (existingEmailOwner) {
      return res.status(400).send({ error: 'Emailul a fost deja folosit de alt cont.' });
    }

    const oldEmail = normalizeEmail(foundUser.user || '');
    foundUser.user = pendingEmail;
    foundUser.emailVerified = true;
    foundUser.profile = {
      ...(foundUser.profile?.toObject ? foundUser.profile.toObject() : foundUser.profile || {}),
      email: pendingEmail,
    };
    foundUser.emailChange = {
      pendingEmail: undefined,
      otpHash: undefined,
      otpExpiresAt: undefined,
      lastSentAt: undefined,
      verifyAttempts: 0,
      requestedAt: undefined,
      confirmedAt: new Date(),
    };
    await foundUser.save();

    await pushUserNotification(foundUser._id, {
      title: 'Email actualizat',
      message: `Emailul contului a fost schimbat din ${oldEmail || 'email vechi'} in ${pendingEmail}.`,
      priority: 'high',
      createdBy: 'Sistem',
      createdByRole: 'system',
    });

    if (EMAIL_WELCOME_ENABLED) {
      try {
        await emailNotifications.sendVerificationSuccessEmail({
          email: pendingEmail,
          name: getUserDisplayName(foundUser),
        });
      } catch (emailError) {
        console.error('[EMAIL] Email-change verification email failed:', emailError);
      }
    }

    return res.send({
      success: true,
      email: pendingEmail,
      message: 'Emailul contului a fost actualizat cu succes.',
    });
  } catch (error) {
    return res.status(500).send({ error: 'Server error' });
  }
});

app.post('/api/auth/verify-email-otp', async (req, res) => {
  try {
    const user = normalizeEmail(req.body?.user);
    const otp = String(req.body?.otp || '').trim();
    if (!user || !/^\d{6}$/.test(otp)) {
      return res.status(400).send({ error: 'Cod OTP invalid.' });
    }

    const foundUser = await User.findOne({ user });
    if (!foundUser) return res.status(404).send({ error: 'Contul nu a fost gasit.' });
    if (foundUser.authProvider !== 'local') {
      return res.status(400).send({ error: 'Acest cont nu foloseste verificare OTP pe email.' });
    }
    if (foundUser.emailVerified === true) {
      return res.send({ success: true, alreadyVerified: true });
    }

    const verification = foundUser.emailVerification || {};
    if (!verification.otpHash || !verification.otpExpiresAt) {
      return res.status(400).send({ error: 'Nu exista OTP activ. Solicita un cod nou.' });
    }
    if (new Date(verification.otpExpiresAt).getTime() < Date.now()) {
      foundUser.emailVerification = { ...verification, otpHash: undefined, otpExpiresAt: undefined };
      await foundUser.save();
      return res.status(400).send({ error: 'Codul OTP a expirat. Solicita un cod nou.' });
    }

    const attempts = Number(verification.verifyAttempts || 0);
    if (attempts >= EMAIL_OTP_MAX_ATTEMPTS) {
      return res.status(429).send({
        error: 'Ai depasit numarul maxim de incercari. Solicita un cod nou.',
        code: 'OTP_MAX_ATTEMPTS',
      });
    }

    const incomingHash = hashEmailOtp(user, otp);
    if (incomingHash !== verification.otpHash) {
      foundUser.emailVerification = { ...verification, verifyAttempts: attempts + 1 };
      await foundUser.save();
      return res.status(400).send({ error: 'Cod OTP incorect.', code: 'OTP_INVALID' });
    }

    foundUser.emailVerified = true;
    foundUser.emailVerification = {
      otpHash: undefined,
      otpExpiresAt: undefined,
      lastSentAt: undefined,
      verifyAttempts: 0,
    };
    await foundUser.save();

    if (EMAIL_WELCOME_ENABLED) {
      try {
        await emailNotifications.sendVerificationSuccessEmail({
          email: foundUser.user,
          name: getUserDisplayName(foundUser),
        });
      } catch (emailError) {
        console.error('[EMAIL] Verification success email failed:', emailError);
      }
    }

    const config = await getConfig();
    const limits = config.limits[foundUser.plan || 'free'];
    const premiumPrice = config.pricing.premiumPrice;
    const basicPrice = config.pricing.basicPrice;
    const isCompleted = isEventCompleted(foundUser.profile.weddingDate);
    const token = jwt.sign(
      { userId: foundUser._id, plan: foundUser.plan || 'free' },
      JWT_SECRET,
      { expiresIn: '7d' },
    );

    if (EMAIL_LOGIN_ALERT_ENABLED) {
      const requestIp = String(req.headers['x-forwarded-for'] || '')
        .split(',')[0]
        .trim() || req.socket?.remoteAddress || '';
      const requestUserAgent = String(req.headers['user-agent'] || '');
      const nowMs = Date.now();
      const cooldownMs = EMAIL_LOGIN_ALERT_COOLDOWN_MINUTES * 60 * 1000;
      const lastSentMs = foundUser.loginAlerts?.lastSentAt
        ? new Date(foundUser.loginAlerts.lastSentAt).getTime()
        : 0;
      const accountAgeGraceMs = EMAIL_LOGIN_ALERT_SKIP_NEW_ACCOUNT_MINUTES * 60 * 1000;
      const createdAtMs = foundUser.createdAt ? new Date(foundUser.createdAt).getTime() : 0;
      const isFreshAccount = !!createdAtMs && nowMs - createdAtMs < accountAgeGraceMs;
      const hasPreviousAlert = Boolean(foundUser.loginAlerts?.lastSentAt);
      const ipChanged = requestIp && requestIp !== String(foundUser.loginAlerts?.lastIp || '');
      const uaChanged = requestUserAgent && requestUserAgent !== String(foundUser.loginAlerts?.lastUserAgent || '');
      const cooldownPassed = !lastSentMs || nowMs - lastSentMs >= cooldownMs;
      const skipBecauseNewAccount = isFreshAccount && !hasPreviousAlert;
      const shouldSendAlert = !skipBecauseNewAccount && (cooldownPassed || ipChanged || uaChanged);

      if (shouldSendAlert) {
        try {
          const sent = await emailNotifications.sendLoginAlertEmail({
            email: foundUser.user,
            ip: requestIp,
            userAgent: requestUserAgent,
            loginAt: new Date(nowMs),
          });

          if (sent) {
            await User.findByIdAndUpdate(foundUser._id, {
              $set: {
                loginAlerts: {
                  lastSentAt: new Date(nowMs),
                  lastIp: requestIp,
                  lastUserAgent: requestUserAgent,
                },
              },
            });
          }
        } catch (emailError) {
          console.error('[EMAIL] Login alert failed:', emailError);
        }
      }
    }

    const loginAt = new Date();
    await User.findByIdAndUpdate(foundUser._id, {
      $set: {
        'activity.lastLoginAt': loginAt,
        'activity.lastActionAt': loginAt,
        'activity.lastActionLabel': 'Autentificare in aplicatie',
      },
    });

    return res.send({
      success: true,
      user: foundUser.user,
      userId: foundUser._id,
      plan: foundUser.plan || 'free',
      isAdmin: foundUser.isAdmin,
      profile: foundUser.profile,
      payments: foundUser.payments || [],
      archivedEvents: foundUser.archivedEvents || [],
      limits,
      basicPrice,
      premiumPrice,
      pricing: config.pricing,
      isEventCompleted: isCompleted,
      token,
    });
  } catch (error) {
    return res.status(500).send({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const user = normalizeEmail(req.body?.user);
    const { pass } = req.body || {};
    const foundUser = await User.findOne({ user });
    if (!foundUser) return res.status(401).send({ error: 'Datele de autentificare sunt incorecte.' });

    if (foundUser.authProvider === 'google' && !foundUser.pass) {
      return res.status(401).send({ error: 'Acest cont foloseste autentificarea Google.' });
    }
    if (foundUser.authProvider === 'local' && foundUser.emailVerified === false) {
      return res.status(403).send({
        error: 'Emailul nu este verificat. Introdu codul OTP trimis pe email.',
        code: 'EMAIL_NOT_VERIFIED',
        email: foundUser.user,
      });
    }

    const isMatch = await bcrypt.compare(pass, foundUser.pass);
    if (!isMatch) return res.status(401).send({ error: 'Datele de autentificare sunt incorecte.' });

    const config = await getConfig();
    const limits = config.limits[foundUser.plan || 'free'];
    const premiumPrice = config.pricing.premiumPrice;
    const basicPrice = config.pricing.basicPrice;
    const isCompleted = isEventCompleted(foundUser.profile.weddingDate);
    const token = jwt.sign(
      { userId: foundUser._id, plan: foundUser.plan || 'free' },
      JWT_SECRET,
      { expiresIn: '7d' },
    );

    const loginAt = new Date();
    await User.findByIdAndUpdate(foundUser._id, {
      $set: {
        'activity.lastLoginAt': loginAt,
        'activity.lastActionAt': loginAt,
        'activity.lastActionLabel': 'Autentificare in aplicatie',
      },
    });

    return res.send({
      success: true,
      user: foundUser.user,
      userId: foundUser._id,
      plan: foundUser.plan || 'free',
      isAdmin: foundUser.isAdmin,
      profile: foundUser.profile,
      payments: foundUser.payments || [],
      archivedEvents: foundUser.archivedEvents || [],
      limits,
      basicPrice,
      premiumPrice,
      pricing: config.pricing,
      isEventCompleted: isCompleted,
      token,
    });
  } catch (error) {
    return res.status(500).send({ error: 'Server error' });
  }
});

app.post('/api/_legacy/register-disabled', async (req, res) => {
  try {
    const user = normalizeEmail(req.body?.user);
    const { pass } = req.body; 
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!user || !emailRegex.test(user)) {
        return res.status(400).send({ error: 'Adresa de email este obligatorie și trebuie să fie validă.' });
    }
    if (!pass || pass.length < 6) {
        return res.status(400).send({ error: 'Parola trebuie să aibă minim 6 caractere.' });
    }

    const existingUser = await User.findOne({ user });
    if (existingUser) return res.status(400).send({ error: 'Există deja un cont cu acest email.' });
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(pass, salt);
    
    const isFirstUser = (await User.countDocuments({})) === 0;

    const newUser = new User({
      user, 
      pass: hashedPassword, 
      authProvider: 'local',
      plan: 'free',
      isAdmin: isFirstUser, 
      profile: { 
          email: user,
          isSetupComplete: false, // Forces setup modal on first login
          // Default values are empty now until setup
          eventType: 'wedding',
          guestEstimate: 150 
      }
    });
    
    await newUser.save();
    const token = jwt.sign({ userId: newUser._id, plan: 'free' }, JWT_SECRET, { expiresIn: '7d' });
    res.send({ success: true, userId: newUser._id, plan: 'free', token });
  } catch (error) { res.status(500).send({ error: 'Server error' }); }
});

app.post('/api/_legacy/login-disabled', async (req, res) => {
  try {
    const { user, pass } = req.body;
    const foundUser = await User.findOne({ user });
    if (!foundUser) return res.status(401).send({ error: 'Datele de autentificare sunt incorecte.' });
    
    if (foundUser.authProvider === 'google' && !foundUser.pass) {
        return res.status(401).send({ error: 'Acest cont folosește autentificarea Google.' });
    }

    const isMatch = await bcrypt.compare(pass, foundUser.pass);
    if (isMatch) {
      const config = await getConfig();
      const limits = config.limits[foundUser.plan || 'free'];
      const premiumPrice = config.pricing.premiumPrice;
      const basicPrice = config.pricing.basicPrice;
      const isCompleted = isEventCompleted(foundUser.profile.weddingDate);

      const token = jwt.sign({ userId: foundUser._id, plan: foundUser.plan || 'free' }, JWT_SECRET, { expiresIn: '7d' });
      res.send({ 
        success: true, user: foundUser.user, userId: foundUser._id, 
        plan: foundUser.plan || 'free', 
        isAdmin: foundUser.isAdmin, 
        profile: foundUser.profile, 
        payments: foundUser.payments || [],
        archivedEvents: foundUser.archivedEvents || [], 
        limits: limits, 
        basicPrice,
        premiumPrice,
        pricing: config.pricing, 
        isEventCompleted: isCompleted, 
        token: token 
      });
    } else { res.status(401).send({ error: 'Datele de autentificare sunt incorecte.' }); }
  } catch (error) { res.status(500).send({ error: 'Server error' }); }
});

// AUTH GOOGLE
app.post('/api/google-auth', async (req, res) => {
    try {
        const { token } = req.body;
        
        let ticket;
        try {
            if (GOOGLE_CLIENT_ID.includes("PASTE_YOUR")) {
                 return res.status(500).send({ error: 'Server configuration error: GOOGLE_CLIENT_ID missing' });
            }

            ticket = await googleClient.verifyIdToken({
                idToken: token,
                audience: GOOGLE_CLIENT_ID,
            });
        } catch (e) {
            console.error("Google verify error:", e);
            return res.status(400).send({ error: 'Invalid Google Token' });
        }

        const payload = ticket.getPayload();
        const { email, sub, name, picture } = payload;

        let user = await User.findOne({ user: email });

        if (!user) {
            const isFirstUser = (await User.countDocuments({})) === 0;
            const [firstName, ...lastNameParts] = (name || '').split(' ');
            
            user = new User({
                user: email,
                authProvider: 'google',
                googleId: sub,
                plan: 'free',
                isAdmin: isFirstUser,
                profile: {
                    email: email,
                    isSetupComplete: false,
                    firstName: firstName || '',
                    lastName: lastNameParts.join(' ') || '',
                    avatarUrl: picture,
                    eventType: 'wedding',
                    guestEstimate: 150
                }
            });
            await user.save();
        } else {
            if (user.authProvider === 'local' && !user.googleId) {
                user.googleId = sub;
            }
            if (!user.profile.avatarUrl && picture) {
                user.profile.avatarUrl = picture;
                await user.save();
            }
        }

        const config = await getConfig();
        const limits = config.limits[user.plan || 'free'];
        const premiumPrice = config.pricing.premiumPrice;
        const basicPrice = config.pricing.basicPrice;
        const isCompleted = isEventCompleted(user.profile.weddingDate);

        const sessionToken = jwt.sign({ userId: user._id, plan: user.plan || 'free' }, JWT_SECRET, { expiresIn: '7d' });

        const loginAt = new Date();
        await User.findByIdAndUpdate(user._id, {
            $set: {
                'activity.lastLoginAt': loginAt,
                'activity.lastActionAt': loginAt,
                'activity.lastActionLabel': 'Autentificare in aplicatie',
            },
        });
        
        res.send({ 
            success: true, 
            user: user.user, 
            userId: user._id, 
            plan: user.plan || 'free', 
            isAdmin: user.isAdmin, 
            profile: user.profile, 
            payments: user.payments || [],
            archivedEvents: user.archivedEvents || [],
            limits: limits, 
            basicPrice,
            premiumPrice,
            pricing: config.pricing, 
            isEventCompleted: isCompleted,
            token: sessionToken 
        });

    } catch (e) {
        console.error(e);
        res.status(500).send({ error: 'Authentication failed' });
    }
});


// ── Helper: filtreaza undefined/null din profil inainte de merge ─────────────
// Previne ca 'undefined' explicit din profilul userului sa suprascrie defaults
function cleanProfileForMerge(profile) {
    if (!profile) return {};
    return Object.fromEntries(
        Object.entries(profile).filter(([, v]) => v !== null && v !== undefined)
    );
}

app.get('/api/user/me', authenticateToken, async (req, res) => {
  try {
    let user = await User.findById(req.user.userId);
    if (!user) return res.status(404).send({ error: 'User not found' });

    // ── Auto-inject default blocks if user has none ───────────────────────
    // Handles: existing users, accounts created before default blocks existed
    if (user.profile?.isSetupComplete) {
      let sections = [];
      try { sections = JSON.parse(user.profile?.customSections || '[]'); } catch {}
      if (!sections.length) {
        await User.findByIdAndUpdate(req.user.userId, {
          $set: { 'profile.customSections': WEDDING_DEFAULT_BLOCKS }
        });
        user = await User.findById(req.user.userId); // re-fetch with updated data
      }
    }
    
    const config = await getConfig();
    const limits = config.limits[user.plan || 'free'];
    const premiumPrice = config.pricing.premiumPrice;
    const basicPrice = config.pricing.basicPrice;
    const isCompleted = isEventCompleted(user.profile.weddingDate);

    // ── Merge template defaults < user profile ────────────────────────────
    // Citim template-ul ales din project
    const userProject = await Project.findOne({ ownerId: user._id });
    const templateId = userProject?.selectedTemplate || 'castle-magic';
    const tplDoc = await TemplateDefaults.findOne({ templateId });
    let mergedProfile = user.profile || {};
    if (tplDoc) {
        const tplRaw = tplDoc.toObject();
        delete tplRaw._id; delete tplRaw.__v; delete tplRaw.templateId; delete tplRaw.updatedAt;
        // Null/empty string din defaults nu suprascriu profilul userului
        const cleanDefaults = Object.fromEntries(
            Object.entries(tplRaw).filter(([, v]) => v !== null && v !== undefined && v !== '')
        );
        // user profile are prioritate: daca userul a setat ceva, ramane ce a setat el
        mergedProfile = { ...cleanDefaults, ...cleanProfileForMerge(user.profile?.toObject ? user.profile.toObject() : user.profile) };
    }

    res.send({ 
        success: true, 
        user: user.user, 
        userId: user._id, 
        plan: user.plan || 'free', 
        isAdmin: user.isAdmin, 
        profile: mergedProfile, 
        payments: user.payments || [],
        archivedEvents: user.archivedEvents || [],
        limits: limits, 
        basicPrice,
        premiumPrice,
        pricing: config.pricing,
        isEventCompleted: isCompleted
    });
  } catch (error) {
    res.status(500).send({ error: 'Server error' });
  }
});

app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId, 'notifications activity');
    if (!user) return res.status(404).send({ error: 'User not found' });

    const notifications = Array.isArray(user.notifications) ? [...user.notifications] : [];
    notifications.sort((a, b) => new Date(b?.createdAt || 0).getTime() - new Date(a?.createdAt || 0).getTime());

    const unreadCount = notifications.filter((n) => n?.isRead !== true).length;
    res.send({
      success: true,
      notifications,
      unreadCount,
      activity: user.activity || {},
    });
  } catch (e) {
    res.status(500).send({ error: e.message });
  }
});

app.post('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notificationId = String(req.params.id || '').trim();
    if (!notificationId) return res.status(400).send({ error: 'Notification id lipsa.' });

    await User.findOneAndUpdate(
      { _id: req.user.userId, 'notifications._id': notificationId },
      {
        $set: {
          'notifications.$.isRead': true,
          'notifications.$.readAt': new Date(),
        },
      }
    );
    res.send({ success: true });
  } catch (e) {
    res.status(500).send({ error: e.message });
  }
});

app.post('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    await User.findByIdAndUpdate(req.user.userId, {
      $set: {
        'notifications.$[n].isRead': true,
        'notifications.$[n].readAt': now,
      },
    }, {
      arrayFilters: [{ 'n.isRead': { $ne: true } }],
    });
    res.send({ success: true });
  } catch (e) {
    res.status(500).send({ error: e.message });
  }
});

// --- NEW ROUTE: SETUP EVENT (ONBOARDING) ---
app.post('/api/user/setup-event', authenticateToken, async (req, res) => {
    try {
        const {
            eventType,
            weddingDate,
            eventName,
            eventRole,
            contactName,
            phone,
            shippingCounty,
            shippingCity,
            shippingStreet,
            shippingNumber,
            shippingBlock,
            shippingStaircase,
            shippingFloor,
            shippingApartment,
            shippingPostalCode,
            shippingLandmark,
            shippingCountry,
            firstName,
            lastName,
        } = req.body || {};
        
        if (!eventType || !weddingDate) {
            return res.status(400).send({ error: 'Tipul și data evenimentului sunt obligatorii.' });
        }

        if (isPastOrInvalidEventDate(weddingDate)) {
            return res.status(400).send({ error: 'Data evenimentului nu poate fi in trecut.' });
        }

        const normalizedPhone = normalizeRoPhone(phone || '');
        if (!eventRole || !contactName || !normalizedPhone) {
            return res.status(400).send({ error: 'Rolul, numele si telefonul sunt obligatorii.' });
        }
        if (!isValidRoPhone(normalizedPhone)) {
            return res.status(400).send({ error: 'Numarul de telefon este invalid.' });
        }

        const normalizedShipping = normalizeShippingAddressParts({
          shippingCounty,
          shippingCity,
          shippingStreet,
          shippingNumber,
          shippingBlock,
          shippingStaircase,
          shippingFloor,
          shippingApartment,
          shippingPostalCode,
          shippingLandmark,
          shippingCountry: shippingCountry || 'Romania',
        });
        const hasAnyShippingPayload = [
          shippingCounty,
          shippingCity,
          shippingStreet,
          shippingNumber,
          shippingBlock,
          shippingStaircase,
          shippingFloor,
          shippingApartment,
          shippingPostalCode,
          shippingLandmark,
          shippingCountry,
        ]
          .map((v) => sanitizeInputText(v || ''))
          .some(Boolean);
        if (hasAnyShippingPayload && !isShippingAddressComplete(normalizedShipping)) {
          return res.status(400).send({
            error: 'Adresa principala este incompleta. Completeaza judet, localitate, strada, numar si cod postal.',
          });
        }

        const contactNameNorm = normalizeText(contactName);
        const [firstNameFromContact, ...lastNameFromContactParts] = contactNameNorm.split(/\s+/);
        const finalFirstName = normalizeText(firstName) || firstNameFromContact || '';
        const finalLastName = normalizeText(lastName) || lastNameFromContactParts.join(' ');

        // Default blocks & data per event type
        const defaultData = {};

        if (eventType === 'wedding') {
            // ── Demo names & texts (matches the template preview) ──────────
            defaultData["profile.partner1Name"] = "Camila";
            defaultData["profile.partner2Name"] = "Sebastián";
            defaultData["profile.welcomeText"] = "Ne bucurăm să anunțăm căsătoria noastră și dorim să împărțim cu tine acest moment special.";
            defaultData["profile.celebrationText"] = "nunții noastre";
            defaultData["profile.showWelcomeText"] = true;
            defaultData["profile.showCelebrationText"] = true;
            defaultData["profile.showCountdown"] = true;
            defaultData["profile.showRsvpButton"] = true;
            defaultData["profile.rsvpButtonText"] = "Confirmă Prezența";
            defaultData["profile.godparents"] = JSON.stringify([
                { godfather: "Prenume Naș", godmother: "Prenume Nașă" }
            ]);
            defaultData["profile.parents"] = JSON.stringify({
                p1_father: "Tatăl Miresei",
                p1_mother: "Mama Miresei",
                p2_father: "Tatăl Mirelui",
                p2_mother: "Mama Mirelui",
                others: []
            });
            defaultData["profile.customSections"] = WEDDING_DEFAULT_BLOCKS;
        }

        const now = new Date();
        const setupSet = {
            "profile.eventName": eventName || `Eveniment ${eventType}`,
            "profile.eventType": eventType,
            "profile.weddingDate": new Date(weddingDate),
            "profile.isSetupComplete": true,
            "profile.eventRole": normalizeText(eventRole),
            "profile.firstName": finalFirstName,
            "profile.lastName": finalLastName,
            "profile.phone": normalizedPhone,
            "activity.lastProfileUpdateAt": now,
            "activity.lastActionAt": now,
            "activity.lastActionLabel": "Onboarding completat",
            ...defaultData
        };
        if (hasAnyShippingPayload && isShippingAddressComplete(normalizedShipping)) {
            setupSet["profile.address"] = composeShippingAddressLine(normalizedShipping);
            setupSet["profile.city"] = normalizedShipping.shippingCity;
            setupSet["profile.county"] = normalizedShipping.shippingCounty;
            setupSet["profile.country"] = normalizedShipping.shippingCountry || 'Romania';
            setupSet["profile.shippingCounty"] = normalizedShipping.shippingCounty;
            setupSet["profile.shippingCity"] = normalizedShipping.shippingCity;
            setupSet["profile.shippingStreet"] = normalizedShipping.shippingStreet;
            setupSet["profile.shippingNumber"] = normalizedShipping.shippingNumber;
            setupSet["profile.shippingBlock"] = normalizedShipping.shippingBlock;
            setupSet["profile.shippingStaircase"] = normalizedShipping.shippingStaircase;
            setupSet["profile.shippingFloor"] = normalizedShipping.shippingFloor;
            setupSet["profile.shippingApartment"] = normalizedShipping.shippingApartment;
            setupSet["profile.shippingPostalCode"] = normalizedShipping.shippingPostalCode;
            setupSet["profile.shippingLandmark"] = normalizedShipping.shippingLandmark;
            setupSet["profile.shippingCountry"] = normalizedShipping.shippingCountry || 'Romania';
        }

        const updatedUser = await User.findByIdAndUpdate(req.user.userId, {
            $set: setupSet
        }, { new: true });

        if (EMAIL_WELCOME_ENABLED && updatedUser) {
            try {
                await emailNotifications.sendWelcomeEmail({
                    email: updatedUser.user,
                    name: getUserDisplayName(updatedUser),
                    eventType: updatedUser.profile?.eventType || eventType,
                    eventName: updatedUser.profile?.eventName || eventName || '',
                    eventDate: updatedUser.profile?.weddingDate || new Date(weddingDate),
                });
            } catch (emailError) {
                console.error('[EMAIL] Event setup welcome email failed:', emailError);
            }
        }

        res.send({ success: true, profile: updatedUser?.profile || null });
    } catch (e) {
        console.error(e);
        res.status(500).send({ error: 'Setup failed.' });
    }
});

// --- NEW ROUTE: ARCHIVE AND RESET EVENT ---
app.post('/api/user/archive-event', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const user = await User.findById(userId);
        
        if (!user) return res.status(404).send({ error: 'User not found' });

        // Use lean() to get plain JS objects for archiving
        const project = await Project.findOne({ ownerId: userId }).lean();
        const guests = await Guest.find({ ownerId: userId }).lean();
        
        // 1. SAVE FULL SNAPSHOT
        const snapshot = new ArchivedSnapshot({
            ownerId: userId,
            data: {
                profile: user.profile,
                project: project || {}, // Ensure project is at least empty object
                guests: guests || []
            }
        });
        await snapshot.save();

        const archiveEntry = {
            snapshotId: snapshot._id.toString(), // Store reference as string explicitly
            eventName: user.profile.eventName,
            eventType: user.profile.eventType,
            eventDate: user.profile.weddingDate,
            archivedAt: new Date(),
            guestCount: guests ? guests.length : 0,
            totalSpent: project ? project.totalBudget : 0
        };

        // 2. DELETE OLD DATA
        await Guest.deleteMany({ ownerId: userId });
        await Project.deleteMany({ ownerId: userId });

        const resetProfile = {
            ...user.profile.toObject(),
            isSetupComplete: false, // Forces user to setup again!
            eventName: "", // Reset name
            weddingDate: null, 
            eventTime: "",
            locationName: "",
            locationAddress: "",
            venueWazeLink: "",
            timeline: "",
            budget: 0,
            inviteSlug: ""
        };

        await User.findByIdAndUpdate(userId, {
            $push: { archivedEvents: archiveEntry },
            $set: { 
                profile: resetProfile,
                plan: 'free' 
            }
        });

        res.send({ success: true, message: 'Eveniment arhivat. Puteți începe planificarea noului eveniment.' });

    } catch (e) {
        console.error(e);
        res.status(500).send({ error: 'Nu am putut arhiva evenimentul.' });
    }
});

// --- NEW ROUTE: GET ARCHIVED SNAPSHOT ---
app.get('/api/archived-event/:snapshotId', authenticateToken, async (req, res) => {
    try {
        const snapshot = await ArchivedSnapshot.findOne({ _id: req.params.snapshotId, ownerId: req.user.userId });
        if (!snapshot) return res.status(404).send({ error: 'Arhivă inexistentă.' });
        res.send(snapshot.data);
    } catch (e) {
        console.error(e);
        res.status(500).send({ error: 'Server error' });
    }
});

// --- DATA MODIFICATION ROUTES (Protected by ensureActiveEvent) ---

// ─── Media upload — folder ierarhic per user ─────────────────────────────────
//
//  Structură: uploads/{userId[0..1]}/{userId[2..3]}/{userId}/{timestamp}-{random}.jpg
//  Exemplu:   uploads/5f/3a/5f3ab2c1d.../1700000000-x7k2.jpg
//
//  De ce sharding pe 2 nivele:
//  - 100k useri × 8 poze = 800k fișiere total
//  - Cu 2 nivele hex (256 × 256 = 65536 bucket-uri) → avg 12 fișiere/folder
//  - readdir() rapid, backup selectiv, cleanup la ștergere cont

const UPLOADS_ROOT = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_ROOT)) fs.mkdirSync(UPLOADS_ROOT, { recursive: true });

// Returnează path-ul directorului pentru un userId și îl creează dacă nu există
function userUploadDir(userId) {
    const uid   = String(userId);
    const shard = uid.slice(-4, -2) || 'xx';  // ultimele 4 chars → 2 nivele
    const shard2= uid.slice(-2) || 'xx';
    const dir   = path.join(UPLOADS_ROOT, shard, shard2, uid);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    return dir;
}

// Multer storage cu destination dinamic per user
const storage = multer.diskStorage({
    destination: (req, _file, cb) => {
        try {
            const dir = userUploadDir(req.user.userId);
            cb(null, dir);
        } catch (e) { cb(e, ''); }
    },
    filename: (_req, file, cb) => {
        const ext  = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '') || '.jpg';
        const name = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`;
        cb(null, name);
    },
});

const upload = multer({
    storage,
    limits: { fileSize: 32 * 1024 * 1024 }, // 32 MB — audio files pot fi mai mari
    fileFilter: (_req, file, cb) => {
        const allowed = [
            'image/jpeg','image/png','image/webp','image/gif','image/avif',
            'audio/mpeg','audio/mp3','audio/wav','audio/ogg','audio/aac',
            'audio/x-m4a','audio/mp4','video/mp4',
        ];
        if (allowed.includes(file.mimetype)) cb(null, true);
        else cb(new Error('Format neacceptat. Sunt permise imagini si fisiere audio.'));
    },
});

// Serve uploads ca static — cu cache headers agresive (imaginile nu se schimbă)
app.use('/uploads', express.static(UPLOADS_ROOT, {
    maxAge: '365d',          // browser cache 1 an
    immutable: true,         // nu re-validează niciodată
    etag: true,
}));

// POST /api/upload — un singur fișier, returnează { url, size }
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Niciun fișier primit.' });
        const uid   = String(req.user.userId);
        const shard = uid.slice(-4, -2) || 'xx';
        const shard2= uid.slice(-2) || 'xx';
        const url   = `/uploads/${shard}/${shard2}/${uid}/${req.file.filename}`;
        res.json({ url, size: req.file.size });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// POST /api/download-yt-audio — descarcă audio de pe YouTube cu @ybd-project/ytdl-core
app.post('/api/download-yt-audio', authenticateToken, async (req, res) => {
    const { url } = req.body;
    if (!url || typeof url !== 'string') return res.status(400).json({ error: 'URL lipsă.' });

    const ytIdMatch = url.match(/(?:v=|youtu\.be\/|embed\/|shorts\/)([a-zA-Z0-9_-]{11})/);
    if (!ytIdMatch) return res.status(400).json({ error: 'URL YouTube invalid.' });
    const cleanUrl = `https://www.youtube.com/watch?v=${ytIdMatch[1]}`;

    try {
        const { YtdlCore, toPipeableStream } = await import('@ybd-project/ytdl-core');

        // 1. Metadata
        let title = '', author = '';
        try {
            const info = await YtdlCore.getInfo(cleanUrl);
            title  = info.videoDetails?.title || '';
            author = info.videoDetails?.author || info.videoDetails?.ownerChannelName || '';
            console.log('[ytdl] downloading:', title, 'by', author);
        } catch (e) {
            console.warn('[ytdl] metadata warn:', e.message);
        }

        // 2. Salvează audio
        const uid   = String(req.user.userId);
        const dir   = userUploadDir(uid);
        const fname = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}.webm`;
        const fpath = path.join(dir, fname);

        await new Promise((resolve, reject) => {
            // toPipeableStream primește URL + opțiuni, returnează un stream Node.js
            const pipeable = toPipeableStream(cleanUrl, {
                filter: 'audioonly',
                quality: 'highestaudio',
            });
            const file = fs.createWriteStream(fpath);
            pipeable.pipe(file);
            pipeable.on('error', reject);
            file.on('finish', resolve);
            file.on('error', reject);
        });

        const shard   = uid.slice(-4, -2) || 'xx';
        const shard2  = uid.slice(-2)     || 'xx';
        const fileUrl = `/uploads/${shard}/${shard2}/${uid}/${fname}`;

        console.log('[ytdl] saved:', fileUrl);
        res.json({ url: fileUrl, title, author });

    } catch (e) {
        console.error('[ytdl] error:', e.message);
        res.status(500).json({ error: 'Nu s-a putut descărca melodia. ' + e.message });
    }
});

// DELETE /api/upload — șterge un fișier; verifică că aparține userului autentificat
app.delete('/api/upload', authenticateToken, (req, res) => {
    try {
        const { url } = req.body;
        if (!url || typeof url !== 'string') return res.status(400).json({ error: 'URL lipsă.' });

        // Reconstruiește path-ul absolut și verifică că e în folderul userului
        const uid      = String(req.user.userId);
        const shard    = uid.slice(-4, -2) || 'xx';
        const shard2   = uid.slice(-2) || 'xx';
        const userDir  = path.join(UPLOADS_ROOT, shard, shard2, uid);
        const filename = path.basename(url);                          // extrage doar numele
        const filepath = path.join(userDir, filename);

        // Security: path traversal check — filepath trebuie să fie în userDir
        if (!filepath.startsWith(userDir + path.sep)) {
            return res.status(403).json({ error: 'Acces interzis.' });
        }

        if (fs.existsSync(filepath)) fs.unlinkSync(filepath);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// DELETE /api/upload/all/:userId — șterge tot folderul unui user (la ștergere cont)
app.delete('/api/upload/all/:userId', authenticateToken, (req, res) => {
    try {
        // Doar adminul sau userul însuși poate face asta
        if (req.user.userId !== req.params.userId && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Acces interzis.' });
        }
        const uid    = String(req.params.userId);
        const shard  = uid.slice(-4, -2) || 'xx';
        const shard2 = uid.slice(-2) || 'xx';
        const dir    = path.join(UPLOADS_ROOT, shard, shard2, uid);
        if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
        res.json({ success: true, message: `Folderul userului ${uid} a fost șters.` });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/profile', authenticateToken, ensureActiveEvent, async (req, res) => {
    try {
        const { profile } = req.body;
        if (profile && typeof profile === 'object') {
            if (Object.prototype.hasOwnProperty.call(profile, 'phone')) {
                const nextPhone = normalizeRoPhone(profile.phone || '');
                if (nextPhone && !isValidRoPhone(nextPhone)) {
                    return res.status(400).send({ error: 'Numarul de telefon trebuie sa fie valid.' });
                }
                profile.phone = nextPhone;
            }
            if (Object.prototype.hasOwnProperty.call(profile, 'weddingDate')) {
                const rawWeddingDate =
                    typeof profile.weddingDate === 'string'
                        ? profile.weddingDate.trim()
                        : profile.weddingDate;
                if (isPastOrInvalidEventDate(rawWeddingDate)) {
                    return res.status(400).send({ error: 'Data evenimentului nu poate fi in trecut.' });
                }
            }

            const shippingKeys = [
              'shippingCounty',
              'shippingCity',
              'shippingStreet',
              'shippingNumber',
              'shippingBlock',
              'shippingStaircase',
              'shippingFloor',
              'shippingApartment',
              'shippingPostalCode',
              'shippingLandmark',
              'shippingCountry',
            ];
            const hasShippingPayload = shippingKeys.some((k) =>
              Object.prototype.hasOwnProperty.call(profile, k),
            );
            if (hasShippingPayload) {
              const normalizedShipping = normalizeShippingAddressParts({
                shippingCounty: profile.shippingCounty,
                shippingCity: profile.shippingCity,
                shippingStreet: profile.shippingStreet,
                shippingNumber: profile.shippingNumber,
                shippingBlock: profile.shippingBlock,
                shippingStaircase: profile.shippingStaircase,
                shippingFloor: profile.shippingFloor,
                shippingApartment: profile.shippingApartment,
                shippingPostalCode: profile.shippingPostalCode,
                shippingLandmark: profile.shippingLandmark,
                shippingCountry: profile.shippingCountry || profile.country || 'Romania',
              });
              if (!isShippingAddressComplete(normalizedShipping)) {
                return res.status(400).send({
                  error:
                    'Adresa principala este incompleta. Completeaza judet, localitate, strada, numar si cod postal (6 cifre).',
                });
              }
              profile.shippingCounty = normalizedShipping.shippingCounty;
              profile.shippingCity = normalizedShipping.shippingCity;
              profile.shippingStreet = normalizedShipping.shippingStreet;
              profile.shippingNumber = normalizedShipping.shippingNumber;
              profile.shippingBlock = normalizedShipping.shippingBlock;
              profile.shippingStaircase = normalizedShipping.shippingStaircase;
              profile.shippingFloor = normalizedShipping.shippingFloor;
              profile.shippingApartment = normalizedShipping.shippingApartment;
              profile.shippingPostalCode = normalizedShipping.shippingPostalCode;
              profile.shippingLandmark = normalizedShipping.shippingLandmark;
              profile.shippingCountry = normalizedShipping.shippingCountry;

              // backward compatibility fields reused elsewhere in app
              profile.address = composeShippingAddressLine(normalizedShipping);
              profile.city = normalizedShipping.shippingCity;
              profile.county = normalizedShipping.shippingCounty;
              profile.country = normalizedShipping.shippingCountry;
            }

            const billingCity = String(profile.billingCity || '').trim();
            const billingCountry = normalizeCountryName(profile.billingCountry || 'Romania');
            const billingType = String(profile.billingType || '').trim() === 'company' ? 'company' : 'individual';
            const normalizedSector = normalizeSectorName(profile.billingSector || '');
            if (isBucharestCity(billingCity)) {
                profile.billingCounty = 'Bucuresti';
                if (billingType === 'company') {
                    profile.billingSector = normalizedSector;
                }
            } else if (profile.billingSector) {
                profile.billingSector = normalizedSector;
            }
            profile.billingCountry = billingCountry;
        }

        // Safety: strip any leftover base64 imageData from blocks
        if (profile?.customSections) {
            try {
                const blocks = JSON.parse(profile.customSections);
                profile.customSections = JSON.stringify(
                    blocks.map((b) => {
                        if (b.type === 'photo' && b.imageData?.startsWith('data:')) {
                            const { imageData, ...rest } = b;
                            return rest;
                        }
                        return b;
                    })
                );
            } catch { /* invalid JSON, leave as-is */ }
        }

        // Convert to dot-notation $set so Mongoose strict mode never strips any field
        const $setPayload = {};
        for (const [key, val] of Object.entries(profile)) {
            $setPayload[`profile.${key}`] = val;
        }
        const now = new Date();
        $setPayload['activity.lastProfileUpdateAt'] = now;
        $setPayload['activity.lastActionAt'] = now;
        $setPayload['activity.lastActionLabel'] = 'Setari profil actualizate';

        await User.findOneAndUpdate(
            { _id: req.user.userId },
            { $set: $setPayload },
            { new: true, strict: false }
        );
        res.send({ success: true });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.post('/api/project', authenticateToken, ensureActiveEvent, async (req, res) => {
    const { elements, tasks, budget, totalBudget, selectedTemplate } = req.body;
    const now = new Date();
    const updateData = { updatedAt: now, elements, tasks, budget, totalBudget, selectedTemplate };
    await Project.findOneAndUpdate({ ownerId: req.user.userId }, updateData, { new: true, upsert: true });
    await User.findByIdAndUpdate(req.user.userId, {
      $set: {
        'activity.lastProjectUpdateAt': now,
        'activity.lastActionAt': now,
        'activity.lastActionLabel': 'Proiect actualizat',
      },
    });
    res.send({ success: true });
});

app.post('/api/guests', authenticateToken, ensureActiveEvent, async (req, res) => {
    const { name, type } = req.body;
    
    const user = await User.findById(req.user.userId);
    const config = await getConfig();
    const limits = config.limits[user.plan || 'free'];
    const currentCount = await Guest.countDocuments({ ownerId: req.user.userId });
    
    if (currentCount >= limits.maxGuests) {
        return res.status(403).send({ error: 'Limit reached.' });
    }

    const newGuest = new Guest({ 
        ownerId: req.user.userId, 
        name, 
        type, 
        token: generateToken(), 
        status: 'pending',
        isSent: false,
        source: 'manual'
    });
    await newGuest.save();
    const now = new Date();
    await User.findByIdAndUpdate(req.user.userId, {
      $set: {
        'activity.lastGuestsUpdateAt': now,
        'activity.lastActionAt': now,
        'activity.lastActionLabel': 'Lista invitati actualizata',
      },
    });
    res.send(newGuest);
});

app.put('/api/guests/:id/sent', authenticateToken, ensureActiveEvent, async (req, res) => {
    try {
        const { isSent } = req.body;
        const guest = await Guest.findOneAndUpdate(
            { _id: req.params.id, ownerId: req.user.userId },
            { isSent: isSent },
            { new: true }
        );
        const now = new Date();
        await User.findByIdAndUpdate(req.user.userId, {
          $set: {
            'activity.lastGuestsUpdateAt': now,
            'activity.lastActionAt': now,
            'activity.lastActionLabel': 'Status invitat actualizat',
          },
        });
        res.send(guest);
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.delete('/api/guests/:id', authenticateToken, ensureActiveEvent, async (req, res) => {
    await Guest.findByIdAndDelete(req.params.id);
    const now = new Date();
    await User.findByIdAndUpdate(req.user.userId, {
      $set: {
        'activity.lastGuestsUpdateAt': now,
        'activity.lastActionAt': now,
        'activity.lastActionLabel': 'Invitat sters',
      },
    });
    res.send({ success: true });
});

// --- READ-ONLY ROUTES (Always allowed even if completed) ---

app.get('/api/project/:userId', authenticateToken, async (req, res) => {
    const project = await Project.findOne({ ownerId: req.user.userId });
    res.send(project || {});
});

app.get('/api/guests/:userId', authenticateToken, async (req, res) => {
    const guests = await Guest.find({ ownerId: req.user.userId });
    res.send(guests);
});

// --- PUBLIC ROUTES & ADMIN ---
// ... (Keeping existing Admin and Public routes same)

app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({});
        const basicUsers = await User.countDocuments({ plan: 'basic' });
        const premiumUsers = await User.countDocuments({ plan: 'premium' });
        const freeUsers = await User.countDocuments({ $or: [{ plan: 'free' }, { plan: { $exists: false } }] });
        const paidUsers = basicUsers + premiumUsers;
        
        const usersWithPayments = await User.find({ "payments.0": { "$exists": true } });
        let totalRevenue = 0;
        let recentPayments = [];

        usersWithPayments.forEach(u => {
            u.payments.forEach(p => {
                if (p.status === 'Paid') {
                    totalRevenue += p.amount || 0;
                    recentPayments.push({
                        userEmail: u.user,
                        amount: p.amount,
                        date: p.date,
                        invoiceId: p.invoiceId
                    });
                }
            });
        });

        recentPayments.sort((a, b) => new Date(b.date) - new Date(a.date));

        res.send({
            totalUsers,
            basicUsers,
            premiumUsers,
            paidUsers,
            freeUsers,
            totalRevenue,
            recentPayments: recentPayments.slice(0, 10)
        });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find({}, '-pass'); 
        res.send(users);
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.post('/api/admin/users/:id/notify', authenticateAdmin, async (req, res) => {
    try {
        const targetUserId = String(req.params.id || '').trim();
        const title = String(req.body?.title || '').trim();
        const message = String(req.body?.message || '').trim();
        const priority = String(req.body?.priority || '').toLowerCase() === 'high' ? 'high' : 'normal';

        if (!targetUserId) return res.status(400).send({ error: 'User id lipsa.' });
        if (!title || !message) {
            return res.status(400).send({ error: 'Titlul si mesajul sunt obligatorii.' });
        }

        const [targetUser, adminUser] = await Promise.all([
            User.findById(targetUserId),
            User.findById(req.user.userId),
        ]);
        if (!targetUser) return res.status(404).send({ error: 'Utilizatorul tinta nu exista.' });

        const adminName = adminUser
            ? `${adminUser.profile?.firstName || ''} ${adminUser.profile?.lastName || ''}`.trim() || adminUser.user
            : 'Admin';

        await pushUserNotification(targetUser._id, {
            title,
            message,
            priority,
            createdBy: adminName,
            createdByRole: 'admin',
        });

        let emailSent = false;
        if (priority === 'high' && targetUser.user) {
            try {
                emailSent = await emailNotifications.sendAdminNotificationEmail({
                    email: targetUser.user,
                    name: getUserDisplayName(targetUser),
                    title,
                    message,
                    priority,
                });
            } catch (emailError) {
                console.error('[EMAIL] Admin notification failed:', emailError);
            }
        }

        res.send({ success: true, emailSent });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

// --- ADMIN TEMPLATE ROUTES ---
app.get('/api/admin/templates', authenticateAdmin, async (req, res) => {
    try {
        const templates = await InvitationTemplate.find({});
        res.send(templates);
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.post('/api/admin/templates', authenticateAdmin, async (req, res) => {
    try {
        const templateData = req.body;
        const template = new InvitationTemplate(templateData);
        await template.save();
        res.send(template);
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.put('/api/admin/templates/:id', authenticateAdmin, async (req, res) => {
    try {
        const template = await InvitationTemplate.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.send(template);
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.delete('/api/admin/templates/:id', authenticateAdmin, async (req, res) => {
    try {
        await InvitationTemplate.findByIdAndDelete(req.params.id);
        res.send({ success: true });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

// --- PUBLIC TEMPLATE ROUTES ---
app.get('/api/templates', async (req, res) => {
    try {
        const templates = await InvitationTemplate.find({ isActive: true });
        res.send(templates);
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.put('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const { plan, user, profile, emailVerified } = req.body || {};
        const updatePayload = {};

        if (typeof plan === 'string') updatePayload.plan = plan;
        if (typeof user === 'string') updatePayload.user = user.trim().toLowerCase();
        if (typeof emailVerified === 'boolean') updatePayload.emailVerified = emailVerified;

        if (profile && typeof profile === 'object') {
            const nextProfile = { ...profile };
            if (typeof nextProfile.weddingDate === 'string') {
                const rawDate = nextProfile.weddingDate.trim();
                nextProfile.weddingDate = rawDate ? new Date(rawDate) : undefined;
            }
            if (isPastOrInvalidEventDate(nextProfile.weddingDate)) {
                return res.status(400).send({ error: 'Data evenimentului nu poate fi in trecut.' });
            }
            updatePayload.profile = nextProfile;
        }

        await User.findByIdAndUpdate(req.params.id, { $set: updatePayload });
        res.send({ success: true });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        await User.findByIdAndDelete(userId);
        await Project.deleteMany({ ownerId: userId });
        await Guest.deleteMany({ ownerId: userId });
        res.send({ success: true });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.get('/api/admin/email/status', authenticateAdmin, async (req, res) => {
    res.send({
        success: true,
        enabled: emailNotifications.isEnabled,
        provider: 'resend',
        from: RESEND_FROM,
        loginAlertsEnabled: EMAIL_LOGIN_ALERT_ENABLED,
        loginAlertCooldownMinutes: EMAIL_LOGIN_ALERT_COOLDOWN_MINUTES,
        loginAlertSkipNewAccountMinutes: EMAIL_LOGIN_ALERT_SKIP_NEW_ACCOUNT_MINUTES,
        welcomeEnabled: EMAIL_WELCOME_ENABLED,
    });
});

app.post('/api/admin/email/send-test', authenticateAdmin, async (req, res) => {
    try {
        const { userId, type } = req.body || {};
        if (!userId || !type) {
            return res.status(400).send({ error: 'userId si type sunt obligatorii.' });
        }

        const user = await User.findById(userId);
        if (!user) return res.status(404).send({ error: 'Utilizator inexistent.' });
        const email = normalizeEmail(user.user);
        if (!email) return res.status(400).send({ error: 'Utilizator fara email valid.' });

        let sent = false;
        if (type === 'welcome') {
            sent = await emailNotifications.sendWelcomeEmail({
                email,
                name: getUserDisplayName(user),
                eventType: user.profile?.eventType || 'wedding',
                eventName: user.profile?.eventName || '',
                eventDate: user.profile?.weddingDate,
            });
        } else if (type === 'login_alert') {
            sent = await emailNotifications.sendLoginAlertEmail({
                email,
                ip: req.socket?.remoteAddress || 'admin-trigger',
                userAgent: req.headers['user-agent'] || 'admin-panel',
                loginAt: new Date(),
            });
        } else if (type === 'reminder') {
            sent = await emailNotifications.sendEventReminderEmail({
                email,
                name: getUserDisplayName(user),
                eventType: user.profile?.eventType || 'wedding',
                eventName: user.profile?.eventName || '',
                eventDate: user.profile?.weddingDate,
                daysLeft: computeDaysUntilDate(user.profile?.weddingDate),
            });
        } else {
            return res.status(400).send({ error: 'Tip email invalid. Foloseste welcome, login_alert sau reminder.' });
        }

        if (!sent) {
            return res.status(500).send({ error: 'Emailul nu a putut fi trimis.' });
        }

        return res.send({ success: true });
    } catch (e) {
        return res.status(500).send({ error: e.message });
    }
});

app.post('/api/admin/email/send-reminders', authenticateAdmin, async (req, res) => {
    try {
        const daysAhead = Math.max(0, Math.min(30, Number(req.body?.daysAhead ?? 3)));
        const onlyVerified = req.body?.onlyVerified !== false;
        const limit = Math.max(1, Math.min(500, Number(req.body?.limit ?? 200)));

        const now = new Date();
        now.setHours(0, 0, 0, 0);
        const maxDate = new Date(now);
        maxDate.setDate(maxDate.getDate() + daysAhead);
        maxDate.setHours(23, 59, 59, 999);

        const query = {
            'profile.weddingDate': { $gte: now, $lte: maxDate },
        };
        if (onlyVerified) query.emailVerified = { $ne: false };

        const users = await User.find(query, 'user profile emailVerified').limit(limit);

        let sentCount = 0;
        let failedCount = 0;
        const skipped = [];

        for (const user of users) {
            const email = normalizeEmail(user.user);
            const eventDate = user.profile?.weddingDate;
            const daysLeft = computeDaysUntilDate(eventDate);

            if (!email || !eventDate || daysLeft === null || daysLeft < 0) {
                skipped.push(email || String(user._id));
                continue;
            }

            const sent = await emailNotifications.sendEventReminderEmail({
                email,
                name: getUserDisplayName(user),
                eventType: user.profile?.eventType || 'wedding',
                eventName: user.profile?.eventName || '',
                eventDate,
                daysLeft,
            });

            if (sent) sentCount += 1;
            else failedCount += 1;
        }

        return res.send({
            success: true,
            scanned: users.length,
            sent: sentCount,
            failed: failedCount,
            skipped: skipped.length,
        });
    } catch (e) {
        return res.status(500).send({ error: e.message });
    }
});

app.post('/api/admin/cancel-sub', authenticateAdmin, async (req, res) => {
    try {
        const { userId } = req.body;
        await User.findByIdAndUpdate(userId, { plan: 'free' });
        res.send({ success: true });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.get('/api/admin/config', authenticateAdmin, async (req, res) => {
    try {
        const config = await getConfig();
        res.send(config);
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.put('/api/admin/config', authenticateAdmin, async (req, res) => {
    try {
        const current = await getConfig();
        const incomingLimits = req.body?.limits || {};
        const incomingPricing = req.body?.pricing || {};
        const limits = {
          free: incomingLimits.free || current.limits.free,
          basic: incomingLimits.basic || current.limits.basic,
          premium: incomingLimits.premium || current.limits.premium,
        };
        const pricing = {
          currency: incomingPricing.currency || current.pricing.currency || 'ron',
          basicPrice: Number.isFinite(Number(incomingPricing.basicPrice))
            ? Number(incomingPricing.basicPrice)
            : Number(current.pricing.basicPrice || 1900),
          premiumPrice: Number.isFinite(Number(incomingPricing.premiumPrice))
            ? Number(incomingPricing.premiumPrice)
            : Number(current.pricing.premiumPrice || 4900),
          oldPrice: Number.isFinite(Number(incomingPricing.oldPrice))
            ? Number(incomingPricing.oldPrice)
            : Number(current.pricing.oldPrice || 0),
        };
        await SystemConfig.findOneAndUpdate({ key: 'global_config' }, { limits, pricing }, { upsert: true });
        res.send({ success: true });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

// ── Services coming soon flag — public read ───────────────────────────────────
app.get('/api/config/services-coming-soon', async (req, res) => {
    try {
        const config = await getConfig();
        res.json({ enabled: !!config?.servicesComingSoon });
    } catch (e) { res.status(500).send({ error: e.message }); }
});

// ── Services coming soon flag — admin toggle ──────────────────────────────────
app.put('/api/admin/config/services-coming-soon', authenticateAdmin, async (req, res) => {
    try {
        const { enabled } = req.body;
        await SystemConfig.findOneAndUpdate(
            { key: 'global_config' },
            { $set: { servicesComingSoon: !!enabled } },
            { upsert: true }
        );
        res.json({ enabled: !!enabled });
    } catch (e) { res.status(500).send({ error: e.message }); }
});


// ── Template Defaults — public read (folosit de DashboardApp la incarcare) ──
app.get('/api/config/template-defaults/:templateId', async (req, res) => {
    try {
        const doc = await TemplateDefaults.findOne({ templateId: req.params.templateId });
        if (!doc) return res.json({});
        const { _id, __v, updatedAt, templateId, ...rest } = doc.toObject();
        // strip null values so frontend ?? fallback works correctly
        const clean = Object.fromEntries(Object.entries(rest).filter(([, v]) => v !== null && v !== undefined));
        res.json(clean);
    } catch (e) { res.status(500).send({ error: e.message }); }
});

// ── Template Defaults — admin read ───────────────────────────────────────────
// DELETE /api/admin/config/template-defaults/:templateId — resetează config + șterge fișierele
app.delete('/api/admin/config/template-defaults/:templateId', authenticateAdmin, async (req, res) => {
    try {
        const { templateId } = req.params;
        const doc = await TemplateDefaults.findOne({ templateId });
        if (!doc) return res.json({ ok: true, deleted: 0 });

        const toDelete = [];

        // Colectăm toate URL-urile de fișiere
        if (doc.heroBgImage)       toDelete.push(doc.heroBgImage);
        if (doc.heroBgImageMobile) toDelete.push(doc.heroBgImageMobile);
        if (doc.themeImages) {
            for (const theme of Object.values(doc.themeImages)) {
                if (theme && typeof theme === 'object') {
                    if (theme.desktop) toDelete.push(theme.desktop);
                    if (theme.mobile)  toDelete.push(theme.mobile);
                }
            }
        }
        // introVariants — cleanup fișiere regal
        if (doc.introVariants) {
            for (const variant of Object.values(doc.introVariants)) {
                if (variant && typeof variant === 'object') {
                    if (variant.desktop) toDelete.push(variant.desktop);
                    if (variant.mobile)  toDelete.push(variant.mobile);
                }
            }
        }

        // Ștergem fișierele fizice
        let deletedFiles = 0;
        for (const url of toDelete) {
            if (!url || !url.startsWith('/uploads/')) continue;
            try {
                const filepath = path.join(UPLOADS_ROOT, url.replace('/uploads/', ''));
                if (fs.existsSync(filepath)) {
                    fs.unlinkSync(filepath);
                    deletedFiles++;
                }
            } catch (e) { console.error('Could not delete file:', url, e.message); }
        }

        // Ștergem documentul din DB
        await TemplateDefaults.deleteOne({ templateId });

        res.json({ ok: true, deleted: deletedFiles, totalUrls: toDelete.length });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/admin/config/template-defaults/:templateId', authenticateAdmin, async (req, res) => {
    try {
        const doc = await TemplateDefaults.findOne({ templateId: req.params.templateId });
        if (!doc) return res.json({});
        const { _id, __v, templateId, ...rest } = doc.toObject();
        res.json(rest);
    } catch (e) { res.status(500).send({ error: e.message }); }
});

// ── Template Defaults — admin write ──────────────────────────────────────────
app.post('/api/admin/config/template-defaults/:templateId', authenticateAdmin, async (req, res) => {
    try {
        const { templateId } = req.params;
        const patch = { ...req.body, templateId, updatedAt: new Date() };
        const collectTemplateUploadUrls = (doc) => {
            const urls = new Set();
            if (!doc || typeof doc !== 'object') return urls;

            const pushIfUpload = (val) => {
                if (typeof val === 'string' && val.startsWith('/uploads/')) urls.add(val);
            };

            pushIfUpload(doc.heroBgImage);
            pushIfUpload(doc.heroBgImageMobile);
            pushIfUpload(doc.videoUrl);

            if (doc.themeImages && typeof doc.themeImages === 'object') {
                for (const imgs of Object.values(doc.themeImages)) {
                    if (!imgs || typeof imgs !== 'object') continue;
                    pushIfUpload(imgs.desktop);
                    pushIfUpload(imgs.mobile);
                }
            }

            if (doc.introVariants && typeof doc.introVariants === 'object') {
                for (const variant of Object.values(doc.introVariants)) {
                    if (!variant || typeof variant !== 'object') continue;
                    pushIfUpload(variant.desktop);
                    pushIfUpload(variant.mobile);
                }
            }

            return urls;
        };

        const safeDeleteUploadByUrl = (url) => {
            if (typeof url !== 'string' || !url.startsWith('/uploads/')) return false;
            const relPath = url.replace(/^\/uploads\//, '');
            const absolute = path.resolve(UPLOADS_ROOT, relPath);
            const root = path.resolve(UPLOADS_ROOT) + path.sep;
            if (!absolute.startsWith(root)) return false;
            if (!fs.existsSync(absolute)) return false;
            fs.unlinkSync(absolute);
            return true;
        };

        const existing = await TemplateDefaults.findOne({ templateId });
        const beforeUrls = collectTemplateUploadUrls(existing?.toObject?.() || existing || {});

        // strip undefined/null for fields explicitly cleared
        await TemplateDefaults.findOneAndUpdate(
            { templateId },
            { $set: patch },
            { upsert: true, new: true, strict: false }
        );

        const updated = await TemplateDefaults.findOne({ templateId });
        const afterUrls = collectTemplateUploadUrls(updated?.toObject?.() || updated || {});
        for (const oldUrl of beforeUrls) {
            if (afterUrls.has(oldUrl)) continue;
            try { safeDeleteUploadByUrl(oldUrl); } catch {}
        }

        res.json({ success: true });
    } catch (e) { res.status(500).send({ error: e.message }); }
});

// ── Services Marketplace — public read ───────────────────────────────────────
app.get('/api/services', async (req, res) => {
    try {
        const services = await Service.find({ available: true }).sort({ featured: -1, createdAt: -1 });
        res.json(services);
    } catch (e) { res.status(500).send({ error: e.message }); }
});

// ── Services Marketplace — admin CRUD ────────────────────────────────────────
app.get('/api/admin/services', authenticateAdmin, async (req, res) => {
    try {
        const services = await Service.find().sort({ createdAt: -1 });
        res.json(services);
    } catch (e) { res.status(500).send({ error: e.message }); }
});

app.post('/api/admin/services', authenticateAdmin, async (req, res) => {
    try {
        const service = new Service(req.body);
        await service.save();
        res.status(201).json(service);
    } catch (e) { res.status(400).send({ error: e.message }); }
});

app.put('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
    try {
        const service = await Service.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!service) return res.status(404).send({ error: 'Not found' });
        res.json(service);
    } catch (e) { res.status(400).send({ error: e.message }); }
});

app.delete('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
    try {
        await Service.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).send({ error: e.message }); }
});

// ── Seed default services if collection is empty ──────────────────────────────
async function seedServices() {
    const count = await Service.countDocuments();
    if (count > 0) return;
    const defaults = [
        { name: 'Sweet Dreams Candy Bar', category: 'candybar', description: 'Candy bar de lux cu dulciuri artizanale, decoruri personalizate și setup complet pentru evenimentul tău. Include masă decorată, recipiente de sticlă, etichetare și livrare.', priceFrom: 1200, priceTo: 3500, priceUnit: 'total', location: 'București', phone: '0721 000 001', instagram: '@sweetdreams.ro', imageUrl: 'https://images.unsplash.com/photo-1558636508-e0db3814bd1d?w=600&q=80', rating: 4.9, reviewCount: 84, tags: ['lux','personalizat','livrare'], featured: true, available: true },
        { name: 'Formația Romantica', category: 'formatie', description: 'Formație completă cu 6 muzicieni, repertoriu variat: muzică populară, manele, internațional. Experiență de peste 15 ani în nunți și evenimente.', priceFrom: 3500, priceTo: 6000, priceUnit: 'total', location: 'București & împrejurimi', phone: '0745 000 002', imageUrl: 'https://images.unsplash.com/photo-1470225620780-dba8ba36b745?w=600&q=80', rating: 4.8, reviewCount: 127, tags: ['populară','manele','internațional'], featured: true, available: true },
        { name: 'DJ Alex Pro', category: 'dj', description: 'DJ profesionist cu echipament premium, lumini și sistem de sunet. Playlist personalizat, mixing live, experiență la peste 300 de nunți.', priceFrom: 1500, priceTo: 2500, priceUnit: 'total', location: 'Nationwide', phone: '0733 000 003', instagram: '@djAlexPro', imageUrl: 'https://images.unsplash.com/photo-1516450360452-9312f5e86fc7?w=600&q=80', rating: 4.7, reviewCount: 203, tags: ['lumini','mixing live','nationwide'], featured: false, available: true },
        { name: 'Atelier Floral Irina', category: 'florarie', description: 'Aranjamente florale pentru nunți: buchete mireasă, centrepiece-uri, arcuri florale, decoruri sală. Flori proaspete din import și locale.', priceFrom: 2000, priceUnit: 'total', location: 'Cluj-Napoca', phone: '0756 000 004', website: 'www.atelierfloral.ro', imageUrl: 'https://images.unsplash.com/photo-1487530811015-780de7c30f3a?w=600&q=80', rating: 5.0, reviewCount: 56, tags: ['buchete','aranjamente','arcuri'], featured: true, available: true },
        { name: 'Studio Lumina Foto', category: 'foto-video', description: 'Pachet complet foto + video pentru nuntă: 2 fotografi, 2 cameramani, album premium, clip cinematic 4K, drone, livrare în 60 zile.', priceFrom: 4500, priceTo: 8000, priceUnit: 'total', location: 'București', phone: '0766 000 005', website: 'www.studiolumina.ro', imageUrl: 'https://images.unsplash.com/photo-1606216794079-73f9c1f1a108?w=600&q=80', rating: 4.9, reviewCount: 91, tags: ['4K','drone','album premium'], featured: true, available: true },
        { name: 'Tort de Vis Cofetărie', category: 'cofetarie', description: 'Torturi de nuntă personalizate, desert table, cupcakes și prăjituri. Design unic creat împreună cu voi. Livrare și montaj inclus.', priceFrom: 800, priceTo: 3000, priceUnit: 'total', location: 'Iași', phone: '0722 000 006', imageUrl: 'https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=600&q=80', rating: 4.8, reviewCount: 142, tags: ['personalizat','livrare','desert table'], featured: false, available: true },
    ];
    // Folosim create() în loc de insertMany() — aplică schema defaults corect
    for (const d of defaults) await Service.create(d);
    console.log('✅ Seeded', defaults.length, 'default services');
}

// ── Fix documente vechi fără câmpul available ─────────────────────────────────
app.post('/api/admin/services/fix-available', authenticateAdmin, async (req, res) => {
    try {
        const result = await Service.updateMany(
            { available: { $exists: false } },
            { $set: { available: true } }
        );
        res.json({ fixed: result.modifiedCount });
    } catch (e) { res.status(500).send({ error: e.message }); }
});

// ── Force reseed ──────────────────────────────────────────────────────────────
app.post('/api/admin/services/reseed', authenticateAdmin, async (req, res) => {
    try {
        await Service.deleteMany({});
        await seedServices();
        const services = await Service.find();
        res.json({ seeded: services.length });
    } catch (e) { res.status(500).send({ error: e.message }); }
});



// ── Service Requests — public submit ─────────────────────────────────────────
app.post('/api/service-requests', authenticateToken, async (req, res) => {
    try {
        const { serviceId, serviceName, serviceCategory, name, email, phone, address, contactTime, budget, gdprAccepted, callApproved } = req.body;
        if (!name || !email || !phone || !serviceId) return res.status(400).send({ error: 'Câmpuri obligatorii lipsă.' });
        const req2 = new ServiceRequest({ serviceId, serviceName, serviceCategory, name, email, phone, address, contactTime, budget, gdprAccepted, callApproved });
        await req2.save();
        res.status(201).json(req2);
    } catch (e) { res.status(500).send({ error: e.message }); }
});

// ── Service Requests — user: own requests ────────────────────────────────────
app.get('/api/service-requests/mine', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).lean();
        if (!user) return res.status(404).send({ error: 'User not found' });
        const requests = await ServiceRequest.find({ email: user.profile?.email || '' }).sort({ createdAt: -1 });
        res.json(requests);
    } catch (e) { res.status(500).send({ error: e.message }); }
});

// ── Service Requests — admin: all ────────────────────────────────────────────
app.get('/api/admin/service-requests', authenticateAdmin, async (req, res) => {
    try {
        const requests = await ServiceRequest.find().sort({ createdAt: -1 });
        res.json(requests);
    } catch (e) { res.status(500).send({ error: e.message }); }
});

// ── Service Requests — admin: update status ───────────────────────────────────
app.put('/api/admin/service-requests/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status, notes } = req.body;
        const updated = await ServiceRequest.findByIdAndUpdate(req.params.id, { status, notes }, { new: true });
        if (!updated) return res.status(404).send({ error: 'Not found' });
        res.json(updated);
    } catch (e) { res.status(500).send({ error: e.message }); }
});

app.post('/api/upgrade', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { email, billing = {}, targetPlan: requestedPlanRaw } = req.body || {};
    
    const user = await User.findById(userId);
    if (!user) return res.status(404).send({ error: "Utilizator inexistent." });
    const clean = (value, max = 180) => String(value ?? '').trim().slice(0, max);
    const requestedPlan = normalizePlan(requestedPlanRaw || 'premium');
    if (requestedPlan === 'free') {
      return res.status(400).send({ error: "Planul ales este invalid." });
    }
    const currentPlan = normalizePlan(user.plan || 'free');

    const checkoutAddress = getCheckoutContactAndAddress({
      billing,
      profile: user.profile || {},
      emailFallback: email || user.user,
    });
    const { shippingAddress, profileShipping, addressSource } = checkoutAddress;
    const billingCountry = normalizeCountryName(shippingAddress.shippingCountry || 'Romania');
    const billingCity = clean(shippingAddress.shippingCity, 120);
    const billingCounty = clean(shippingAddress.shippingCounty, 120);
    const billingAddress = composeShippingAddressLine(shippingAddress);
    const billingEmail = clean(checkoutAddress.email);

    const billingType = clean(billing.type, 20) === 'company' ? 'company' : 'individual';
    const fallbackBillingName = clean(
      user.profile?.billingName ||
      [user.profile?.firstName, user.profile?.lastName].filter(Boolean).join(' ') ||
      user.profile?.partner1Name ||
      'Client',
      120
    );
    const contactFullName = `${checkoutAddress.firstName} ${checkoutAddress.lastName}`.trim();
    const billingName = clean(billing.name || contactFullName || fallbackBillingName, 120);
    const billingCompany = clean(billing.company || user.profile?.billingCompany, 160);
    const billingVatCodeInput = clean(billing.vatCode || user.profile?.billingVatCode, 64);
    const billingVatCode = normalizeBillingTaxCode({
      billingType,
      vatCode: billingVatCodeInput,
    });
    const billingRegNo = clean(billing.regNo || user.profile?.billingRegNo, 64);
    const billingSector = normalizeSectorName(clean(billing.sector || user.profile?.billingSector, 32));
    const billingPhone = clean(checkoutAddress.phone || user.profile?.billingPhone || user.profile?.phone, 40);

    if (!billingEmail || !billingEmail.includes('@')) {
        return res.status(400).send({ error: "Email-ul de facturare este obligatoriu." });
    }
    if (!checkoutAddress.firstName || !checkoutAddress.lastName) {
      return res.status(400).send({ error: "Completeaza prenumele si numele pentru checkout." });
    }
    if (!checkoutAddress.phone || !isValidRoPhone(checkoutAddress.phone)) {
      return res.status(400).send({ error: "Numarul de telefon este obligatoriu si trebuie sa fie valid." });
    }
    if (!isShippingAddressComplete(shippingAddress)) {
      return res.status(400).send({
        error:
          "Adresa de checkout este incompleta. Completeaza judet, localitate, strada, numar si cod postal.",
      });
    }
    if (!billingName) {
        return res.status(400).send({ error: "Numele de facturare este obligatoriu." });
    }
    if (billingType === 'company' && !billingCompany) {
        return res.status(400).send({ error: "Numele companiei este obligatoriu pentru facturare pe firma." });
    }
    if (billingType === 'company' && isBucharestCity(billingCity) && !billingSector) {
        return res.status(400).send({ error: "Pentru firme din Bucuresti, selecteaza sectorul." });
    }
    if (!billingAddress || !billingCity || !billingCountry || !billingCounty) {
      return res.status(400).send({ error: "Completeaza adresa, orasul, judetul si tara pentru facturare." });
    }

    const profileUpdateSet = {
      'profile.email': billingEmail,
      'profile.billingType': billingType,
      'profile.billingName': billingName,
      'profile.billingCompany': billingCompany,
      'profile.billingVatCode': billingVatCode,
      'profile.billingRegNo': billingRegNo,
      'profile.billingAddress': billingAddress,
      'profile.billingCity': billingCity,
      'profile.billingSector': billingSector,
      'profile.billingCounty': billingCounty,
      'profile.billingCountry': billingCountry,
      'profile.billingEmail': billingEmail,
      'profile.billingPhone': billingPhone,
      'profile.firstName': checkoutAddress.firstName || user.profile?.firstName || '',
      'profile.lastName': checkoutAddress.lastName || user.profile?.lastName || '',
      'profile.phone': billingPhone || user.profile?.phone || '',
    };
    if (isShippingAddressComplete(shippingAddress)) {
      profileUpdateSet['profile.address'] = billingAddress;
      profileUpdateSet['profile.city'] = shippingAddress.shippingCity;
      profileUpdateSet['profile.county'] = shippingAddress.shippingCounty;
      profileUpdateSet['profile.country'] = shippingAddress.shippingCountry || 'Romania';
      profileUpdateSet['profile.shippingCounty'] = shippingAddress.shippingCounty;
      profileUpdateSet['profile.shippingCity'] = shippingAddress.shippingCity;
      profileUpdateSet['profile.shippingStreet'] = shippingAddress.shippingStreet;
      profileUpdateSet['profile.shippingNumber'] = shippingAddress.shippingNumber;
      profileUpdateSet['profile.shippingBlock'] = shippingAddress.shippingBlock;
      profileUpdateSet['profile.shippingStaircase'] = shippingAddress.shippingStaircase;
      profileUpdateSet['profile.shippingFloor'] = shippingAddress.shippingFloor;
      profileUpdateSet['profile.shippingApartment'] = shippingAddress.shippingApartment;
      profileUpdateSet['profile.shippingPostalCode'] = shippingAddress.shippingPostalCode;
      profileUpdateSet['profile.shippingLandmark'] = shippingAddress.shippingLandmark;
      profileUpdateSet['profile.shippingCountry'] = shippingAddress.shippingCountry || 'Romania';
    }
    await User.findByIdAndUpdate(userId, {
      $set: profileUpdateSet,
    });

    const config = await getConfig();
    const planPriceMap = {
      basic: config.pricing.basicPrice,
      premium: config.pricing.premiumPrice,
    };
    const charge = getUpgradeCharge(planPriceMap, currentPlan, requestedPlan);
    if (!charge.ok) {
      return res.status(400).send({ error: charge.message });
    }
    const priceAmount = charge.payableAmount;
    const productName =
      charge.currentPlan === 'free'
        ? (requestedPlan === 'basic' ? 'Wedding Planner Basic' : 'Wedding Planner Premium')
        : `Upgrade Wedding Planner ${charge.currentPlan} -> ${requestedPlan}`;
    const productDescription =
      charge.currentPlan === 'free'
        ? 'Acces nelimitat la functii premium pe viata.'
        : `Diferenta de pret pentru upgrade ${charge.currentPlan} -> ${requestedPlan}.`;
    const metadataRaw = {
      currentPlan: charge.currentPlan,
      targetPlan: requestedPlan,
      currentPlanPrice: charge.currentPrice,
      targetPlanPrice: charge.targetPrice,
      payableAmount: charge.payableAmount,
      billingType,
      billingName,
      billingCompany,
      billingVatCode,
      billingRegNo,
      billingAddress,
      billingCity,
      billingSector,
      billingCounty,
      billingCountry,
      billingEmail,
      billingPhone,
      checkoutAddressSource: addressSource,
      checkoutFirstName: checkoutAddress.firstName,
      checkoutLastName: checkoutAddress.lastName,
      checkoutPhone: checkoutAddress.phone,
      checkoutEmail: checkoutAddress.email,
      checkoutCounty: shippingAddress.shippingCounty,
      checkoutCity: shippingAddress.shippingCity,
      checkoutStreet: shippingAddress.shippingStreet,
      checkoutNumber: shippingAddress.shippingNumber,
      checkoutBlock: shippingAddress.shippingBlock,
      checkoutStaircase: shippingAddress.shippingStaircase,
      checkoutFloor: shippingAddress.shippingFloor,
      checkoutApartment: shippingAddress.shippingApartment,
      checkoutPostalCode: shippingAddress.shippingPostalCode,
      checkoutLandmark: shippingAddress.shippingLandmark,
      checkoutCountry: shippingAddress.shippingCountry || 'Romania',
      accountCounty: profileShipping.shippingCounty,
      accountCity: profileShipping.shippingCity,
      accountStreet: profileShipping.shippingStreet,
      accountNumber: profileShipping.shippingNumber,
      accountBlock: profileShipping.shippingBlock,
      accountStaircase: profileShipping.shippingStaircase,
      accountFloor: profileShipping.shippingFloor,
      accountApartment: profileShipping.shippingApartment,
      accountPostalCode: profileShipping.shippingPostalCode,
      accountLandmark: profileShipping.shippingLandmark,
      accountCountry: profileShipping.shippingCountry || 'Romania',
    };
    const stripeMetadata = Object.fromEntries(
      Object.entries(metadataRaw)
        .filter(([, value]) => !!value)
        .map(([key, value]) => [key, String(value).slice(0, 500)])
    );

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'ron',
            product_data: {
              name: productName,
              description: productDescription,
            },
            unit_amount: priceAmount, 
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      customer_email: billingEmail,
      billing_address_collection: 'required',
      metadata: stripeMetadata,
      payment_intent_data: {
        metadata: stripeMetadata,
      },
      client_reference_id: userId,
      invoice_creation: { enabled: true },
      success_url: `${CLIENT_URL}/dashboard?payment=success`,
      cancel_url: `${CLIENT_URL}/dashboard?payment=canceled`,
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: 'Nu am putut iniția plata securizată.' });
  }
});

app.get('/api/invite-data/:token', async (req, res) => {
    try {
        const guest = await Guest.findOne({ token: req.params.token });
        if (!guest) return res.sendStatus(404);

        guest.openedAt = new Date();
        if (guest.status === 'pending') guest.status = 'opened';
        await guest.save();

        const project = await Project.findOne({ ownerId: guest.ownerId });
        const user = await User.findById(guest.ownerId);
        if (!user) return res.sendStatus(404);

        // Merge template defaults < user profile (user are prioritate)
        const templateId = project?.selectedTemplate || 'castle-magic';
        const tplDoc = await TemplateDefaults.findOne({ templateId });
        const tplDefaults = tplDoc ? tplDoc.toObject() : {};
        // stergem campurile Mongoose interne
        delete tplDefaults._id; delete tplDefaults.__v; delete tplDefaults.templateId; delete tplDefaults.updatedAt;
        // null-urile din defaults nu suprascriu profilul
        const cleanDefaults = Object.fromEntries(Object.entries(tplDefaults).filter(([, v]) => v !== null && v !== undefined && v !== ''));
        const mergedProfile = { ...cleanDefaults, ...cleanProfileForMerge(user.profile?.toObject ? user.profile.toObject() : user.profile) };

        res.send({ guest, project, profile: mergedProfile });
    } catch (e) {
        console.error('invite-data error:', e);
        res.status(500).send({ error: e.message });
    }
});

app.get('/api/public-invite-data/:slug', async (req, res) => {
    try {
        const { slug } = req.params;
        const owner = await User.findOne({ "profile.inviteSlug": slug.toLowerCase() });
        if (!owner) return res.status(404).send({ error: 'Eveniment inexistent.' });

        const project = await Project.findOne({ ownerId: owner._id });

        // Merge template defaults < owner profile
        const templateId = project?.selectedTemplate || 'castle-magic';
        const tplDoc = await TemplateDefaults.findOne({ templateId });
        const tplDefaults = tplDoc ? tplDoc.toObject() : {};
        delete tplDefaults._id; delete tplDefaults.__v; delete tplDefaults.templateId; delete tplDefaults.updatedAt;
        const cleanDefaults = Object.fromEntries(Object.entries(tplDefaults).filter(([, v]) => v !== null && v !== undefined && v !== ''));
        const mergedProfile = { ...cleanDefaults, ...cleanProfileForMerge(owner.profile?.toObject ? owner.profile.toObject() : owner.profile) };

        res.send({
            guest: { name: '', status: 'pending', type: 'guest' },
            project: project || {},
            profile: mergedProfile,
            isPublic: true,
            ownerId: owner._id
        });
    } catch (e) {
        console.error('public-invite-data error:', e);
        res.status(500).send({ error: e.message });
    }
});

app.post('/api/guest/rsvp', async (req, res) => {
    try {
        const { token, status, rsvpData } = req.body || {};
        if (!token) return res.status(400).send({ error: 'Token lipsa.' });

        const guest = await Guest.findOne({ token: String(token).trim() });
        if (!guest) return res.status(404).send({ error: 'Invitat inexistent.' });

        const nextStatusRaw = String(status || '').trim().toLowerCase();
        const allowedStatuses = new Set(['pending', 'opened', 'confirmed', 'declined']);
        const nextStatus = allowedStatuses.has(nextStatusRaw) ? nextStatusRaw : guest.status;

        guest.status = nextStatus;
        if (rsvpData && typeof rsvpData === 'object') guest.rsvp = rsvpData;
        await guest.save();

        if ((nextStatus === 'confirmed' || nextStatus === 'declined') && guest.ownerId) {
            try {
                const owner = await User.findById(guest.ownerId);
                if (owner?.user) {
                    await emailNotifications.sendGuestRsvpEmail({
                        email: owner.user,
                        ownerName: getUserDisplayName(owner),
                        guestName: guest.name,
                        status: nextStatus,
                        rsvpData: guest.rsvp || {},
                        eventType: owner?.profile?.eventType || 'wedding',
                        eventName: owner?.profile?.eventName || '',
                        eventDate: owner?.profile?.weddingDate,
                    });
                }
            } catch (emailError) {
                console.error('[EMAIL] guest/rsvp notification failed:', emailError);
            }
        }

        res.send({ success: true });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

app.post('/api/guest/public-rsvp', async (req, res) => {
    const { ownerId, name, status, rsvpData } = req.body;
    if (!ownerId || !name) return res.status(400).send({ error: 'Date incomplete.' });
    
    const owner = await User.findById(ownerId);
    if (!owner) return res.status(404).send({ error: 'Eveniment inexistent.' });
    
    // Check if event is active before allowing new public RSVPs
    if (isEventCompleted(owner.profile.weddingDate)) {
        return res.status(403).send({ error: 'Acest eveniment a fost încheiat.' });
    }

    const config = await getConfig();
    const limits = config.limits[owner.plan || 'free'];
    const currentCount = await Guest.countDocuments({ ownerId });
    
    if (currentCount >= limits.maxGuests) return res.status(403).send({ error: 'Limita atinsă.' });
    
    const nextStatus = String(status || '').toLowerCase() === 'declined' ? 'declined' : 'confirmed';

    const newGuest = new Guest({
        ownerId, name, type: 'adult', token: generateToken(),
        status: nextStatus, isSent: true, source: 'public', rsvp: rsvpData
    });
    await newGuest.save();

    try {
        if (owner?.user) {
            await emailNotifications.sendGuestRsvpEmail({
                email: owner.user,
                ownerName: getUserDisplayName(owner),
                guestName: newGuest.name,
                status: nextStatus,
                rsvpData: newGuest.rsvp || {},
                eventType: owner?.profile?.eventType || 'wedding',
                eventName: owner?.profile?.eventName || '',
                eventDate: owner?.profile?.weddingDate,
            });
        }
    } catch (emailError) {
        console.error('[EMAIL] guest/public-rsvp notification failed:', emailError);
    }

    res.send({ success: true, guest: newGuest });
});

// ─────────────────────────────────────────────────────────────────────────────
// INVOICE HELPERS
// ─────────────────────────────────────────────────────────────────────────────

async function generateInvoiceNumber() {
    const year = new Date().getFullYear();
    const cfg  = await SystemConfig.findOneAndUpdate(
        { key: 'global_config' },
        { $inc: { invoiceCounter: 1 } },
        { new: true, upsert: true }
    );
    return `FACT-${year}-${String(cfg.invoiceCounter).padStart(4, '0')}`;
}

function generateInvoicePDF(data) {
    return new Promise((resolve, reject) => {
        const {
            invoiceNumber, date, amount, currency = 'RON',
            description, billingEmail, billingFirstName, billingLastName,
            billingAddress, paymentMethod = 'Netopia / Card Bancar', orderId,
        } = data;

        // Helvetica uses WinAnsiEncoding (U+0000–U+00FF). Romanian chars like Ă, Ș, Ț
        // are U+0100+ and render as invisible glyphs. Strip diacritics via NFD normalization.
        const t = s => (s || '').normalize('NFD').replace(/[\u0300-\u036f\u0326-\u0329]/g, '').replace(/[^\x00-\x7F]/g, '');

        const doc    = new PDFDocument({ margin: 50, size: 'A4' });
        const chunks = [];
        doc.on('data', c => chunks.push(c));
        doc.on('end',  () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);

        const dateStr = new Date(date).toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
        const W = 595 - 100; // pagina A4 minus margini

        // ── Header ──────────────────────────────────────────────────────────
        doc.fontSize(22).font('Helvetica-Bold').text('FACTURA FISCALA', 50, 50);
        doc.fontSize(10).font('Helvetica').fillColor('#666')
           .text('Wedding Planner Pro', 50, 80)
           .text('contact@weddingplanner.ro', 50, 93);

        // Numar + data (dreapta)
        doc.fontSize(10).font('Helvetica-Bold').fillColor('#000')
           .text(`Nr: ${invoiceNumber}`, 400, 50, { width: 145, align: 'right' });
        doc.fontSize(10).font('Helvetica').fillColor('#333')
           .text(`Data: ${dateStr}`, 400, 65, { width: 145, align: 'right' });

        // Linie separator
        doc.moveTo(50, 115).lineTo(545, 115).strokeColor('#e0e0e0').lineWidth(1).stroke();

        // ── Bill To ─────────────────────────────────────────────────────────
        doc.fontSize(9).font('Helvetica-Bold').fillColor('#888').text('FACTURAT CATRE', 50, 130);
        const clientName = t([billingFirstName, billingLastName].filter(Boolean).join(' ') || 'Client');
        doc.fontSize(11).font('Helvetica-Bold').fillColor('#000').text(clientName, 50, 145);
        doc.fontSize(10).font('Helvetica').fillColor('#333');
        if (billingEmail) doc.text(billingEmail, 50, 160);
        if (billingAddress) doc.text(t(billingAddress), 50, 173);

        // ── Tabel produse ────────────────────────────────────────────────────
        const tableTop = 220;
        doc.fontSize(9).font('Helvetica-Bold').fillColor('#fff')
           .rect(50, tableTop, W, 24).fill('#2d3748').stroke();
        doc.fillColor('#fff')
           .text('Descriere', 60, tableTop + 7)
           .text('Cant.', 380, tableTop + 7, { width: 50, align: 'center' })
           .text('Pret', 440, tableTop + 7, { width: 50, align: 'right' })
           .text('Total', 500, tableTop + 7, { width: 45, align: 'right' });

        const rowTop = tableTop + 24;
        doc.rect(50, rowTop, W, 28).fill('#f9f9f9').stroke();
        doc.fontSize(10).font('Helvetica').fillColor('#000')
           .text(t(description || 'Wedding Planner Premium'), 60, rowTop + 8)
           .text('1', 380, rowTop + 8, { width: 50, align: 'center' })
           .text(`${Number(amount).toFixed(2)} ${currency}`, 440, rowTop + 8, { width: 50, align: 'right' })
           .text(`${Number(amount).toFixed(2)} ${currency}`, 500, rowTop + 8, { width: 45, align: 'right' });

        // ── Total ────────────────────────────────────────────────────────────
        const totalTop = rowTop + 40;
        doc.moveTo(50, totalTop).lineTo(545, totalTop).strokeColor('#e0e0e0').lineWidth(1).stroke();
        doc.fontSize(12).font('Helvetica-Bold').fillColor('#000')
           .text('TOTAL DE PLATA:', 350, totalTop + 10)
           .text(`${Number(amount).toFixed(2)} ${currency}`, 460, totalTop + 10, { width: 85, align: 'right' });

        // ── Detalii plata ────────────────────────────────────────────────────
        doc.fontSize(9).font('Helvetica').fillColor('#888')
           .text(`Metoda de plata: ${t(paymentMethod)}`, 50, totalTop + 45)
           .text(`Referinta comanda: ${orderId}`, 50, totalTop + 58)
           .text('Status: ACHITAT', 50, totalTop + 71);

        // ── Footer ───────────────────────────────────────────────────────────
        doc.moveTo(50, 750).lineTo(545, 750).strokeColor('#e0e0e0').lineWidth(1).stroke();
        doc.fontSize(8).fillColor('#aaa')
           .text('Va multumim pentru incredere! Aceasta factura este generata automat.', 50, 760, { align: 'center', width: W });

        doc.end();
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// NETOPIA PAYMENTS
// ─────────────────────────────────────────────────────────────────────────────

function encryptNetopia(orderData) {
    const builder = new Builder({ headless: false, renderOpts: { pretty: false } });
    const xml = builder.buildObject(orderData);

    const aesKey = crypto.randomBytes(32);
    const iv     = crypto.randomBytes(16);

    const cipher    = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    const encrypted = Buffer.concat([cipher.update(xml, 'utf8'), cipher.final()]);

    const certPath = path.join(process.cwd(), 'sandbox.3BX6-JMJU-8QP0-ACQC-PNHL.public.cer');
    if (!fs.existsSync(certPath)) throw new Error('Netopia public.cer not found in project root.');

    const publicKey      = crypto.createPublicKey(fs.readFileSync(certPath));
    const encryptedKey   = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, aesKey);

    return {
        iv:      iv.toString('base64'),
        env_key: encryptedKey.toString('base64'),
        data:    encrypted.toString('base64'),
        cipher:  'aes-256-cbc',
    };
}

// 1. Initiate — authenticated
app.post('/api/netopia/initiate', authenticateToken, async (req, res) => {
    try {
        if (!NETOPIA_SIGNATURE) return res.status(400).json({ error: 'NETOPIA_SIGNATURE lipsește din env.' });

        const userId  = req.user.userId;
        const user    = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User inexistent.' });
        const { billing = {}, targetPlan: requestedPlanRaw } = req.body || {};
        const clean = (value, max = 180) => String(value ?? '').trim().slice(0, max);
        const requestedPlan = normalizePlan(requestedPlanRaw || 'premium');
        if (requestedPlan === 'free') {
          return res.status(400).json({ error: 'Planul ales este invalid.' });
        }
        const currentPlan = normalizePlan(user.plan || 'free');

        const config    = await getConfig();
        const planPriceMap = {
          basic: config.pricing.basicPrice,
          premium: config.pricing.premiumPrice,
        };
        const charge = getUpgradeCharge(planPriceMap, currentPlan, requestedPlan);
        if (!charge.ok) {
          return res.status(400).json({ error: charge.message });
        }
        const priceAmount = charge.payableAmount;
        const amount    = (priceAmount / 100).toFixed(2);
        const planLabel = requestedPlan === 'basic' ? 'Basic' : 'Premium';
        const planDetailsLabel =
          charge.currentPlan === 'free'
            ? `Wedding Planner ${planLabel}`
            : `Upgrade ${charge.currentPlan} -> ${planLabel}`;
        const orderId   = `ORD_${Date.now()}`;
        const timestamp = Date.now().toString();

        const checkoutAddress = getCheckoutContactAndAddress({
          billing,
          profile: user.profile || {},
          emailFallback: user.user,
        });
        const { shippingAddress, profileShipping, addressSource } = checkoutAddress;
        const billingType = clean(billing.type, 20) === 'company' ? 'company' : 'individual';
        const fallbackBillingName = clean(
          user.profile?.billingName ||
          [user.profile?.firstName, user.profile?.lastName].filter(Boolean).join(' ') ||
          user.profile?.partner1Name ||
          'Client',
          120
        );
        const contactFullName = `${checkoutAddress.firstName} ${checkoutAddress.lastName}`.trim();
        const billingName = clean(billing.name || contactFullName || fallbackBillingName, 120);
        const billingCompany = clean(billing.company || user.profile?.billingCompany, 160);
        const billingVatCode = normalizeBillingTaxCode({
          billingType,
          vatCode: clean(billing.vatCode || user.profile?.billingVatCode, 64),
        });
        const billingRegNo = clean(billing.regNo || user.profile?.billingRegNo, 64);
        const billingAddress = composeShippingAddressLine(shippingAddress);
        const billingCity = clean(shippingAddress.shippingCity, 120);
        const billingSector = normalizeSectorName(clean(billing.sector || user.profile?.billingSector, 32));
        const billingCountry = normalizeCountryName(shippingAddress.shippingCountry || 'Romania');
        const billingCounty = clean(shippingAddress.shippingCounty, 120);
        const billingPhone = clean(checkoutAddress.phone || user.profile?.billingPhone || user.profile?.phone || '0700000000', 40);
        let billingEmail = clean(checkoutAddress.email || user.profile?.billingEmail || user.profile?.email || user.user);

        if (!billingEmail || !billingEmail.includes('@')) {
          return res.status(400).json({ error: 'Email-ul de facturare este obligatoriu.' });
        }
        if (!checkoutAddress.firstName || !checkoutAddress.lastName) {
          return res.status(400).json({ error: 'Completeaza prenumele si numele pentru checkout.' });
        }
        if (!checkoutAddress.phone || !isValidRoPhone(checkoutAddress.phone)) {
          return res.status(400).json({ error: 'Numarul de telefon este obligatoriu si trebuie sa fie valid.' });
        }
        if (!isShippingAddressComplete(shippingAddress)) {
          return res.status(400).json({
            error: 'Adresa de checkout este incompleta. Completeaza judet, localitate, strada, numar si cod postal.',
          });
        }
        if (!billingName) {
          return res.status(400).json({ error: 'Numele de facturare este obligatoriu.' });
        }
        if (billingType === 'company' && !billingCompany) {
          return res.status(400).json({ error: 'Numele companiei este obligatoriu pentru facturare pe firma.' });
        }
        if (billingType === 'company' && isBucharestCity(billingCity) && !billingSector) {
          return res.status(400).json({ error: 'Pentru firme din Bucuresti, selecteaza sectorul.' });
        }
        if (!billingAddress || !billingCity || !billingCountry || !billingCounty) {
          return res.status(400).json({ error: 'Completeaza adresa, orasul, judetul si tara pentru facturare.' });
        }

        const profileUpdateSet = {
          'profile.email': billingEmail,
          'profile.billingType': billingType,
          'profile.billingName': billingName,
          'profile.billingCompany': billingCompany,
          'profile.billingVatCode': billingVatCode,
          'profile.billingRegNo': billingRegNo,
          'profile.billingAddress': billingAddress,
          'profile.billingCity': billingCity,
          'profile.billingSector': billingSector,
          'profile.billingCounty': billingCounty,
          'profile.billingCountry': billingCountry,
          'profile.billingEmail': billingEmail,
          'profile.billingPhone': billingPhone,
          'profile.firstName': checkoutAddress.firstName || user.profile?.firstName || '',
          'profile.lastName': checkoutAddress.lastName || user.profile?.lastName || '',
          'profile.phone': billingPhone || user.profile?.phone || '',
        };
        if (isShippingAddressComplete(shippingAddress)) {
          profileUpdateSet['profile.address'] = billingAddress;
          profileUpdateSet['profile.city'] = shippingAddress.shippingCity;
          profileUpdateSet['profile.county'] = shippingAddress.shippingCounty;
          profileUpdateSet['profile.country'] = shippingAddress.shippingCountry || 'Romania';
          profileUpdateSet['profile.shippingCounty'] = shippingAddress.shippingCounty;
          profileUpdateSet['profile.shippingCity'] = shippingAddress.shippingCity;
          profileUpdateSet['profile.shippingStreet'] = shippingAddress.shippingStreet;
          profileUpdateSet['profile.shippingNumber'] = shippingAddress.shippingNumber;
          profileUpdateSet['profile.shippingBlock'] = shippingAddress.shippingBlock;
          profileUpdateSet['profile.shippingStaircase'] = shippingAddress.shippingStaircase;
          profileUpdateSet['profile.shippingFloor'] = shippingAddress.shippingFloor;
          profileUpdateSet['profile.shippingApartment'] = shippingAddress.shippingApartment;
          profileUpdateSet['profile.shippingPostalCode'] = shippingAddress.shippingPostalCode;
          profileUpdateSet['profile.shippingLandmark'] = shippingAddress.shippingLandmark;
          profileUpdateSet['profile.shippingCountry'] = shippingAddress.shippingCountry || 'Romania';
        }
        await User.findByIdAndUpdate(userId, { $set: profileUpdateSet });

        const displayName = billingCompany || billingName;
        const { firstName, lastName } = splitDisplayName(displayName);

        const returnUrl =
          `${APP_URL.replace(/\/$/, '')}/api/netopia/return?orderId=${encodeURIComponent(orderId)}`;

        const orderXml = {
            order: {
                $: { id: orderId, timestamp, type: 'card' },
                signature: NETOPIA_SIGNATURE,
                url: {
                    return:  returnUrl,
                    confirm: `${APP_URL}/api/netopia/confirm`,
                },
                invoice: {
                    $: { currency: 'RON', amount },
                    details: `${planDetailsLabel} — acces pe viata`,
                    contact_info: {
                        billing: {
                            $: { type: billingType === 'company' ? 'company' : 'person' },
                            first_name:   firstName,
                            last_name:    lastName,
                            address:      billingAddress,
                            email:        billingEmail,
                            mobile_phone: billingPhone,
                        },
                    },
                },
                ipn_cipher: 'aes-256-cbc',
            },
        };

        const encrypted = encryptNetopia(orderXml);

        // Salvăm comanda în profilul userului (status PENDING)
        await User.findByIdAndUpdate(userId, {
            $push: {
                payments: {
                    date:             new Date(),
                    amount:           parseFloat(amount),
                    invoiceId:        orderId,
                    billingEmail,
                    billingFirstName: firstName,
                    billingLastName: lastName,
                    billingAddress: billingAddress || [billingCity, billingCounty, billingCountry].filter(Boolean).join(', '),
                    billingCity,
                    billingSector,
                    billingCounty,
                    billingCountry,
                    checkoutAddressSource: addressSource,
                    checkoutFirstName: checkoutAddress.firstName,
                    checkoutLastName: checkoutAddress.lastName,
                    checkoutPhone: checkoutAddress.phone,
                    checkoutEmail: checkoutAddress.email,
                    checkoutCounty: shippingAddress.shippingCounty,
                    checkoutCity: shippingAddress.shippingCity,
                    checkoutStreet: shippingAddress.shippingStreet,
                    checkoutNumber: shippingAddress.shippingNumber,
                    checkoutBlock: shippingAddress.shippingBlock,
                    checkoutStaircase: shippingAddress.shippingStaircase,
                    checkoutFloor: shippingAddress.shippingFloor,
                    checkoutApartment: shippingAddress.shippingApartment,
                    checkoutPostalCode: shippingAddress.shippingPostalCode,
                    checkoutLandmark: shippingAddress.shippingLandmark,
                    checkoutCountry: shippingAddress.shippingCountry || 'Romania',
                    savedAddressSnapshot: {
                      county: profileShipping.shippingCounty,
                      city: profileShipping.shippingCity,
                      street: profileShipping.shippingStreet,
                      number: profileShipping.shippingNumber,
                      block: profileShipping.shippingBlock,
                      staircase: profileShipping.shippingStaircase,
                      floor: profileShipping.shippingFloor,
                      apartment: profileShipping.shippingApartment,
                      postalCode: profileShipping.shippingPostalCode,
                      landmark: profileShipping.shippingLandmark,
                      country: profileShipping.shippingCountry || 'Romania',
                    },
                    checkoutAddressSnapshot: {
                      county: shippingAddress.shippingCounty,
                      city: shippingAddress.shippingCity,
                      street: shippingAddress.shippingStreet,
                      number: shippingAddress.shippingNumber,
                      block: shippingAddress.shippingBlock,
                      staircase: shippingAddress.shippingStaircase,
                      floor: shippingAddress.shippingFloor,
                      apartment: shippingAddress.shippingApartment,
                      postalCode: shippingAddress.shippingPostalCode,
                      landmark: shippingAddress.shippingLandmark,
                      country: shippingAddress.shippingCountry || 'Romania',
                    },
                    paymentMethod:    'netopia_card',
                    planTarget:       requestedPlan,
                    status:           'Pending',
                    relatedEventDate: user.profile?.weddingDate,
                    relatedEventName: user.profile?.eventName || planDetailsLabel,
                },
            },
        });

        res.json({
            success:    true,
            iv:         encrypted.iv,
            env_key:    encrypted.env_key,
            data:       encrypted.data,
            cipher:     encrypted.cipher,
            paymentUrl: NETOPIA_SANDBOX
                ? 'https://sandboxsecure.mobilpay.ro'
                : 'https://secure.mobilpay.ro',
            orderId,
        });
    } catch (err) {
        console.error('Netopia initiate error:', err);
        res.status(500).json({ error: err.message });
    }
});

async function finalizeNetopiaPaymentAsPaid(orderId) {
  const user = await User.findOne({ 'payments.invoiceId': orderId });
  if (!user) return null;

  const payment = user.payments.find((p) => p.invoiceId === orderId);
  if (!payment) return null;
  const wasAlreadyPaid = String(payment.status || '').toLowerCase() === 'paid';
  const targetPlan = normalizePlan(payment.planTarget || 'premium');

  const billing = getSmartbillBillingFromProfile(user.profile || {}, payment.billingEmail || user.user);

  let invoiceNum = payment.invoiceNumber || '';
  let invoiceUrl = payment.invoicePdfUrl || '';
  let invoiceEmailData = null;
  let invoiceGeneratedNow = false;
  if (!invoiceNum || !invoiceUrl) {
    if (isSmartbillConfigured()) {
      try {
        const smartbillResult = await createSmartbillInvoiceFlow({
          billing,
          amount: Number(payment.amount || 0),
          currency: 'RON',
          description: targetPlan === 'basic' ? 'Wedding Planner Basic' : 'Wedding Planner Premium',
          sendEmail: false,
        });
        if (smartbillResult?.enabled) {
          invoiceNum = smartbillResult.invoiceNumber || invoiceNum;
          invoiceUrl = smartbillResult.pdfPublicUrl || invoiceUrl;
          invoiceEmailData = {
            pdfFilePath: smartbillResult.pdfFilePath || '',
            pdfFileName: smartbillResult.pdfFileName || '',
          };
          invoiceGeneratedNow = true;
        }
      } catch (smartbillErr) {
        console.error(`[SMARTBILL] Netopia order ${orderId} invoice failed:`, smartbillErr.message);
      }
    }

    if (!invoiceNum) {
      invoiceNum = await generateInvoiceNumber();
    }
    if (!invoiceUrl) {
      invoiceUrl = `/invoice/${invoiceNum}`;
    }
  }

  const billingEmail = String(billing.email || payment.billingEmail || user.user || '').trim();
  const displayName =
    String(billing.company || billing.name || '').trim() || getUserDisplayName(user);

  const updated = await User.findOneAndUpdate(
    { _id: user._id, 'payments.invoiceId': orderId },
    {
      $set: {
        plan: planAtLeast(user.plan || 'free', targetPlan),
        'profile.billingVatCode': billing.vatCode,
        'payments.$.status': 'Paid',
        'payments.$.invoiceNumber': invoiceNum,
        'payments.$.invoicePdfUrl': invoiceUrl,
      },
    },
    { new: true }
  );

  const shouldSendInvoiceEmail =
    Boolean(billingEmail && invoiceNum) && (!wasAlreadyPaid || invoiceGeneratedNow);
  let emailSent = false;

  if (shouldSendInvoiceEmail) {
    const attachmentPath =
      invoiceEmailData?.pdfFilePath || resolveLocalUploadPathFromPublicUrl(invoiceUrl);
    const attachment = buildEmailAttachmentFromFile(
      attachmentPath,
      invoiceEmailData?.pdfFileName || `${invoiceNum}.pdf`,
    );
    const invoicePublicUrl = invoiceUrl
      ? (String(invoiceUrl).startsWith('http') ? invoiceUrl : `${CLIENT_URL}${invoiceUrl}`)
      : '';

    try {
      emailSent = await emailNotifications.sendBillingInvoiceEmail({
        email: billingEmail,
        name: displayName,
        invoiceNumber: invoiceNum,
        amount: Number(payment.amount || 0),
        currency: 'RON',
        issueDate: new Date(),
        eventName: payment.relatedEventName || user?.profile?.eventName || '',
        invoiceUrl: invoicePublicUrl,
        attachments: attachment ? [attachment] : [],
      });
      console.log('[NETOPIA][EMAIL] Invoice email sent via emailNotifications', {
        orderId,
        billingEmail,
        invoiceNumber: invoiceNum,
        hasAttachment: Boolean(attachment),
        emailSent,
      });
    } catch (emailErr) {
      console.error('[NETOPIA][EMAIL] Invoice email failed:', emailErr.message);
    }
  } else {
    console.log('[NETOPIA][EMAIL] Invoice email skipped', {
      orderId,
      billingEmail,
      invoiceNumber: invoiceNum,
      wasAlreadyPaid,
      invoiceGeneratedNow,
    });
  }

  return {
    user,
    updated,
    invoiceNum,
    invoiceUrl,
    emailSent,
    wasAlreadyPaid,
    invoiceGeneratedNow,
  };
}

// 2. IPN (notifyUrl) — Netopia trimite JSON, la fel ca Stripe webhook
app.post('/api/netopia/confirm', async (req, res) => {
    console.log('=== NETOPIA IPN RECEIVED ===');
    const crcOk = '<?xml version="1.0" encoding="utf-8"?><crc>OK</crc>';
    const crcRetry = '<?xml version="1.0" encoding="utf-8"?><crc>RETRY</crc>';
    res.set('Content-Type', 'text/xml');

    const { env_key, data, iv, cipher } = req.body;

    if (!env_key || !data) {
        console.warn('Netopia IPN: payload invalid (env_key/data lipsa).');
        return res.status(400).send(crcRetry);
    }

    try {
        // 1. Citim cheia privată
        const keyRelPath = (process.env.NETOPIA_PRIVATE_KEY_PATH || './sandbox.3BX6-JMJU-8QP0-ACQC-PNHLprivate.key').replace(/^\.\//, '');
        const keyPath = path.join(process.cwd(), keyRelPath);
        console.log('Netopia IPN: cheia privată la', keyPath, '| există:', fs.existsSync(keyPath));
        if (!fs.existsSync(keyPath)) throw new Error(`Cheia privată nu există: ${keyPath}`);

        // 2. Decriptăm cheia AES cu RSA (node-forge evită restricția din OpenSSL 3)
        const privateKeyPem   = fs.readFileSync(keyPath, 'utf8');
        const forgePrivateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        const aesKeyBinary    = forgePrivateKey.decrypt(forge.util.decode64(env_key), 'RSAES-PKCS1-V1_5');
        const aesKey          = Buffer.from(aesKeyBinary, 'binary');

        // 3. Decriptăm payload-ul cu AES-256-CBC
        const ivBuf    = iv ? Buffer.from(iv, 'base64') : Buffer.alloc(16, 0);
        const decipher = crypto.createDecipheriv(cipher || 'aes-256-cbc', aesKey, ivBuf);
        const xmlStr   = Buffer.concat([
            decipher.update(Buffer.from(data, 'base64')),
            decipher.final(),
        ]).toString('utf8');
        console.log('Netopia IPN XML decriptat:', xmlStr);

        // 4. Parsăm XML-ul
        const parser  = new Parser({ explicitArray: false });
        const parsed  = await parser.parseStringPromise(xmlStr);
        const order   = parsed?.order;
        const orderId = order?.$?.id;
        const mobilpay = order?.mobilpay;

        // errorCode "0" = aprobat
        const errorCode = String(mobilpay?.error?.$?.code ?? mobilpay?.error?.code ?? '-1').trim();
        const action    = mobilpay?.action ?? 'unknown';
        console.log(`Netopia IPN: orderId=${orderId} | action=${action} | errorCode=${errorCode}`);

        if (!orderId) {
            console.warn('Netopia IPN: orderId lipsește din XML decriptat');
            return res.send(crcOk);
        }

        if (errorCode === '0') {
            // Plată aprobată — la fel ca Stripe checkout.session.completed
            const result = await finalizeNetopiaPaymentAsPaid(orderId);
            console.log(`Netopia IPN: user găsit pentru orderId=${orderId}:`, !!result?.user);

            if (result?.user) {
                console.log(`✅ Netopia IPN: user ${result.user._id} → plan=${result.updated?.plan} | factură=${result.invoiceNum} | email=${result.emailSent ? 'sent' : 'skip'} (order ${orderId})`);
            } else {
                console.warn(`Netopia IPN: ordinul ${orderId} nu există în DB`);
            }
        } else {
            await User.findOneAndUpdate(
                { 'payments.invoiceId': orderId },
                { $set: { 'payments.$.status': 'Failed' } }
            );
            console.log(`❌ Netopia: order ${orderId} FAILED (errorCode=${errorCode})`);
        }

        return res.send(crcOk);
    } catch (err) {
        console.error('Netopia IPN error:', err.message);
        // No ACK on processing errors -> Netopia can retry callback delivery.
        return res.status(500).send(crcRetry);
    }
});

// TEST MANUAL — apelează din browser: GET /api/netopia/test-upgrade/:userId
// Șterge după ce testezi!
app.get('/api/netopia/test-upgrade/:userId', async (req, res) => {
    try {
        const result = await User.findByIdAndUpdate(
            req.params.userId,
            { plan: 'premium' },
            { new: true }
        );
        res.json({ ok: true, plan: result?.plan });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 3. Return URL (redirectUrl) — userul ajunge aici după plată (browser redirect).
//    Facem upgrade și aici ca fallback, în cazul în care IPN-ul nu a ajuns (ex. tunel Cloudflare schimbat).
app.get('/api/netopia/return', async (req, res) => {
    try {
        // Netopia poate trimite orderId ca string sau array dacă îl punem și noi în URL — luăm primul
        const rawId = req.query.orderId;
        const orderId = Array.isArray(rawId) ? rawId[0] : (typeof rawId === 'string' ? rawId.split(',')[0] : null);

        if (orderId) {
            const user = await User.findOne({ 'payments.invoiceId': orderId });
            if (user) {
                const payment = user.payments.find(p => p.invoiceId === orderId);
                // Facem upgrade doar dacă e încă Pending (IPN-ul poate fi deja procesat)
                if (payment && payment.status === 'Pending') {
                    const result = await finalizeNetopiaPaymentAsPaid(orderId);
                    console.log(`✅ Netopia return: user ${user._id} → premium | factură=${result?.invoiceNum || '-'} | email=${result?.emailSent ? 'sent' : 'skip'} (order ${orderId})`);
                }
            }
        }
    } catch (err) {
        console.error('Netopia return handler error:', err.message);
    }
    res.redirect(`${CLIENT_URL}/dashboard?payment=success`);
});

// ── HTML Invoice Page ─────────────────────────────────────────────────────────
app.get('/invoice/:invoiceNumber', async (req, res) => {
    const { invoiceNumber } = req.params;
    try {
        const user = await User.findOne({ 'payments.invoiceNumber': invoiceNumber });
        if (!user) return res.status(404).send('<h2>Factura nu a fost gasita.</h2>');
        const p = user.payments.find(x => x.invoiceNumber === invoiceNumber);
        if (!p) return res.status(404).send('<h2>Factura nu a fost gasita.</h2>');

        const date = new Date(p.date).toLocaleDateString('ro-RO', { day: '2-digit', month: 'long', year: 'numeric' });
        const amount = Number(p.amount || 0).toFixed(2);
        const clientName = [p.billingFirstName, p.billingLastName].filter(Boolean).join(' ') || 'Client';
        const invoiceCity = p.billingCity || user?.profile?.billingCity || user?.profile?.city || '';
        const invoiceSector = p.billingSector || user?.profile?.billingSector || '';
        const invoiceCounty = p.billingCounty || user?.profile?.billingCounty || user?.profile?.county || '';
        const invoiceCountry = p.billingCountry || user?.profile?.billingCountry || user?.profile?.country || '';

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(`<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Factură ${invoiceNumber}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #222; }
  .page { max-width: 800px; margin: 40px auto; background: #fff; border-radius: 12px; box-shadow: 0 4px 32px rgba(0,0,0,.10); overflow: hidden; }
  .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); color: #fff; padding: 40px 48px 36px; display: flex; justify-content: space-between; align-items: flex-start; }
  .brand { font-size: 22px; font-weight: 700; letter-spacing: .5px; }
  .brand-sub { font-size: 12px; color: rgba(255,255,255,.6); margin-top: 4px; }
  .invoice-meta { text-align: right; }
  .invoice-title { font-size: 28px; font-weight: 300; letter-spacing: 2px; text-transform: uppercase; opacity: .9; }
  .invoice-num { font-size: 14px; color: rgba(255,255,255,.7); margin-top: 6px; }
  .badge { display: inline-block; background: #10b981; color: #fff; font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 20px; margin-top: 8px; letter-spacing: .5px; }
  .body { padding: 40px 48px; }
  .info-row { display: grid; grid-template-columns: 1fr 1fr; gap: 32px; margin-bottom: 36px; }
  .info-block label { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #888; display: block; margin-bottom: 8px; }
  .info-block .val { font-size: 15px; color: #111; font-weight: 600; }
  .info-block .sub { font-size: 13px; color: #555; margin-top: 3px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 28px; }
  thead tr { background: #1a1a2e; color: #fff; }
  thead th { padding: 12px 16px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; text-align: left; }
  thead th:last-child { text-align: right; }
  tbody tr { border-bottom: 1px solid #f0f0f0; }
  tbody tr:last-child { border-bottom: none; }
  tbody td { padding: 16px; font-size: 14px; color: #333; }
  tbody td:last-child { text-align: right; font-weight: 600; }
  .total-section { background: #f8f9fc; border-radius: 8px; padding: 20px 24px; text-align: right; }
  .total-section .total-label { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #888; }
  .total-section .total-val { font-size: 32px; font-weight: 700; color: #1a1a2e; margin-top: 4px; }
  .total-section .total-currency { font-size: 16px; font-weight: 400; color: #666; margin-left: 4px; }
  .meta-section { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 32px; padding-top: 24px; border-top: 1px solid #eee; }
  .meta-block label { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #aaa; display: block; margin-bottom: 4px; }
  .meta-block .val { font-size: 13px; color: #444; font-weight: 500; word-break: break-all; }
  .footer { background: #f8f9fc; padding: 20px 48px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #eee; }
  .footer-text { font-size: 12px; color: #aaa; }
  .print-btn { background: #1a1a2e; color: #fff; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background .2s; }
  .print-btn:hover { background: #0f3460; }
  @media print {
    body { background: #fff; }
    .page { box-shadow: none; margin: 0; border-radius: 0; max-width: 100%; }
    .print-btn { display: none; }
    .footer { border-top: none; background: none; padding: 16px 48px; }
  }
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div>
      <div class="brand">Wedding Planner Pro</div>
      <div class="brand-sub">contact@weddingplanner.ro</div>
    </div>
    <div class="invoice-meta">
      <div class="invoice-title">Factură</div>
      <div class="invoice-num">${invoiceNumber}</div>
      <div><span class="badge">ACHITAT</span></div>
    </div>
  </div>

  <div class="body">
    <div class="info-row">
      <div class="info-block">
        <label>Facturat către</label>
        <div class="val">${clientName}</div>
        <div class="sub">${p.billingEmail || ''}</div>
        ${p.billingAddress ? `<div class="sub">${p.billingAddress}</div>` : ''}
        <div class="sub">Oras: ${invoiceCity || '-'}</div>
        ${invoiceSector ? `<div class="sub">Sector: ${invoiceSector}</div>` : ''}
        <div class="sub">Judet: ${invoiceCounty || '-'}</div>
        <div class="sub">Tara: ${invoiceCountry || '-'}</div>
      </div>
      <div class="info-block">
        <label>Detalii factură</label>
        <div class="val">${invoiceNumber}</div>
        <div class="sub">Data: ${date}</div>
        <div class="sub">Metodă: ${p.billingFirstName ? 'Netopia / Card Bancar' : 'Card (Stripe)'}</div>
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Descriere</th>
          <th style="text-align:center">Cantitate</th>
          <th style="text-align:right">Preț unitar</th>
          <th>Total</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Wedding Planner Pro — Licență Premium</td>
          <td style="text-align:center">1</td>
          <td style="text-align:right">${amount} RON</td>
          <td>${amount} RON</td>
        </tr>
      </tbody>
    </table>

    <div class="total-section">
      <div class="total-label">Total de plată</div>
      <div class="total-val">${amount}<span class="total-currency">RON</span></div>
    </div>

    <div class="meta-section">
      <div class="meta-block"><label>Referință comandă</label><div class="val">${p.invoiceId || '-'}</div></div>
      <div class="meta-block"><label>Status plată</label><div class="val" style="color:#10b981;font-weight:700">Achitat</div></div>
      <div class="meta-block"><label>Data emiterii</label><div class="val">${date}</div></div>
    </div>
  </div>

  <div class="footer">
    <div class="footer-text">Vă mulțumim pentru încredere! Această factură a fost generată automat.</div>
    <button class="print-btn" onclick="window.print()">⬇ Descarcă / Printează</button>
  </div>
</div>
</body>
</html>`);
    } catch (err) {
        console.error('Invoice page error:', err.message);
        res.status(500).send('<h2>Eroare la generarea facturii.</h2>');
    }
});

app.use(express.static(path.join(__dirname, 'dist')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.use((err, req, res, next) => {
    console.error("❌ GLOBAL ERROR:", err.stack);
    if (!res.headersSent) res.status(500).send({ error: 'Internal Server Error' });
});

app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
