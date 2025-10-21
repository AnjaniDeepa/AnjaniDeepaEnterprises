// =========================
// Load environment variables
// =========================
require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const session = require('express-session');
const multer = require('multer');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// =========================
// Express setup
// =========================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: false
}));

// =========================
// Multer file uploads setup
// =========================
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'))
});

const MIN_RESUME_BYTES = 50 * 1024; // 50 KB
const MAX_RESUME_BYTES = 5 * 1024 * 1024; // 5 MB
const allowedMime = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
];
const allowedExt = ['.pdf', '.doc', '.docx'];

const upload = multer({
  storage,
  limits: { fileSize: MAX_RESUME_BYTES },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedExt.includes(ext) && allowedMime.includes(file.mimetype)) return cb(null, true);
    cb(new Error('Invalid file type. Only PDF, DOC, DOCX allowed.'));
  }
});

// =========================
// Nodemailer setup
// =========================
let mailer = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
} else {
  console.log('⚠️ Mailer not configured. Emails will not be sent.');
}

// =========================
// File paths and helpers
// =========================
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const JOBS_FILE = path.join(DATA_DIR, 'jobs.json');
const APPS_FILE = path.join(DATA_DIR, 'applications.json');
const MAIL_LOG = path.join(DATA_DIR, 'email-log.jsonl');

function logMailAttempt(entry) {
  try {
    const line = JSON.stringify({ timestamp: new Date().toISOString(), ...entry }) + '\n';
    fs.appendFileSync(MAIL_LOG, line, 'utf8');
  } catch (e) {
    console.error('Failed to write mail log', e);
  }
}

function readJSON(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch { return []; }
}

function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

// =========================
// Middleware
// =========================
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// =========================
// Public routes
// =========================
app.get('/', (req, res) => res.render('home', { jobs: readJSON(JOBS_FILE) }));
app.get('/about', (req, res) => res.render('about'));
app.get('/jobs', (req, res) => res.render('jobs', { jobs: readJSON(JOBS_FILE) }));

// Apply to a job form
app.get('/jobs/:id/apply', (req, res) => {
  const job = readJSON(JOBS_FILE).find(j => String(j.id) === String(req.params.id));
  if (!job) return res.status(404).send('Job not found');
  res.render('apply', { job, error: null });
});

app.post('/jobs/:id/apply', (req, res) => {
  upload.single('resume')(req, res, async err => {
    const job = readJSON(JOBS_FILE).find(j => String(j.id) === String(req.params.id));
    if (!job) return res.status(404).send('Job not found');

    const { name, email, phone, cover } = req.body || {};
    const form = { name, email, phone, cover };

    // Handle file upload errors
    if (err) {
      if (req.file?.path) fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: err.message || 'File upload error', form });
    }

    // Validate fields
    if (!name || !email || !phone || !cover) {
      if (req.file?.path) fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: 'All fields are required', form });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (req.file?.path) fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: 'Invalid email address', form });
    }
    if (!/^[0-9+\-\s]{7,20}$/.test(phone)) {
      if (req.file?.path) fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: 'Invalid phone number', form });
    }
    if (!req.file) return res.render('apply', { job, error: 'Resume is required', form });

    const stats = fs.statSync(req.file.path);
    if (stats.size < MIN_RESUME_BYTES) {
      fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: 'Resume too small (min 50 KB)', form });
    }

    // Save application
    const apps = readJSON(APPS_FILE);
    const application = {
      id: Date.now(),
      jobId: job.id,
      name, email, phone, cover,
      resume: '/uploads/' + path.basename(req.file.path),
      appliedAt: new Date().toISOString()
    };
    apps.push(application);
    writeJSON(APPS_FILE, apps);

    // Send confirmation email
    const companyEmail = process.env.SMTP_USER || 'contact@anjanideepa.example';
    const mailOptions = {
      from: companyEmail,
      to: application.email,
      subject: `Application Received: ${job.title} at Anjani Deepa Enterprises`,
      text: `Dear ${application.name},\n\nWe received your application for ${job.title}.\n\nRegards,\nAnjani Deepa Enterprises`,
      html: `<p>Dear ${application.name},</p><p>We received your application for <strong>${job.title}</strong>.</p><p>Regards,<br/>Anjani Deepa Enterprises</p>`,
      attachments: [{ filename: path.basename(application.resume), path: path.join(__dirname, application.resume) }]
    };
    if (mailer) {
      try {
        await mailer.sendMail(mailOptions);
        console.log('Confirmation email sent to', application.email);
        logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: true });
      } catch (e) {
        console.error('Error sending email', e);
        logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: false, error: String(e) });
      }
    } else {
      console.log('Mailer not configured, email not sent.');
      logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: false, note: 'Mailer not configured' });
    }

    res.render('apply-success', { job, application });
  });
});

app.get('/contact', (req, res) => res.render('contact'));

// =========================
// Admin
// =========================
const ADMIN_USER = {
  username: process.env.ADMIN_USERNAME,
  password: process.env.ADMIN_PASSWORD
};

app.get('/admin', (req, res) => {
  if (!req.session.user) return res.render('admin-login', { error: null, applications: [] });
  const jobs = readJSON(JOBS_FILE);
  const applications = readJSON(APPS_FILE);
  res.render('admin', { jobs, message: null, applications });
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER.username && password === ADMIN_USER.password) {
    req.session.user = { username };
    return res.redirect('/admin');
  }
  res.render('admin-login', { error: 'Invalid credentials' });
});

app.post('/admin/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// =========================
// Start server
// =========================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
