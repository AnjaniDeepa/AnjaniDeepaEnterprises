// Load environment variables
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

// ===================== VIEWS & STATIC =====================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(session({ secret: process.env.SESSION_SECRET || 'change-this-secret', resave: false, saveUninitialized: false }));

// ===================== FILE UPLOAD =====================
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const MIN_RESUME_BYTES = 50 * 1024;
const MAX_RESUME_BYTES = 5 * 1024 * 1024;

const allowedMime = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
];
const allowedExt = ['.pdf', '.doc', '.docx'];

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'))
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_RESUME_BYTES },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedExt.includes(ext) && allowedMime.includes(file.mimetype)) return cb(null, true);
    cb(new Error('Invalid file type. Only PDF, DOC, DOCX are allowed.'));
  }
});

// ===================== EMAIL CONFIG =====================
let mailer = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
  console.log('Mailer configured successfully');
} else {
  console.log('Mailer not configured. Emails will not be sent.');
}

// ===================== DATA FILES =====================
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const JOBS_FILE = path.join(DATA_DIR, 'jobs.json');
const APPS_FILE = path.join(DATA_DIR, 'applications.json');
const MAIL_LOG = path.join(DATA_DIR, 'email-log.jsonl');

function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return []; }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

function logMail(entry) {
  const line = JSON.stringify({ timestamp: new Date().toISOString(), ...entry }) + '\n';
  fs.appendFileSync(MAIL_LOG, line, 'utf8');
}

// ===================== MIDDLEWARE =====================
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// ===================== ROUTES =====================

// Home & About
app.get('/', (req, res) => res.render('home', { jobs: readJSON(JOBS_FILE) }));
app.get('/about', (req, res) => res.render('about'));
app.get('/jobs', (req, res) => res.render('jobs', { jobs: readJSON(JOBS_FILE) }));

// Apply to job
app.get('/jobs/:id/apply', (req, res) => {
  const job = readJSON(JOBS_FILE).find(j => String(j.id) === String(req.params.id));
  if (!job) return res.status(404).send('Job not found');
  res.render('apply', { job, error: null });
});

app.post('/jobs/:id/apply', (req, res) => {
  upload.single('resume')(req, res, async (err) => {
    const job = readJSON(JOBS_FILE).find(j => String(j.id) === String(req.params.id));
    if (!job) return res.status(404).send('Job not found');

    const { name, email, phone, cover } = req.body || {};
    const form = { name, email, phone, cover };

    if (err) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: err.message, form });
    }

    if (!name || !email || !phone || !cover || !req.file) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: 'All fields are required and resume must be uploaded', form });
    }

    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) return res.render('apply', { job, error: 'Invalid email', form });

    const phoneRe = /^[0-9+\-\s]{7,20}$/;
    if (!phoneRe.test(phone)) return res.render('apply', { job, error: 'Invalid phone', form });

    const stats = fs.statSync(req.file.path);
    if (stats.size < MIN_RESUME_BYTES) {
      fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: 'Resume too small', form });
    }

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

    // send confirmation email
    const companyEmail = process.env.SMTP_USER || 'contact@anjanideepa.example';
    const mailOptions = {
      from: companyEmail,
      to: application.email,
      subject: `Application Received: ${job.title}`,
      text: `Dear ${application.name},\n\nWe received your application for ${job.title} at Anjani Deepa Enterprises.`,
      html: `<p>Dear ${application.name},</p><p>We received your application for <strong>${job.title}</strong> at Anjani Deepa Enterprises.</p>`,
      attachments: [{ filename: path.basename(req.file.path), path: req.file.path }]
    };

    if (mailer) {
      try {
        await mailer.sendMail(mailOptions);
        logMail({ to: application.email, subject: mailOptions.subject, sent: true });
        console.log('Email sent to', application.email);
      } catch (e) {
        logMail({ to: application.email, subject: mailOptions.subject, sent: false, error: String(e) });
        console.error('Email error:', e);
      }
    } else {
      logMail({ to: application.email, subject: mailOptions.subject, sent: false, note: 'Mailer not configured' });
      console.log('Mailer not configured. Email not sent.');
    }

    res.render('apply-success', { job, application });
  });
});

// Contact page
app.get('/contact', (req, res) => res.render('contact'));

// ===================== ADMIN =====================
const ADMIN_USER = {
  username: process.env.ADMIN_USERNAME,
  password: process.env.ADMIN_PASSWORD
};

app.get('/admin', (req, res) => {
  if (!req.session.user) return res.render('admin-login', { error: null, applications: [] });
  res.render('admin', { jobs: readJSON(JOBS_FILE), applications: readJSON(APPS_FILE), message: null });
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER.username && password === ADMIN_USER.password) {
    req.session.user = { username };
    return res.redirect('/admin');
  }
  res.render('admin-login', { error: 'Invalid credentials', applications: [] });
});

app.post('/admin/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// Add / Delete jobs and applications
app.post('/admin/jobs', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const jobs = readJSON(JOBS_FILE);
  const id = Date.now();
  const { title, location, description, openings, experience } = req.body;
  jobs.push({ id, title, location, description, openings: parseInt(openings) || 1, experience: parseInt(experience) || 0, postedAt: new Date().toISOString() });
  writeJSON(JOBS_FILE, jobs);
  res.redirect('/admin');
});

app.post('/admin/jobs/:id/delete', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const id = String(req.params.id);
  let jobs = readJSON(JOBS_FILE);
  jobs = jobs.filter(j => String(j.id) !== id);
  writeJSON(JOBS_FILE, jobs);

  let apps = readJSON(APPS_FILE);
  const remaining = [];
  apps.forEach(app => {
    if (String(app.jobId) === id && app.resume) {
      const full = path.join(__dirname, app.resume.replace(/^\/+/, '').split('/').join(path.sep));
      if (fs.existsSync(full)) fs.unlinkSync(full);
    } else remaining.push(app);
  });
  writeJSON(APPS_FILE, remaining);
  res.redirect('/admin');
});

// Reject application
app.post('/admin/applications/:id/reject', async (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const id = String(req.params.id);
  const apps = readJSON(APPS_FILE);
  const appIndex = apps.findIndex(a => String(a.id) === id);
  if (appIndex === -1) return res.redirect('/admin');

  const application = apps[appIndex];
  const job = readJSON(JOBS_FILE).find(j => j.id === application.jobId);

  const mailOptions = {
    from: process.env.SMTP_USER || 'contact@anjanideepa.example',
    to: application.email,
    subject: `Update on Your Application for ${job?.title || 'a job'}`,
    text: `Dear ${application.name},\n\nWe regret to inform you that your application was not successful.`,
    html: `<p>Dear ${application.name},</p><p>We regret to inform you that your application for <strong>${job?.title || 'a job'}</strong> was not successful.</p>`
  };

  if (mailer) {
    try { await mailer.sendMail(mailOptions); logMail({ to: application.email, subject: mailOptions.subject, sent: true, note: 'Rejection' }); } 
    catch (e) { logMail({ to: application.email, subject: mailOptions.subject, sent: false, error: String(e), note: 'Rejection' }); }
  }

  // Delete resume if exists
  if (application.resume) {
    const full = path.join(__dirname, application.resume.replace(/^\/+/, '').split('/').join(path.sep));
    if (fs.existsSync(full)) fs.unlinkSync(full);
  }

  apps.splice(appIndex, 1);
  writeJSON(APPS_FILE, apps);
  res.redirect('/admin');
});

// ===================== START SERVER =====================
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
