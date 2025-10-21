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

// ========== Express setup ==========
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

// ========== Multer setup ==========
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'))
});

const MIN_RESUME_BYTES = 50 * 1024;
const MAX_RESUME_BYTES = 5 * 1024 * 1024;
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

// ========== Nodemailer ==========
let mailer = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
} else console.log('⚠️ Mailer not configured. Emails will not be sent.');

// ========== Data helpers ==========
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
function logMailAttempt(entry) {
  try { fs.appendFileSync(MAIL_LOG, JSON.stringify({ timestamp: new Date().toISOString(), ...entry }) + '\n'); } 
  catch (e) { console.error('Failed to write mail log', e); }
}

// ========== Middleware ==========
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// ========== Public routes ==========
app.get('/', (req, res) => res.render('home', { jobs: readJSON(JOBS_FILE) }));
app.get('/about', (req, res) => res.render('about'));
app.get('/jobs', (req, res) => res.render('jobs', { jobs: readJSON(JOBS_FILE) }));

app.get('/jobs/:id/apply', (req, res) => {
  const job = readJSON(JOBS_FILE).find(j => String(j.id) === String(req.params.id));
  if (!job) return res.status(404).send('Job not found');
  res.render('apply', { job, error: null });
});

// Apply POST
app.post('/jobs/:id/apply', (req, res) => {
  upload.single('resume')(req, res, async err => {
    const job = readJSON(JOBS_FILE).find(j => String(j.id) === String(req.params.id));
    if (!job) return res.status(404).send('Job not found');

    const { name, email, phone, cover } = req.body || {};
    const form = { name, email, phone, cover };

    if (err) {
      if (req.file?.path) fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: err.message || 'File upload error', form });
    }

    if (!name || !email || !phone || !cover) {
      if (req.file?.path) fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: 'All fields required', form });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (req.file?.path) fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: 'Invalid email', form });
    }
    if (!/^[0-9+\-\s]{7,20}$/.test(phone)) {
      if (req.file?.path) fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: 'Invalid phone', form });
    }
    if (!req.file) return res.render('apply', { job, error: 'Resume required', form });

    const stats = fs.statSync(req.file.path);
    if (stats.size < MIN_RESUME_BYTES) {
      fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return res.render('apply', { job, error: 'Resume too small (50 KB min)', form });
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

    // Send email
    const companyEmail = process.env.SMTP_USER || 'contact@anjanideepa.example';
    const mailOptions = {
      from: companyEmail,
      to: application.email,
      subject: `Application Received: ${job.title}`,
      text: `Dear ${application.name}, We received your application for ${job.title}.`,
      html: `<p>Dear ${application.name},</p><p>We received your application for <strong>${job.title}</strong>.</p><p>Regards, Anjani Deepa Enterprises</p>`,
      attachments: [{ filename: path.basename(application.resume), path: path.join(__dirname, application.resume) }]
    };
    if (mailer) {
      try {
        await mailer.sendMail(mailOptions);
        logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: true });
      } catch (e) {
        console.error('Email error', e);
        logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: false, error: String(e) });
      }
    } else logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: false, note: 'Mailer not configured' });

    res.render('apply-success', { job, application });
  });
});

app.get('/contact', (req, res) => res.render('contact'));

// ========== Admin ==========
const ADMIN_USER = { username: process.env.ADMIN_USERNAME, password: process.env.ADMIN_PASSWORD };

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
  res.render('admin-login', { error: 'Invalid credentials' });
});

app.post('/admin/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// ========== Admin: Jobs ==========
app.post('/admin/jobs', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const { title, location, description, openings, experience } = req.body;
  const jobs = readJSON(JOBS_FILE);
  jobs.push({
    id: Date.now(),
    title, location, description,
    openings: Math.max(1, parseInt(openings) || 1),
    experience: Math.max(0, Math.min(50, parseInt(experience) || 0)),
    postedAt: new Date().toISOString()
  });
  writeJSON(JOBS_FILE, jobs);
  res.redirect('/admin');
});

app.post('/admin/jobs/:id/delete', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const id = String(req.params.id);
  let jobs = readJSON(JOBS_FILE);
  jobs = jobs.filter(j => String(j.id) !== id);
  writeJSON(JOBS_FILE, jobs);

  // Delete associated applications & resumes
  let apps = readJSON(APPS_FILE);
  apps.forEach(app => {
    if (String(app.jobId) === id && app.resume) {
      const fullPath = path.join(__dirname, app.resume.replace(/^\/+/, '').split('/').join(path.sep));
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }
  });
  apps = apps.filter(app => String(app.jobId) !== id);
  writeJSON(APPS_FILE, apps);

  res.redirect('/admin');
});

// ========== Admin: Applications ==========
app.post('/admin/applications/:id/delete', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const id = String(req.params.id);
  let apps = readJSON(APPS_FILE);
  apps.forEach(app => {
    if (String(app.id) === id && app.resume) {
      const fullPath = path.join(__dirname, app.resume.replace(/^\/+/, '').split('/').join(path.sep));
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }
  });
  apps = apps.filter(app => String(app.id) !== id);
  writeJSON(APPS_FILE, apps);
  res.redirect('/admin');
});

// ========== Admin: Reject application ==========
app.post('/admin/applications/:id/reject', async (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const id = String(req.params.id);
  const apps = readJSON(APPS_FILE);
  const appIndex = apps.findIndex(a => String(a.id) === id);
  if (appIndex === -1) return res.redirect('/admin');

  const appToReject = apps[appIndex];
  const job = readJSON(JOBS_FILE).find(j => j.id === appToReject.jobId);

  // Send rejection email
  const companyEmail = process.env.SMTP_USER || 'contact@anjanideepa.example';
  const mailOptions = {
    from: companyEmail,
    to: appToReject.email,
    subject: `Update on your application for ${job?.title || 'a job'}`,
    text: `Dear ${appToReject.name}, we regret to inform you...`,
    html: `<p>Dear ${appToReject.name},</p><p>We regret to inform you...</p>`
  };
  if (mailer) {
    try { await mailer.sendMail(mailOptions); logMailAttempt({ to: appToReject.email, subject: mailOptions.subject, sent: true }); }
    catch (e) { console.error('Email error', e); logMailAttempt({ to: appToReject.email, subject: mailOptions.subject, sent: false, error: String(e) }); }
  }

  // Remove resume file
  if (appToReject.resume) {
    const fullPath = path.join(__dirname, appToReject.resume.replace(/^\/+/, '').split('/').join(path.sep));
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  }

  apps.splice(appIndex, 1);
  writeJSON(APPS_FILE, apps);
  res.redirect('/admin');
});

// ========== Start server ==========
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
