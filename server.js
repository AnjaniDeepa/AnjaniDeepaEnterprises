// ==================== Load environment ====================
require('dotenv').config();
// At the top, after require('dotenv') and other modules
const nodemailer = require('nodemailer');

const express = require('express');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const session = require('express-session');
const multer = require('multer');
const sgTransport = require('nodemailer-sendgrid-transport');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== View Engine ====================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ==================== Middleware ====================
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(session({ secret: process.env.SESSION_SECRET || 'change-this-secret', resave: false, saveUninitialized: false }));

// ==================== File Uploads ====================
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
    if (allowedExt.includes(ext)) return cb(null, true);
    cb(new Error('Invalid file type. Only PDF, DOC, DOCX allowed'));
  }
});



let mailer = null;

if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });

  // Test connection immediately
  mailer.verify((err, success) => {
    if (err) {
      console.error('Mailer connection failed:', err);
    } else {
      console.log('Mailer ready to send messages');
    }
  });
} else {
  console.log('Mailer not configured. Emails will not be sent.');
}

// ==================== Email Logging ====================
const MAIL_LOG = path.join(__dirname, 'data', 'email-log.jsonl');
function logMailAttempt(entry) {
  try {
    const line = JSON.stringify({ timestamp: new Date().toISOString(), ...entry }) + '\n';
    fs.appendFileSync(MAIL_LOG, line, 'utf8');
  } catch (e) {
    console.error('Failed to write mail log', e);
  }
}

// ==================== Data Files ====================
const JOBS_FILE = path.join(__dirname, 'data', 'jobs.json');
const APPS_FILE = path.join(__dirname, 'data', 'applications.json');

function readJobs() { try { return JSON.parse(fs.readFileSync(JOBS_FILE, 'utf8')); } catch (e) { return []; } }
function writeJobs(jobs) { fs.writeFileSync(JOBS_FILE, JSON.stringify(jobs, null, 2), 'utf8'); }
function readApplications() { try { return JSON.parse(fs.readFileSync(APPS_FILE, 'utf8')); } catch (e) { return []; } }
function writeApplications(apps) { fs.writeFileSync(APPS_FILE, JSON.stringify(apps, null, 2), 'utf8'); }

// ==================== Middleware ====================
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// ==================== Routes ====================
app.get('/', (req, res) => { res.render('home', { jobs: readJobs() }); });
app.get('/about', (req, res) => { res.render('about'); });
app.get('/jobs', (req, res) => { res.render('jobs', { jobs: readJobs() }); });

app.get('/jobs/:id/apply', (req, res) => {
  const job = readJobs().find(j => String(j.id) === String(req.params.id));
  if (!job) return res.status(404).send('Job not found');
  res.render('apply', { job, error: null, form: {} });
});

// ==================== Job Application ====================
app.post('/jobs/:id/apply', (req, res) => {
  upload.single('resume')(req, res, async (err) => {
    const job = readJobs().find(j => String(j.id) === String(req.params.id));
    if (!job) return res.status(404).send('Job not found');

    const { name, email, phone, cover } = req.body || {};
    const form = { name, email, phone, cover };

    if (err) return res.render('apply', { job, error: err.message, form });

    if (!name || !email || !phone || !cover) return res.render('apply', { job, error: 'All fields required', form });
    if (!req.file) return res.render('apply', { job, error: 'Resume required', form });

    // Check file size
    try {
      const stats = fs.statSync(req.file.path);
      if (stats.size < MIN_RESUME_BYTES) throw new Error('Resume too small');
    } catch (e) {
      return res.render('apply', { job, error: 'Resume invalid', form });
    }

    // Save application
    const apps = readApplications();
    const application = { id: Date.now(), jobId: job.id, name, email, phone, cover, resume: '/uploads/' + path.basename(req.file.path), appliedAt: new Date().toISOString() };
    apps.push(application);
    writeApplications(apps);

    if (mailer) {
  mailer.sendMail(mailOptions)
    .then(() => {
      console.log('Confirmation email sent to', application.email);
      logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: true });
    })
    .catch(err => {
      console.error('Error sending email', err);
      logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: false, error: String(err) });
    });
} else {
  console.log('Email (not sent) would be:', mailOptions);
  logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: false, note: 'not configured' });
}

// Immediately render success page without waiting for email
res.render('apply-success', { job, application });


// ==================== Contact ====================
app.get('/contact', (req, res) => { res.render('contact'); });

// ==================== Admin ====================
const ADMIN_USER = { username: process.env.ADMIN_USERNAME, password: process.env.ADMIN_PASSWORD };

app.get('/admin', (req, res) => {
  if (!req.session.user) return res.render('admin-login', { error: null });
  res.render('admin', { jobs: readJobs(), applications: readApplications() });
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER.username && password === ADMIN_USER.password) {
    req.session.user = { username };
    return res.redirect('/admin');
  }
  res.render('admin-login', { error: 'Invalid credentials' });
});

app.post('/admin/logout', (req, res) => { req.session.destroy(() => res.redirect('/')); });

// ==================== Admin Job CRUD ====================
app.post('/admin/jobs', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const { title, location, description, openings, experience } = req.body;
  const jobs = readJobs();
  jobs.push({ id: Date.now(), title, location, description, openings: parseInt(openings)||1, experience: parseInt(experience)||0, postedAt: new Date().toISOString() });
  writeJobs(jobs);
  res.redirect('/admin');
});

app.post('/admin/jobs/:id/delete', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const id = req.params.id;
  const jobs = readJobs().filter(j => String(j.id) !== id);
  writeJobs(jobs);
  // delete applications for that job
  const apps = readApplications().filter(a => String(a.jobId) !== id);
  writeApplications(apps);
  res.redirect('/admin');
});

// ==================== Admin Application Delete ====================
app.post('/admin/applications/:id/delete', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const id = req.params.id;
  const apps = readApplications().filter(a => String(a.id) !== id);
  writeApplications(apps);
  res.redirect('/admin');
});

// ==================== Application Rejection ====================
app.post('/admin/applications/:id/reject', async (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const id = req.params.id;
  const apps = readApplications();
  const index = apps.findIndex(a => String(a.id) === id);
  if (index === -1) return res.redirect('/admin');

  const appToReject = apps[index];
  const job = readJobs().find(j => j.id === appToReject.jobId);
  const jobTitle = job ? job.title : 'the job';

  // Send rejection email
  if (mailer) {
    try {
      await mailer.sendMail({
        from: process.env.SMTP_USER || 'contact@anjanideepa.example',
        to: appToReject.email,
        subject: `Update on Your Application for ${jobTitle}`,
        text: `Dear ${appToReject.name},\nWe regret to inform you...`,
        html: `<p>Dear ${appToReject.name},</p><p>We regret to inform you...</p>`
      });
      logMailAttempt({ to: appToReject.email, subject: `Update on Your Application for ${jobTitle}`, sent: true });
    } catch (e) {
      console.error('Email error:', e);
      logMailAttempt({ to: appToReject.email, subject: `Update on Your Application for ${jobTitle}`, sent: false, error: String(e) });
    }
  }

  // Delete application and resume
  if (appToReject.resume) {
    const fullPath = path.join(__dirname, appToReject.resume.replace(/^\/+/, ''));
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  }

  apps.splice(index, 1);
  writeApplications(apps);
  res.redirect('/admin');
});

// ==================== Start Server ====================
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`))
