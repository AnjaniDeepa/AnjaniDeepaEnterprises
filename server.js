// load environment variables from .env if present
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
// serve uploads directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(session({ secret: 'change-this-secret', resave: false, saveUninitialized: false }));

// multer for file uploads
const multer = require('multer');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, uploadsDir); },
  filename: function (req, file, cb) { cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_')); }
});
// Resume size limits
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
  fileFilter: function (req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedExt.includes(ext) && allowedMime.includes(file.mimetype)) return cb(null, true);
    if (allowedExt.includes(ext)) return cb(null, true);
    cb(new Error('Invalid file type. Only PDF, DOC and DOCX are allowed'));
  }
});

// Resend setup for API-based email sending
const { Resend } = require('resend');
let resend = null;
let mailerConfigured = false;
const COMPANY_EMAIL = process.env.SMTP_USER; // Use SMTP_USER for 'from' address

if (process.env.RESEND_API_KEY) {
  resend = new Resend(process.env.RESEND_API_KEY);
  mailerConfigured = true;
  console.log('Resend Mailer configured via API.');
} else {
  // Fallback/Warning for environments without RESEND_API_KEY
  console.log('Resend Mailer not configured. Set RESEND_API_KEY to enable email sending.');
}

// email logging (write attempts to a newline-delimited JSON log)
const MAIL_LOG = path.join(__dirname, 'data', 'email-log.jsonl');
function logMailAttempt(entry) {
  try {
    const line = JSON.stringify(Object.assign({ timestamp: new Date().toISOString() }, entry)) + '\n';
    fs.appendFileSync(MAIL_LOG, line, 'utf8');
  } catch (e) {
    console.error('Failed to write mail log', e);
  }
}

const JOBS_FILE = path.join(__dirname, 'data', 'jobs.json');
const APPS_FILE = path.join(__dirname, 'data', 'applications.json');
function readJobs() {
  try {
    const raw = fs.readFileSync(JOBS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return [];
  }
}

function writeJobs(jobs) {
  fs.writeFileSync(JOBS_FILE, JSON.stringify(jobs, null, 2), 'utf8');
}

function readApplications() {
  try {
    const raw = fs.readFileSync(APPS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return [];
  }
}

function writeApplications(apps) {
  fs.writeFileSync(APPS_FILE, JSON.stringify(apps, null, 2), 'utf8');
}

// Middleware to expose user to views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

app.get('/', (req, res) => {
  const jobs = readJobs();
  res.render('home', { jobs });
});

app.get('/about', (req, res) => {
  res.render('about');
});

app.get('/jobs', (req, res) => {
  const jobs = readJobs();
  res.render('jobs', { jobs });
});

// Apply to a job form
app.get('/jobs/:id/apply', (req, res) => {
  const jobs = readJobs();
  const job = jobs.find(j => String(j.id) === String(req.params.id));
  if (!job) return res.status(404).send('Job not found');
  res.render('apply', { job, error: null });
});

// NOTE: Changed to async to use await for Resend API call
app.post('/jobs/:id/apply', async (req, res) => { 
  upload.single('resume')(req, res, async (err) => { // Added async here too
    const jobs = readJobs();
    const job = jobs.find(j => String(j.id) === String(req.params.id));
    if (!job) return res.status(404).send('Job not found');
    const { name, email, phone, cover } = req.body || {};
    const form = { name: name || '', email: email || '', phone: phone || '', cover: cover || '' };

    if (err) {
      if (req.file && req.file.path && fs.existsSync(req.file.path)) {
        try { fs.unlinkSync(req.file.path); } catch (e) { console.error('Failed to remove bad upload', e); }
      }
      return res.render('apply', { job, error: err.message || 'File upload error', form });
    }

    if (!name || !email || !phone || !cover) {
      if (req.file && req.file.path && fs.existsSync(req.file.path)) {
        try { fs.unlinkSync(req.file.path); } catch (e) { }
      }
      return res.render('apply', { job, error: 'All fields are required', form });
    }

    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) {
      if (req.file && req.file.path && fs.existsSync(req.file.path)) try { fs.unlinkSync(req.file.path); } catch (e) { }
      return res.render('apply', { job, error: 'Please enter a valid email address', form });
    }

    const phoneRe = /^[0-9+\-\s]{7,20}$/;
    if (!phoneRe.test(phone)) {
      if (req.file && req.file.path && fs.existsSync(req.file.path)) try { fs.unlinkSync(req.file.path); } catch (e) { }
      return res.render('apply', { job, error: 'Please enter a valid phone number', form });
    }

    if (!req.file) return res.render('apply', { job, error: 'Resume is required and must be PDF/DOC/DOCX within size limits', form });

    try {
      const stats = fs.statSync(req.file.path);
      if (stats.size < MIN_RESUME_BYTES) {
        try { fs.unlinkSync(req.file.path); } catch (e) { }
        return res.render('apply', { job, error: 'Resume file is too small (min 50 KB)', form });
      }
    } catch (e) {
      return res.render('apply', { job, error: 'Could not process resume file', form });
    }

    const apps = readApplications();
    const application = { id: Date.now(), jobId: job.id, name, email, phone, cover, resume: null, appliedAt: new Date().toISOString() };
    if (req.file) {
      application.resume = '/uploads/' + path.basename(req.file.path);
    }
    apps.push(application);
    writeApplications(apps);

    // Prepare email content
    const mailOptions = {
      from: COMPANY_EMAIL,
      to: application.email,
      subject: `Application Received: ${job.title} at Anjani Deepa Enterprises`,
      text: `Dear ${application.name},\n\nSuccess! We've received your application for the ${job.title} role at Anjani Deepa Enterprises.\n\nYour profile is now under review by our hiring team. We appreciate your interest in joining us and will be in touch if your experience matches this exciting opportunity.\n\nGood luck!\n\nBest regards,\nThe Recruitment Team\nAnjani Deepa Enterprises`,
      html: `<p>Dear ${application.name},</p>
            <h2>🎉 Application Received Successfully!</h2>
            <p>Thank you for submitting your application for the <strong>${job.title}</strong> position at <strong>Anjani Deepa Enterprises</strong>.</p>
            <p>Your passion for the role is clear, and your profile is now under careful review by our dedicated hiring team. We're excited to evaluate your experience.</p>
            <p>We will contact you directly if your background and qualifications align with this exciting opportunity.</p>
            <p>Wishing you the very best of luck!</p>
            <p>Best regards,<br/>The Recruitment Team<br/>Anjani Deepa Enterprises</p>`
    };
    
    // Send email using Resend API
    if (mailerConfigured && resend) {
      try {
        // Resend API: Only sending text/html body for simplicity.
        // Attaching the file would require reading it into a buffer and configuring the 'attachments' array differently.
        await resend.emails.send({
          from: COMPANY_EMAIL,
          to: application.email,
          subject: mailOptions.subject,
          text: mailOptions.text,
          html: mailOptions.html
        });
        
        console.log('Confirmation email sent to', application.email);
        logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: true });
        
      } catch (err) {
        console.error('Error sending email via Resend API', err);
        logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: false, error: String(err) });
      }

    } else {
      console.log('Email (not sent) would be:', mailOptions);
      logMailAttempt({ to: application.email, subject: mailOptions.subject, sent: false, note: 'Resend not configured' });
    }
    
    res.render('apply-success', { job, application });
  });
});

app.get('/contact', (req, res) => {
  res.render('contact');
});

// ====================== ADMIN LOGIN SECTION =========================

// Admin credentials now stored in environment variables
const ADMIN_USER = {
  username: process.env.ADMIN_USERNAME,
  password: process.env.ADMIN_PASSWORD
};

if (!ADMIN_USER.username || !ADMIN_USER.password) {
  console.warn('⚠️  ADMIN_USERNAME or ADMIN_PASSWORD not set in environment variables.');
}

app.get('/admin', (req, res) => {
  if (!req.session.user) {
    return res.render('admin-login', { error: null, applications: [] });
  }
  const jobs = readJobs();
  const applications = readApplications();
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

app.post('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ===================================================================

// Protected: add job
app.post('/admin/jobs', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const { title, location, description, openings, experience } = req.body;
  const jobs = readJobs();
  const id = Date.now();
  const openingsNum = Math.max(1, parseInt(openings || '1', 10) || 1);
  const expNum = Math.max(0, Math.min(50, parseInt(experience || '0', 10) || 0));
  jobs.push({ id, title, location, description, openings: openingsNum, experience: expNum, postedAt: new Date().toISOString() });
  writeJobs(jobs);
  res.redirect('/admin');
});

// Protected: delete job
app.post('/admin/jobs/:id/delete', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const jobs = readJobs();
  const id = String(req.params.id);
  const filtered = jobs.filter(j => String(j.id) !== id);
  writeJobs(filtered);
  const after = readJobs();
  const stillExists = after.some(j => String(j.id) === id);
  if (stillExists) {
    console.error('Failed to delete job', id);
    return res.status(500).send('Failed to delete job');
  }

  try {
    const apps = readApplications();
    const remaining = [];
    apps.forEach(app => {
      if (String(app.jobId) === id) {
        if (app.resume) {
          let resumePath = app.resume;
          resumePath = resumePath.replace(/^\/+/, '');
          resumePath = resumePath.split('/').join(path.sep).split('\\').join(path.sep);
          const full = path.join(__dirname, resumePath);
          try {
            if (fs.existsSync(full)) fs.unlinkSync(full);
          } catch (e) {
            console.error('Failed to delete resume file', full, e);
          }
        }
      } else {
        remaining.push(app);
      }
    });
    writeApplications(remaining);
  } catch (e) {
    console.error('Error while removing applications for job', id, e);
  }

  res.redirect('/admin');
});

// Protected: delete single application
app.post('/admin/applications/:id/delete', (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const id = String(req.params.id);
  try {
    const apps = readApplications();
    const remaining = [];
    apps.forEach(app => {
      if (String(app.id) === id) {
        if (app.resume) {
          let resumePath = app.resume.replace(/^\/+/, '');
          resumePath = resumePath.split('/').join(path.sep).split('\\').join(path.sep);
          const full = path.join(__dirname, resumePath);
          try {
            if (fs.existsSync(full)) fs.unlinkSync(full);
          } catch (e) {
            console.error('Failed to delete resume file for application', id, full, e);
          }
        }
      } else {
        remaining.push(app);
      }
    });
    writeApplications(remaining);
    return res.redirect('/admin');
  } catch (e) {
    console.error('Error deleting application', id, e);
    return res.status(500).send('Error deleting application');
  }
});

// NEW: Protected: Reject application
app.post('/admin/applications/:id/reject', async (req, res) => {
  if (!req.session.user) return res.status(403).send('Forbidden');
  const id = String(req.params.id);
  let applicationToReject;
  let jobTitle = 'a job';

  try {
    const apps = readApplications();
    const jobs = readJobs();
    const appIndex = apps.findIndex(app => String(app.id) === id);
    if (appIndex === -1) {
      console.error('Application not found for rejection:', id);
      return res.redirect('/admin');
    }

    applicationToReject = apps[appIndex];
    const job = jobs.find(j => j.id === applicationToReject.jobId);
    if (job) jobTitle = job.title;

    // Prepare email content
    const mailOptions = {
      from: COMPANY_EMAIL,
      to: applicationToReject.email,
      subject: `Update on Your Application for ${jobTitle}`,
      text: `Dear ${applicationToReject.name},\n\nThank you for your interest in the ${jobTitle} position at Anjani Deepa Enterprises.\n\nWe appreciate you taking the time to apply. After careful review, we regret to inform you that we will not be moving forward with your application at this time.\n\nWe wish you the best in your job search and encourage you to follow our careers page for future opportunities.\n\nSincerely,\nThe Recruitment Team\nAnjani Deepa Enterprises`,
      html: `<p>Dear ${applicationToReject.name},</p>
            <p>Thank you for your interest in the <strong>${jobTitle}</strong> position at <strong>Anjani Deepa Enterprises</strong>.</p>
            <p>We appreciate you taking the time to apply. After careful review, we regret to inform you that we will not be moving forward with your application at this time.</p>
            <p>We wish you the best in your job search and encourage you to follow our careers page for future opportunities.</p>
            <p>Sincerely,<br/>The Recruitment Team<br/>Anjani Deepa Enterprises</p>`
    };

    // Send email using Resend API
    if (mailerConfigured && resend) {
      try {
        await resend.emails.send({
          from: COMPANY_EMAIL,
          to: applicationToReject.email,
          subject: mailOptions.subject,
          text: mailOptions.text,
          html: mailOptions.html
        });
        console.log('Rejection email sent to', applicationToReject.email);
        logMailAttempt({ to: applicationToReject.email, subject: mailOptions.subject, sent: true, note: 'Rejection' });
      } catch (err) {
        console.error('Error sending rejection email via Resend API', err);
        logMailAttempt({ to: applicationToReject.email, subject: mailOptions.subject, sent: false, note: 'Rejection - Resend error' });
      }
    } else {
      console.log('Rejection email (not sent, Resend not configured) would be:', mailOptions);
      logMailAttempt({ to: applicationToReject.email, subject: mailOptions.subject, sent: false, note: 'Rejection - not configured' });
    }

    const remainingApps = apps.filter((_, index) => index !== appIndex);

    if (applicationToReject.resume) {
      let resumePath = applicationToReject.resume.replace(/^\/+/, '');
      resumePath = resumePath.split('/').join(path.sep).split('\\').join(path.sep);
      const full = path.join(__dirname, resumePath);
      try {
        if (fs.existsSync(full)) fs.unlinkSync(full);
      } catch (e) {
        console.error('Failed to delete resume file after rejection:', full, e);
      }
    }

    writeApplications(remainingApps);
    console.log('Application rejected and deleted:', id);

    return res.redirect('/admin');

  } catch (e) {
    console.error('Error processing application rejection:', id, e);
    return res.redirect('/admin');
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});