// load environment variables from .env if present
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const session = require('express-session');

// Use native fetch if available (Node 18+), otherwise require node-fetch
const fetch = global.fetch || require('node-fetch');

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

// === EMAILJS SETUP ===
const EMAILJS_URL = 'https://api.emailjs.com/api/v1.0/email/send';
const EMAILJS_SERVICE_ID = process.env.EMAILJS_SERVICE_ID;
const EMAILJS_USER_ID = process.env.EMAILJS_USER_ID;
const EMAILJS_TEMPLATE_CONFIRM = process.env.EMAILJS_TEMPLATE_ID_CONFIRM; // ID for 'welcome' template
const EMAILJS_TEMPLATE_REJECT = process.env.EMAILJS_TEMPLATE_ID_REJECT; // ID for 'auto_reply' template

let mailerConfigured = false;
// Used as the sender email. Must be the connected Gmail account: anjanideepaenterprises1@gmail.com
const COMPANY_EMAIL = process.env.SMTP_USER || 'contact@anjanideepa.example';

if (EMAILJS_SERVICE_ID && EMAILJS_USER_ID && EMAILJS_TEMPLATE_CONFIRM && EMAILJS_TEMPLATE_REJECT) {
    mailerConfigured = true;
    console.log('EmailJS Mailer configured via API.');
} else {
    console.log('EmailJS Mailer not fully configured. Check all EmailJS environment variables.');
}

// Function to send email using EmailJS API
async function sendEmailJS(templateId, templateParams) {
    if (!mailerConfigured) {
        throw new Error('EmailJS not configured.');
    }

    const payload = {
        service_id: EMAILJS_SERVICE_ID,
        template_id: templateId,
        user_id: EMAILJS_USER_ID,
        template_params: templateParams,
    };

    try {
        const response = await fetch(EMAILJS_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });

        if (response.ok) {
            console.log('EmailJS Response: Success');
            return true;
        } else {
            const errorText = await response.text();
            console.error(`EmailJS Response Error (${response.status}): ${errorText}`);
            throw new Error(`EmailJS API failed with status ${response.status}: ${errorText}`);
        }
    } catch (e) {
        console.error('EmailJS Fetch Error:', e);
        throw e;
    }
}
// ===========================================

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

// NOTE: Set as async to use await for EmailJS API call
app.post('/jobs/:id/apply', async (req, res) => {
    upload.single('resume')(req, res, async (err) => {
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

        // Prepare EmailJS template parameters
        const templateParams = {
            applicant_name: name,
            applicant_email: email,
            job_title: job.title,
            job_location: job.location,
            phone_number: phone,
            cover_letter: cover,
            company_email: COMPANY_EMAIL, // Used as the sender in the template
            // ✅ FIX: Added 'email' key, which is required if template 'To Email' is {{email}}
            email: email
        };

        // Send email using EmailJS API (using the 'welcome' template ID)
        if (mailerConfigured) {
            try {
                await sendEmailJS(EMAILJS_TEMPLATE_CONFIRM, templateParams);

                console.log('Confirmation email sent to', application.email, 'via EmailJS');
                logMailAttempt({ to: application.email, subject: `Application Received: ${job.title}`, sent: true, note: 'EmailJS' });

            } catch (err) {
                console.error('Error sending email via EmailJS API', err);
                logMailAttempt({ to: application.email, subject: `Application Received: ${job.title}`, sent: false, error: String(err) });
            }

        } else {
            console.log('Email (not sent) would be:', templateParams);
            logMailAttempt({ to: application.email, subject: `Application Received: ${job.title}`, sent: false, note: 'EmailJS not configured' });
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
    console.warn('⚠️  ADMIN_USERNAME or ADMIN_PASSWORD not set in environment variables.');
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

        // Prepare EmailJS template parameters
        const templateParams = {
            applicant_name: applicationToReject.name,
            applicant_email: applicationToReject.email,
            job_title: jobTitle,
            company_email: COMPANY_EMAIL, // Used as the sender in the template
            // ✅ FIX: Added 'email' key, which is required if template 'To Email' is {{email}}
            email: applicationToReject.email
        };

        // Send email using EmailJS API (using the 'auto_reply' template ID)
        if (mailerConfigured) {
            try {
                await sendEmailJS(EMAILJS_TEMPLATE_REJECT, templateParams);

                console.log('Rejection email sent to', applicationToReject.email, 'via EmailJS');
                logMailAttempt({ to: applicationToReject.email, subject: `Update on Application for ${jobTitle}`, sent: true, note: 'EmailJS Rejection' });

            } catch (err) {
                console.error('Error sending rejection email via EmailJS API', err);
                logMailAttempt({ to: applicationToReject.email, subject: `Update on Application for ${jobTitle}`, sent: false, note: 'EmailJS Rejection error' });
            }
        } else {
            console.log('Rejection email (not sent, EmailJS not configured) would be:', templateParams);
            logMailAttempt({ to: applicationToReject.email, subject: `Update on Application for ${jobTitle}`, sent: false, note: 'Rejection - not configured' });
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