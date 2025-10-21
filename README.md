# Company Website

Simple Express + EJS website with pages: Home, About Us, Job Openings, Admin Login, Contact Us.

Quick start

1. Install dependencies

```powershell
npm install
```

2. Start server

```powershell
npm start
```

3. Visit http://localhost:3000

Admin credentials: username `admin`, password `admin123` (change in `server.js`).

Email setup
-----------
To enable automatic confirmation emails to applicants, create a `.env` file in the project root (copy from `.env.example`) and fill in SMTP credentials. Example:

```powershell
copy .env.example .env
# then edit .env and set SMTP_PASS to your SMTP password or app password
```

You can then start the server (it will load the `.env` values automatically):

```powershell
node server.js
```

If SMTP is not configured the server will still function but will log the email instead of sending it.
