# CCTV Network Monitoring System 
(LAST UPDATED: 06/11/2026)

A Flask and PostgreSQL web application for monitoring CCTV access, connected devices, user activity, camera status, and system security logs through a secure web-based dashboard.

## Project Members

* Carlson
* Rafael
* Steven
* Patrick

## Project Description

This project is a web-based CCTV and network monitoring system developed for **COMP 012 – Network Administration**. It provides a secure login system, live CCTV monitoring, connected device status checking, user activity tracking, and real-time system logs.

The system uses **Flask** for the backend, **PostgreSQL** for database storage, and **HTML, CSS, and JavaScript** for the web dashboard. The application is deployed online through **Railway**, while the CCTV camera feed is connected through a local RTSP bridge and Cloudflare Tunnel.

## System Flow

The CCTV camera sends its live feed through an **RTSP stream**. Since browsers cannot directly display RTSP feeds, a local Python bridge converts the RTSP stream into a browser-readable MJPEG video feed.

System flow:

```text
D-Link CCTV Camera
→ RTSP Stream
→ Local RTSP Bridge (rtsp_bridge.py)
→ MJPEG /video and /shot.jpg
→ Cloudflare Tunnel
→ Railway Flask Web App
→ Web Dashboard
```

The local RTSP bridge must be running on the laptop connected to the same network as the CCTV camera. Cloudflare Tunnel exposes the local bridge temporarily so the Railway-hosted dashboard can display the live CCTV feed.

## Main Features

* Secure login system
* Web-based monitoring dashboard
* Live CCTV camera preview
* CCTV online/offline status detection
* Connected device status monitoring
* Current logged-in device display
* Real-time system logs
* Paginated log viewing
* User activity tracking
* Login and logout records
* Failed login attempt records
* Failed CAPTCHA records
* Session timeout handling
* IP address logging
* Browser/device information logging
* PostgreSQL database integration
* Railway cloud deployment
* Cloudflare Tunnel support for live camera access
* Discord security alert support

## Security Features

* Server-side password checking through environment variables
* CAPTCHA/addition challenge on login
* CSRF protection
* Login rate limiting
* Failed login attempt tracking
* Temporary IP blocking
* Temporary account lockout
* Automatic idle session timeout
* Timeout logging after expired sessions
* Secure database queries using parameterized SQL
* Secure session cookie settings
* Security headers
* No-cache protection after logout or timeout
* Camera feed address hidden from the dashboard
* Sensitive credentials stored in environment variables

## Dashboard Flow

After a user logs in successfully, the dashboard displays:

1. **Live Camera Feed**
   Shows the CCTV feed coming from the local RTSP bridge through Cloudflare Tunnel.

2. **Connected Devices**
   Displays the CCTV camera status and the current logged-in browser device. The camera feed address is hidden for security.

3. **System Logs**
   Shows login, logout, failed login, failed CAPTCHA, timeout, and security-related activity records.

4. **Session Handling**
   If the user stays idle for one hour, closes the browser, or shuts down the device without logging out, the session expires. On the next access, the user is redirected to the login page and the timeout is recorded in the system logs.

## Technology Stack

* Flask
* PostgreSQL
* psycopg
* Flask-WTF
* Flask-Limiter
* Werkzeug Security
* OpenCV
* HTML
* CSS
* JavaScript
* Railway
* Cloudflare Tunnel
* Git and GitHub

## Deployment Notes

The Railway app runs the Flask dashboard using:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT
```

The Railway root directory is:

```text
camera_dashboard
```

The local CCTV bridge is started separately using:

```bash
py rtsp_bridge.py
```

Both the local RTSP bridge and Cloudflare Tunnel must remain running during the demonstration for the live CCTV feed to work.

## Important Security Reminder

Do not commit or share sensitive values such as:

* CCTV PIN
* RTSP URL with username and password
* Railway database URLs
* Discord webhook URL
* Secret keys
* User passwords
* `.env` files
* SQL backup files
