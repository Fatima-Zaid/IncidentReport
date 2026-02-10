# Cybersecurity Incident Report API

A secure backend API for reporting and managing cybersecurity incidents.
This project was built as part of a backend coding challenge, with a focus on security, clean architecture, and real-world backend practices.

📥 **API Testing:**
[Postman Collection](./Incident_Report_API.postman_collection.json)

---

## 🚀 What This Project Does

The Incident Report API allows authenticated users to report malicious URLs and track cybersecurity incidents.
It enforces strict access control, validates and sanitizes user input, and records sensitive actions through audit logs to ensure accountability.

The system supports two roles:
- **User:** Create and view their own incident reports
- **Admin:** View, update, and delete all incidents, and access audit logs

---

## ✨ Implemented Features

### 🔐 Authentication & Access Control
- User registration and login
- JWT-based authentication (access & refresh tokens)
- Role-based permissions (User vs Admin)
- Protected endpoints (authentication required)

---

### 📄 Incident Management
- Create, retrieve, update, and delete incidents
- Each incident includes:
  - Malicious URL
  - HTTP response
  - Description
  - Severity level (LOW, MEDIUM, HIGH, CRITICAL)
  - Timestamp (auto-generated)
  - Reporting user
  - Optional screenshot upload
- Users can only access their own incidents
- Admins can manage all incidents

---

### 🧼 Input Validation & Sanitization
- Required field validation
- URL format validation
- Controlled severity values
- HTML and script sanitization using **bleach**
- File upload validation (type & size)
- Protection against common injection and XSS attacks

---

### 📝 Audit Logging
Sensitive actions are logged automatically, including:
- Login attempts (success & failure)
- Incident creation, updates, deletion, and access
- Logged data includes:
  - User
  - Action
  - Timestamp
  - Status
  - IP address

Admin-only endpoints allow reviewing audit logs with filtering support.

---

### 🌟 Bonus Enhancements
- Incident filtering by severity and date range
- Audit log filtering by action, status, and user

---

## 🛠️ Tech Stack

- **Backend Framework:** Django 5.2.7
- **API Framework:** Django REST Framework
- **Authentication:** JWT (SimpleJWT)
- **Database:** PostgreSQL
- **Security:** bleach (input sanitization)
- **File Handling:** Pillow


