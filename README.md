# Web-Crawler-for-Broken-Access-Control
A web-based security tool that detects Broken Access Control (BAC) vulnerabilities in web applications.

The Web-Based Access Control Vulnerability Detection System is a Flask-powered web application designed to automatically detect Broken Access Control (BAC) vulnerabilities in target web systems. The system uses Playwright as an automated crawler to simulate different user roles—such as Admin, User, and Guest—and analyze which URLs are accessible to each. By comparing access patterns between roles, the system can identify unauthorized access attempts, such as normal users gaining access to admin-only pages. All results are stored in a MySQL database and presented through a web dashboard that includes scan logs, detected violations, and reports. The platform aims to support multi-application scanning, role-based vulnerability testing, and future integration of ML-based access anomaly detection.

# Features
Role-Based Crawling
- Simulates multiple user roles (admin, user, guest).
- Stores authenticated sessions per role.
- Crawls applications in parallel for faster scanning.

Automated Access Comparison
- Intercepts HTTP requests and responses.
- Detects unauthorized access by comparing accessible URLs between roles.
- Supports detection of privilege escalation and direct object reference flaws.

Vulnerability Detection & Logging
- Identifies misconfigured sessions, weak role enforcement, and cookie manipulation risks.
- Stores detailed logs (status codes, URLs, role permissions).

Dashboard & Reporting
- React.js dashboard for visualization.
- Real-time scan results and summaries.
- Exportable vulnerability reports for audits or forensic analysis.

Technology Stack
- Frontend: Tailwind
- Backend: Flask (Python)
- Crawler Engine: Playwright
- Database: MySQL
