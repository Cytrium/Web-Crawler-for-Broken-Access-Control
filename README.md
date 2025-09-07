# Web-Crawler-for-Broken-Access-Control
A web-based security tool that detects Broken Access Control (BAC) vulnerabilities in web applications.

This project is a web-based security tool that detects Broken Access Control (BAC) vulnerabilities in web applications. It works by simulating multiple user roles (e.g., admin, user, guest), crawling the application, and analyzing differences in access permissions across roles. Unauthorized access attempts are automatically logged, analyzed, and reported through a simple web dashboard.

The system leverages Playwright for automated browser-based crawling, a Flask/FastAPI backend for processing, and MySQL for storing results, ensuring both scalability and ease of use.

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
- Frontend: React.js
- Backend: Flask / FastAPI (Python)
- Crawler Engine: Playwright
- Database: MySQL
