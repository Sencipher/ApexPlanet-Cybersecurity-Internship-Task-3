# ApexPlanet Cybersecurity Internship – Task 3: Web Application Security

**Intern:** Vivek Sen  
**Internship ID:** APSPL2641756  
**Track:** Cybersecurity & Ethical Hacking  
**Target Environment:** DVWA (Damn Vulnerable Web Application) on Kali Linux  
**Security Level:** Low  

---

## 📌 Project Overview
This repository contains the comprehensive vulnerability assessment, proof-of-concept exploitation, root cause analysis, and secure code remediation for key **OWASP Top 10** web application vulnerabilities conducted during Task 3 of the ApexPlanet Internship program.

---

## 📂 Vulnerability Modules & Documentation

Click on any module below to view detailed attack scenarios, source code breakdowns, screenshots, and remediation guides:

* [📁 **SQL Injection (SQLi)**](./SQL-Injection/README.md)
  * Authentication bypass (`' OR '1'='1`)
  * `UNION`-based database extraction (`%' UNION SELECT user, password FROM users #`)
  * Password hash cracking using John the Ripper
  * Remediation using PHP PDO Prepared Statements

* [📁 **Cross-Site Scripting (XSS)**](./XSS/README.md)
  * Reflected XSS session cookie theft (`document.cookie`)
  * Persistent Stored XSS via Guestbook entries
  * Context-aware output encoding (`htmlspecialchars()`) & CSP hardening

* [📁 **Cross-Site Request Forgery (CSRF)**](./CSRF/README.md)
  * Proof-of-concept exploit (`csrf_poc.html`) for unauthorized password reset
  * Defense via Anti-CSRF Synchronizer Tokens & `SameSite=Strict` cookies

* [📁 **Local File Inclusion (LFI)**](./Local%20File%20Inclusion(LFI)/README.md)
  * Directory traversal (`../../../../etc/passwd`)
  * Impact analysis (system account disclosure & RCE vectors)
  * Defense via strict file whitelisting & `php.ini` directives

---

## 🛠️ Tools & Technologies Used
* **Operating System:** Kali Linux (VMware Workstation)
* **Web Environment:** Apache, PHP, MySQL / MariaDB (DVWA)
* **Password Cracking:** John the Ripper
* **Interception & Analysis:** Burp Suite Community Edition
* **Language & Fixes:** PHP, HTML5, JavaScript
