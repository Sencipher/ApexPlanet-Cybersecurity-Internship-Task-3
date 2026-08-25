# Cross-Site Scripting (XSS) Vulnerability Assessment & Remediation

**Internship Program:** Cybersecurity & Ethical Hacking (ApexPlanet)  
**Task Module:** Task 3 – Web Application Security  
**Target Application:** Damn Vulnerable Web Application (DVWA)  
**Security Level:** Low  
**Vulnerability Classification:** CWE-79 (Improper Neutralization of Input During Web Page Generation) / OWASP Top 10 A03:2021 – Injection  

---

## 1. Vulnerability Overview
Cross-Site Scripting (XSS) vulnerabilities occur when an application receives untrusted user input and embeds it into dynamic web output without proper contextual validation or encoding. This allows an attacker to execute arbitrary client-side JavaScript code in the browser session of a legitimate user.

* **Primary Security Risks:**
  * Extraction of session identifiers and sensitive authentication cookies (`PHPSESSID`).
  * Unauthorized execution of state-changing actions under the victim's authenticated context.
  * DOM manipulation, content defacement, and credential phishing overlays.
  * Keystroke logging and redirection to external malicious infrastructure.

---

## 2. Reflected XSS (Non-Persistent)

### 2.1 Target Endpoint & Parameter
* **Target URL:** `http://127.0.0.1/DVWA/vulnerabilities/xss_r/`
* **Vulnerable Parameter:** `name` (HTTP GET request)

### 2.2 Insecure Source Code (Root Cause)
The backend PHP code reads input directly from `$_GET['name']` and echoes it into the HTML body without filtering or output encoding:

```php
// Insecure Reflected XSS Code (DVWA Low Level)
if (array_key_exists("name", $_GET) && $_GET['name'] != NULL) {
    echo '<pre>Hello ' . $_GET['name'] . '</pre>';
```

### 2.3 Attack Methodology & Payload
* **Exploitation Payload:**
  
`<script>alert(document.cookie)</script>`

* **Execution Flow:**

1. The attacker crafts a targeted URL embedding the malicious JavaScript inside the name parameter:
`http://127.0.0.1/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(document.cookie)%3C/script%3E`

2. The victim clicks the malicious link while possessing an active DVWA session.

3. The server immediately reflects the payload back to the browser without sanitizing < or >.

4. The browser executes the JavaScript and displays the victim's active PHPSESSID session cookie.

### 2.4 Exploitation Proof of Concept (PoC)

<img width="1366" height="745" alt="Kali linux - VMware Workstation 8_14_2026 8_35_51 PM" src="https://github.com/user-attachments/assets/714c9232-e118-4f29-b8b5-1f1ee6c7ca78" />


**Figure 2.1:** Reflected XSS execution demonstrating unauthorized access to session cookies via the document.cookie object.


### 3. Stored XSS (Persistent)
**3.1** Target Endpoint & Parameter

* **Target URL:** 
 `http://127.0.0.1/DVWA/vulnerabilities/xss_s/`
 
* **Vulnerable Parameters:** `txtName` (Name field), `mtxMessage` (Message field) via HTTP POST


### 3.2 Insecure Source Code (Root Cause)
The application accepts user input from the guestbook form, stores it raw into the database, and renders stored records to all subsequent visitors without escaping:

```
if (isset($_POST['btnSign'])) {
    $message = trim($_POST['mtxMessage']);
    $name    = trim($_POST['txtName']);

    $query  = "INSERT INTO guestbook (comment, name) VALUES ('$message', '$name');";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
}
```




