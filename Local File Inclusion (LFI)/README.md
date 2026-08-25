# Local File Inclusion (LFI) Assessment & Remediation

**Internship Program:** Cybersecurity & Ethical Hacking (ApexPlanet)  
**Task Module:** Task 3 – Web Application Security  
**Target Application:** Damn Vulnerable Web Application (DVWA)  
**Security Level:** Low  
**Vulnerability Classification:** CWE-98 (Improper Control of Filename for Include/Require) / CWE-22 (Path Traversal)  

---

## 1. Vulnerability Overview
Local File Inclusion (LFI) occurs when an application accepts user input to determine a file path and passes it directly to server-side file inclusion functions (e.g., `include`, `require`) without validation or path sanitization.

* **Target URL:** `http://127.0.0.1/DVWA/vulnerabilities/fi/`
* **Vulnerable Parameter:** `page` (HTTP GET request)

---

## 2. Insecure Source Code (Root Cause Analysis)
The application takes the value of `$_GET['page']` and directly executes PHP's `include()` function, enabling directory traversal sequences:

```php
// Insecure LFI Source Code (DVWA Low Level)
$file = $_GET['page'];

// Directly including the supplied path
include($file);
```
## 3. Attack Payloads & Exploitation Walkthrough
**3.1 Directory Traversal to Read Sensitive System Files**
* **Payload:**

```Plaintext
../../../../etc/passwd
```
* **Full URL:**
```Plaintext
[http://127.0.0.1/DVWA/vulnerabilities/fi/?page=../../../../etc/passwd](http://127.0.0.1/DVWA/vulnerabilities/fi/?page=../../../../etc/passwd)
```
* **Mechanism:** The ../ sequence traverses up the Linux directory hierarchy from the `/var/www/html/dvwa/vulnerabilities/fi/` webroot to the root directory /, reading `/etc/passwd` directly.

## 4. Impact & Risk Analysis
* **System Information Disclosure:** Exposes user names, service accounts, and system configuration files (`/etc/hosts`, `/etc/issue`).

* **Potential for Remote Code Execution (RCE):** Attackers can escalate LFI to RCE via Apache access log poisoning (`/var/log/apache2/access.log`), SSH log poisoning, or PHP wrappers (`php://input, data://`).

## 5. Remediation & Secure Implementation
**5.1 Primary Defense: Strict Whitelisting**
Map allowable parameter values strictly against a hardcoded whitelist so arbitrary paths cannot be resolved:

```PHP
<?php
// Secure Whitelist Implementation
$allowed_files = [
    'include.php' => 'include.php',
    'file1.php'   => 'file1.php',
    'file2.php'   => 'file2.php',
    'file3.php'   => 'file3.php'
];

$page =$_GET['page'] ?? 'include.php';

if (array_key_exists($page,$allowed_files)) {
    include($allowed_files[$page]);
} else {
    http_response_code(404);
    include('404.php');
}
?>
```
**5.2 Server Configuration Hardening**
Disable dangerous PHP wrapper directives in `php.ini` to limit file inclusion vectors:

```Ini, TOML
allow_url_fopen = Off
allow_url_include = Off
```
