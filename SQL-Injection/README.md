# SQL Injection (SQLi) Vulnerability Assessment & Remediation

**Internship Program:** Cybersecurity & Ethical Hacking (ApexPlanet)  
**Task Module:** Task 3 – Web Application Security  
**Target Application:** Damn Vulnerable Web Application (DVWA)  
**Security Level:** Low  
**Vulnerability Classification:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command) / OWASP Top 10 A03:2021 – Injection  

---

## 1. Vulnerability Description
SQL Injection occurs when untrusted user input is directly concatenated into dynamic backend SQL queries without adequate validation or parameterized escaping. This enables an attacker to manipulate SQL syntax, bypass authentication controls, extract sensitive records, modify data, or execute administrative commands against the database engine.

* **Target URL:** `http://127.0.0.1/DVWA/vulnerabilities/sqli/`
* **Vulnerable Parameter:** `id` (User ID input field)

---

## 2. Insecure Source Code (Root Cause)
The backend PHP script takes input directly from the `$_GET['id']` parameter and interpolates it into a raw query string without binding parameters[cite: 1]:

```php
// Insecure implementation in DVWA (Low Level)
$id = $_GET['id'];

$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );
```

---

## 3. Attack Methodology & Payloads

### A. Authentication & Logic Bypass (Tautology)
* **Payload:** `' OR '1'='1`
* **Mechanism:** Injects an always-true condition into the `WHERE` clause, forcing the query to return every row in the database table.

### B. UNION-Based Data Extraction
* **Payload:**
  ```sql
  %' UNION SELECT user, password FROM users #
  ```
* **Step-by-Step Breakdown:**
  1. `%'`: Closes the initial SQL string literal and wildcards the search.
  2. `UNION SELECT`: Appends an independent query to merge results from another table[cite: 1].
  3. `user, password`: Selects two columns to match the column count of the original query (`first_name`, `last_name`)[cite: 1].
  4. `FROM users`: Targets the internal table storing application credentials[cite: 1].
  5. `#`: MySQL comment operator that truncates and ignores the trailing single quote and remaining query syntax.

---

## 4. Extracted Database Credentials & Password Cracking

Executing the `UNION` payload dumps the entire credential table and unsalted MD5 password hashes[cite: 1]:

| User ID / Username | Extracted MD5 Hash | Cracked Plaintext | Account Role |
|---|---|---|---|
| `admin` | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` | Administrator[cite: 1] |
| `gordonb` | `e99a18c428cb38d5f260853678922e03` | `abc123` | Standard User[cite: 1] |
| `1337` | `8d3533d75ae2c3966d7e0d4fcc69216b` | `charley` | Standard User[cite: 1] |
| `pablo` | `0d107d09f5bbe40cade3de5c71e9e9b7` | `letmein` | Standard User[cite: 1] |
| `smithy` | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` | Standard User[cite: 1] |

### Hash Cracking Demonstration (John the Ripper)
```bash
# Save target hash to file
echo -n "5f4dcc3b5aa765d61d8327deb882cf99" > admin_hash.txt

# Crack raw MD5 hash using John the Ripper
john --format=raw-md5 admin_hash.txt
```
* **Cracked Output:** `password`

---

## 5. Remediation & Secure Code Practices

### Primary Fix: Parameterized Queries (PHP PDO)
Prepared statements treat user input strictly as literal data parameters, completely neutralizing code injection[cite: 1].

```php
<?php
// Secure PDO Implementation
$dsn = "mysql:host=127.0.0.1;dbname=dvwa;charset=utf8mb4";
$pdo = new PDO($dsn, "dvwa_user", "secure_password", [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
]);

// Prepare statement with named placeholder
$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');

// Bind parameter and execute
$stmt->execute(['id' => $_GET['id']]);<img width="1366" height="745" alt="Kali linux - VMware Workstation 8_14_2026 8_33_04 PM" src="https://github.com/user-attachments/assets/f71c516b-7497-4b94-807c-1d95e8f684de" />
<img width="1366" height="745" alt="Kali linux - VMware Workstation 8_14_2026 8_33_04 PM" src="https://github.com/user-attachments/assets/4ae9944f-d39a-47ed-9511-1475b2590bd3" />
<img width="1366" height="745" alt="Kali linux - VMware Workstation 8_14_2026 8_33_04 PM" src="https://github.com/user-attachments/assets/64d0e65d-175c-4d38-bedd-387f78223864" />
<img width="1366" height="745" alt="Kali linux - VMware Workstation 8_14_2026 8_33_04 PM" src="https://github.com/user-attachments/assets/a3019757-1ac7-4e36-921d-23ae274685c2" />

$results = $stmt->fetchAll();

// Context-aware output encoding to prevent secondary XSS
foreach ($results as $row) {
    echo htmlspecialchars($row['first_name'], ENT_QUOTES, 'UTF-8') . " " .
         htmlspecialchars($row['last_name'], ENT_QUOTES, 'UTF-8') . "<br />";
}
?>
```

### Additional Defensive Controls
* **Input Validation:** Enforce strict type checking (e.g., `filter_var($_GET['id'], FILTER_VALIDATE_INT)`).
* **Least Privilege:** Restrict database account permissions so the web application cannot execute administrative statements (`DROP`, `ALTER`, `GRANT`).
* **Modern Cryptographic Hashing:** Replace legacy unsalted MD5 with adaptive algorithms like `bcrypt` or `Argon2id` via PHP's `password_hash()` and `password_verify()`.

### 📸 Exploitation Proof of Concept (PoC)

Below is the screenshot demonstrating the successful execution of the UNION-based SQL injection payload in DVWA, extracting database records and MD5 hashes:

<!-- Paste / Drag-and-drop your image directly below this line -->
<img width="1366" height="745" alt="Kali linux - VMware Workstation 8_14_2026 8_32_54 PM" src="https://github.com/user-attachments/assets/2ba1bee3-e7d3-440d-ae31-380133b7e6fb" />


> **Figure 1.1:** Verification of extracted user table rows and password hashes via the `' UNION SELECT user, password FROM users #` payload.
