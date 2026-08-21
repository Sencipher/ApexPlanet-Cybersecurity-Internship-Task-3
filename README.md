# Web Application Security Assessment - DVWA

## Overview
This repository contains vulnerability analysis, proof-of-concept testing, and source-code mitigations for OWASP Top 10 vulnerabilities tested within a controlled DVWA (Damn Vulnerable Web Application) environment.

## Vulnerabilities Explored
- **SQL Injection (SQLi)**: Extraction of database entries via unescaped query parameters.
- **Cross-Site Scripting (XSS)**: Execution of arbitrary client-side scripts via Reflected and Stored vectors.
- **Cross-Site Request Forgery (CSRF)**: Unauthorized state change of user credentials.
- **File Inclusion (LFI/RFI)**: Directory traversal and remote resource execution analysis.

## Key Mitigations Implemented
1. **Parameterized Queries (PDO)**:
   ```php
   $stmt =$pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');
   $stmt->execute(['id' =>$id]);
   $user =$stmt->fetch();
