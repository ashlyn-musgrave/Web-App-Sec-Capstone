# Injection Testing Findings

Baseline Test Cases - Passed

All Injection Vulnerability Test Cases - Failed:

1 - Login SQL Injection
Results: Malicious SQL input returned HTTP 200 instead of 401, indicating a potential authentication bypass.

2 - Login Single Quote
Results: Single quotes in both username and password caused HTTP 500 responses and exposed PostgreSQL syntax errors.

3 - Balance SQL Injection
Results: Malicious account-number input returned HTTP 200 instead of 404. Potential account information was disclosed.

4 - Transaction SQL Injection
Results: SQL injection returned four transaction records instead of an empty list, suggesting the account-number restriction could be getting bypassed.

5 - Transaction Union SQL Injection
Results: UNION-based payload returned four transaction records.

6 - Biller ID Numeric SQL Injection
Results: Manipulated numeric biller ID caused HTTP 500, indicating improper input handling and potentially unsafe SQL construction.

7 - Test Transfer SQL Injection
Results: Malicious destination account input returned HTTP 200 instead of a rejection.