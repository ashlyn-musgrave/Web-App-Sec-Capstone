# Testing plan for Injection

Baseline Test Cases:

These test cases should always pass, even after vulnerability mitigation.

1 - Normal Login 
Scenario: Verifies legitimate credentials are successful.

2 - Invalid Login
Scenario: Verifies invalid credentials are unsuccessful.

Injection Vulnerability Test Cases:

These test cases should pass after mitigation.

1 - Login SQL Injection
Scenario: Verifies authentication bypass using an injection payload (' OR '1'='1' -- ) is unsuccessful.

2 - Login Single Quote
Scenario: Malformed credentials, like single-quotes, should not cause a server error.

3 - Balance SQL Injection
Secnario: Incorrect account identifier should not return a customer's account info.

4 - Transaction SQL Injection
Scenario: Verifies transaction history injection is unsuccessful, and returns no transaction data.

5 - Transaction Union SQL Injection
Scenario: Verifies UNION-based injection cannot retrieve transaction records.

6 - Biller ID Numeric SQL Injection
Scenario: Verifies numeric SQL injection cannot manipulate biller lookup.

7 - Test Transfer SQL Injection
Scenario: Verifies malicious input cannot manipulate bank transfers.

