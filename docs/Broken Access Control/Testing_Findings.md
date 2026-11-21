# Record of Testing Findings

BAC-01: Insecure Direct Object Reference (IDOR)

Vulnerability: Broken Access Control — Insecure Direct Object Reference (IDOR)

Endpoint: /api/v3/user/<user_id>

Testing framework: Python unittest

Test methodology: Two temporary customer accounts were created using an automated test-account helper. A valid JWT was generated for Customer A and used to request Customer A's information. The same JWT was then used to request Customer B's information by changing the user ID in the endpoint URL.

Expected result: The application should reject Customer A's attempt to access Customer B's information with an HTTP 403 or 404 response.

Actual result: The application returned HTTP 200 and exposed Customer B's account information, including their username, account balance, user ID, and administrative status.

Security impact: An authenticated attacker could potentially enumerate customer IDs and retrieve sensitive account information belonging to other users.

Recommended remediation: Implement server-side object-level authorization checks that verify the authenticated user is permitted to access the requested account. Return an appropriate denial response when ownership or authorization cannot be established.

Conclusion: The test failed as expected for an intentionally vulnerable application, demonstrating an IDOR vulnerability in VulnBank.
