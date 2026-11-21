# Record of Testing Findings

### BAC-01: Insecure Direct Object Reference (IDOR)

**Vulnerability**: Broken Access Control — Insecure Direct Object Reference (IDOR)

**Endpoint**: /api/v3/user/<user_id>

**Testing framework**: Python unittest

**Test methodology**: Two temporary customer accounts were created using an automated test-account helper. A valid JWT was generated for Customer A and used to request Customer A's information. The same JWT was then used to request Customer B's information by changing the user ID in the endpoint URL.

**Expected result**: The application should reject Customer A's attempt to access Customer B's information with an HTTP 403 or 404 response.

**Actual result**: The application returned HTTP 200 and exposed Customer B's account information, including their username, account balance, user ID, and administrative status.

**Security impact**: An authenticated attacker could potentially enumerate customer IDs and retrieve sensitive account information belonging to other users.

**Recommended remediation**: Implement server-side object-level authorization checks that verify the authenticated user is permitted to access the requested account. Return an appropriate denial response when ownership or authorization cannot be established.

**Conclusion**: The test failed as expected for an intentionally vulnerable application, demonstrating an IDOR vulnerability in VulnBank.


### BAC-02: Vertical Privilege Escalation — JWT Forgery

**Vulnerability:** Broken Access Control / Insecure JWT Verification

**Affected function:** `verify_token()` in `auth.py`

**Testing framework:** Python `unittest`

**Test methodology:** A legitimate JWT was generated for a temporary customer account with `is_admin=False`. The JWT payload was modified to set `is_admin=True`, and a forged token was signed using an incorrect secret key. The forged token was then submitted to VulnBank's `verify_token()` function.

**Expected result:** The application should reject the forged JWT because its signature cannot be validated using the application's secret key.

**Actual result:** The application accepted the forged token and returned a payload containing `is_admin=True`.

**Security impact:** An attacker could potentially forge authentication tokens containing elevated privileges. If administrator-only endpoints trust these claims without additional authorization checks, this could enable vertical privilege escalation.

**Root cause:** The token verification function catches invalid-signature exceptions and attempts to decode the token again with signature verification disabled.

**Recommended remediation:** Remove the insecure signature-verification fallback. Require a valid signature, enforce a strict algorithm allowlist, use a strong secret key, and validate token expiration. Administrator authorization should also be enforced server-side.

**Conclusion:** BAC-02 failed its security assertion, demonstrating that VulnBank accepts forged JWTs containing unauthorized administrator claims. Additional endpoint-level testing would establish whether those claims permit access to administrator-only functionality.
