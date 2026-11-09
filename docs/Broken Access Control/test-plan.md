# Testing Plan for BAC

Below are the six proposed scenarios that I'll be attempting to exploit on Vulnbank's website:

Test Cases: 

BAC-01 — IDOR
Scenario: Request account details using another customer's account ID

BAC-02 — Vertical privilege escalation
Scenario: Regular user attempts an admin-only action 

BAC-03 — Horizontal privilege escalation
Scenario: Customer A attempts to modify Customer B's profile

BAC-04 — Missing function-level access control
Scenario: Regular user invokes a restricted API operation directly 

BAC-05 — Forced browsing
Scenario: User directly navigates to a restricted page

BAC-06 — Parameter tampering
Scenario: User changes a submitted role or ownership parameter 
