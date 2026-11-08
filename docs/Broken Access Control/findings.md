# Record of Findings 

## Static Code Review

### File: app.py

#### BAC-01: IDOR 

VulnBank endpoint: GET /api/v3/user/<user_id>

Code Snip (lines 1465-1475): 

@app.route('/api/v3/user/<int:user_id>', methods=['GET'])
@token_required
def api_v3_get_user(current_user, user_id):
    user = execute_query(
        "SELECT * FROM users WHERE id = %s",
        (user_id,)
    )

Finding: Authenticated users can request another user's details without an apparent ownership check. Notice that @token_required verifies authentication, but the function doesn't compare the requested user_id against the authenticated user's ID or check whether the requester has administrative permission.
  
#### BAC-02: Vertical privilege escalation 

VulnBank endpoint: POST /register

Code Snip (lines 351-360): 

Build dynamic query based on user input fields
Vulnerability: Mass Assignment possible here
fields = ['username', 'password', 'account_number']
values = [username, user_data.get('password'), account_number]

Include any additional parameters from user input
for key, value in user_data.items():
    if key not in ['username', 'password']:
        fields.append(key)
        values.append(value)

Finding: Registration accepts additional user-controlled fields, potentially including is_admin. The application builds a database insertion using additional fields supplied by the client. That potentially allows someone registering a normal account to influence fields they shouldn't control, including administrative privileges.

#### BAC-03: Horizontal privilege escalation 

VulnBank endpoint: POST /api/virtual-cards/<card_id>/toggle-freeze

Code Snip: 

UPDATE virtual_cards
SET is_frozen = NOT is_frozen
WHERE id = {card_id}
RETURNING is_frozen

Finding; The update uses the card ID without verifying ownership. The problem is that the query selects the card using only its ID. It does not include a condition requiring the card to belong to the authenticated user. As a result, a customer may be able to freeze or unfreeze another customer's virtual card.

#### BAC-04: Missing function-level access control 

VulnBank endpoint: GET /debug/users

Finding: No authenticaion or adminitrative authorization is required by the route itself 

#### BAC-05: Forced Browsing

VulnBank endpoint: GET /transactions/<account_number>

Finding: The route is directly accessible without an authentication decorator 

#### BAC-06: Parameter tampering 

VulnBank endpoint: POST /api/virtual-cards/<card_id>/update-limit

Finding: The endpoint constructs updates from user-supplied fields without an allowlist

