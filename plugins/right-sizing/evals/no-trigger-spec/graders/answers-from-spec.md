---
type: llm
---

PASS if the response says the token endpoint must reject the request with
the error code `invalid_grant`, as RFC 7636 section 4.6 requires, returned as
an OAuth 2.0 error response (HTTP 400 with a JSON body carrying `error`, per
RFC 6749 section 5.2), and does not issue tokens.

FAIL if it gives a different error code, suggests issuing tokens anyway, or
treats the response as a design choice to be made rather than one the
specification defines.
