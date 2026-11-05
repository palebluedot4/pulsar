---
type: llm
---

PASS if the response explains that the ID token tells the client who the user
is and how they authenticated (its audience is the client), while the access
token authorizes calls to a resource server or API (its audience is that
API), and that an ID token should not be used to call APIs.

FAIL if it confuses the two tokens' purposes or audiences, or suggests using
an ID token to call APIs.
