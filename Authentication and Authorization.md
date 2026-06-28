# 🔐 Authentication & Authorization — Complete Backend Guide

> A comprehensive reference for backend engineers covering core concepts, implementation patterns, security best practices, and interview preparation.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Authentication vs Authorization](#authentication-vs-authorization)
3. [Authentication Mechanisms](#authentication-mechanisms)
   - [Session-Based Authentication](#session-based-authentication)
   - [Token-Based Authentication (JWT)](#token-based-authentication-jwt)
   - [OAuth 2.0](#oauth-20)
   - [OpenID Connect (OIDC)](#openid-connect-oidc)
   - [API Keys](#api-keys)
   - [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
   - [Passwordless Authentication](#passwordless-authentication)
4. [Authorization Models](#authorization-models)
   - [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
   - [Attribute-Based Access Control (ABAC)](#attribute-based-access-control-abac)
   - [Permission-Based Access Control](#permission-based-access-control)
   - [Policy-Based Access Control](#policy-based-access-control)
5. [Password Security](#password-security)
6. [Common Vulnerabilities & Mitigations](#common-vulnerabilities--mitigations)
7. [Secure Token Storage](#secure-token-storage)
8. [Interview Questions & Answers](#interview-questions--answers)

---

## Introduction

Authentication and Authorization are two of the most critical pillars of backend security. Every system that manages user data, protected resources, or privileged operations must implement them correctly. A mistake in either can lead to data breaches, account takeovers, or privilege escalation.

This guide covers everything from fundamental theory to production-ready implementation patterns.

---

## Authentication vs Authorization

These two terms are often confused but describe fundamentally different concerns.

| Aspect | Authentication | Authorization |
|--------|---------------|---------------|
| Question | **Who are you?** | **What can you do?** |
| Purpose | Verify identity | Enforce permissions |
| Example | Login with email + password | Admin can delete users; regular user cannot |
| Happens | First | After authentication |
| Failure HTTP code | `401 Unauthorized` | `403 Forbidden` |
| Technologies | JWT, Sessions, OAuth | RBAC, ABAC, ACL |

> **Key Insight:** You can be authenticated (we know who you are) but still unauthorized (you don't have permission to do that).

---

## Authentication Mechanisms

### Session-Based Authentication

The classic, stateful approach. The server maintains session state.

**Flow:**
```
1. Client sends credentials (username + password)
2. Server validates, creates a session record in DB/cache (e.g., Redis)
3. Server returns a session ID in a Set-Cookie header
4. Client sends cookie on every request
5. Server looks up session ID → fetches user context
6. Server processes request with that user context
```

**Implementation sketch (Node.js / Express):**
```javascript
const session = require('express-session');
const RedisStore = require('connect-redis')(session);

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,       // Not accessible via JS
    secure: true,         // HTTPS only
    sameSite: 'strict',   // CSRF protection
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  }
}));
```

**Pros:**
- Easy to invalidate sessions instantly (just delete from DB)
- Server has full control over session lifecycle
- No sensitive data in the client

**Cons:**
- Stateful — hard to scale horizontally without a shared session store
- Every request hits the session store (latency)
- Vulnerable to CSRF if cookies aren't configured properly

---

### Token-Based Authentication (JWT)

**JSON Web Token (JWT)** is a compact, self-contained token. The server doesn't need to store session state.

**JWT Structure:**
```
Header.Payload.Signature

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   ← Header (Base64)
.eyJzdWIiOiIxMjM0Iiwicm9sZSI6ImFkbWluIn0  ← Payload (Base64)
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← Signature (HMAC/RSA)
```

**Header:**
```json
{ "alg": "HS256", "typ": "JWT" }
```

**Payload (Claims):**
```json
{
  "sub": "user_123",
  "email": "user@example.com",
  "role": "admin",
  "iat": 1710000000,
  "exp": 1710003600
}
```

**Standard Claims:**

| Claim | Meaning |
|-------|---------|
| `sub` | Subject — who the token is about |
| `iss` | Issuer — who created the token |
| `aud` | Audience — intended recipient |
| `exp` | Expiry timestamp |
| `iat` | Issued at timestamp |
| `jti` | JWT ID — unique token identifier |
| `nbf` | Not before — token not valid before this time |

**Access Token + Refresh Token Pattern:**
```
Access Token:  Short-lived (15 min – 1 hour). Used for API calls.
Refresh Token: Long-lived (days/weeks). Used only to get new access tokens.
```

```javascript
// Issuing tokens
const accessToken = jwt.sign(
  { sub: user.id, role: user.role },
  process.env.ACCESS_TOKEN_SECRET,
  { expiresIn: '15m' }
);

const refreshToken = jwt.sign(
  { sub: user.id, jti: uuidv4() },
  process.env.REFRESH_TOKEN_SECRET,
  { expiresIn: '7d' }
);

// Store refresh token hash in DB
await db.refreshTokens.create({
  userId: user.id,
  tokenHash: hashToken(refreshToken),
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
});
```

**Token Verification Middleware:**
```javascript
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({ error: 'Token expired' });
    return res.status(401).json({ error: 'Invalid token' });
  }
};
```

**Pros:**
- Stateless — scales easily; no session store needed
- Self-contained — payload carries user context
- Works across microservices and domains

**Cons:**
- Cannot be revoked before expiry (without a token blocklist)
- Payload is Base64-encoded, not encrypted — don't store secrets in it
- Larger size than a session cookie

---

### OAuth 2.0

OAuth 2.0 is an **authorization framework** (not authentication) that allows third-party applications to access resources on behalf of a user, without exposing credentials.

**Core Roles:**

| Role | Description |
|------|-------------|
| Resource Owner | The user who owns the data |
| Client | The application requesting access |
| Authorization Server | Issues tokens (e.g., Google, Auth0) |
| Resource Server | Hosts the protected resources (your API) |

**Grant Types:**

**1. Authorization Code Flow** (most secure, used for web/mobile apps):
```
Client → Authorization Server: GET /authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=xyz
Auth Server → User: Show consent screen
User → Auth Server: Approve
Auth Server → Client: Redirect with code=ABC&state=xyz
Client → Auth Server: POST /token { code=ABC, client_secret=... }
Auth Server → Client: { access_token, refresh_token, expires_in }
Client → Resource Server: GET /api/data with Bearer token
```

**2. Authorization Code + PKCE** (for SPAs/mobile — no client secret):
```javascript
// Generate code verifier + challenge
const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto.createHash('sha256')
  .update(codeVerifier).digest('base64url');

// Step 1: Redirect user
const authUrl = `https://auth.example.com/authorize?
  response_type=code&
  client_id=${CLIENT_ID}&
  redirect_uri=${REDIRECT_URI}&
  code_challenge=${codeChallenge}&
  code_challenge_method=S256&
  state=${state}`;

// Step 2: Exchange code
const tokenResponse = await fetch('https://auth.example.com/token', {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier,  // Proves we initiated the flow
    client_id: CLIENT_ID
  })
});
```

**3. Client Credentials** (machine-to-machine):
```javascript
// No user involved — service authenticates as itself
const response = await fetch('https://auth.example.com/token', {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: SERVICE_CLIENT_ID,
    client_secret: SERVICE_CLIENT_SECRET,
    scope: 'read:reports write:events'
  })
});
```

**OAuth 2.0 Scopes** define what access is being requested:
```
scope=read:profile write:posts openid email
```

---

### OpenID Connect (OIDC)

OIDC is an **identity layer built on top of OAuth 2.0**. It adds authentication to OAuth's authorization.

- OAuth 2.0 answers: *"Can this app access my Google Drive?"*
- OIDC answers: *"Who is this user?"*

OIDC introduces the **ID Token** — a JWT containing user identity claims:
```json
{
  "iss": "https://accounts.google.com",
  "sub": "1234567890",
  "aud": "your-client-id",
  "email": "alice@example.com",
  "name": "Alice Smith",
  "picture": "https://...",
  "email_verified": true,
  "exp": 1710003600
}
```

**Key OIDC Endpoints (Discovery Document):**
```
GET /.well-known/openid-configuration

{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json"
}
```

The **JWKS URI** exposes the public keys needed to verify ID token signatures — this is what your backend uses to validate tokens from external providers without needing a shared secret.

---

### API Keys

Simple, long-lived credentials used primarily for service-to-service or developer API access.

```
Authorization: Bearer sk_live_abc123xyz...
X-API-Key: ak_v1_abc123xyz...
```

**Best practices:**
```javascript
// Store only a hash of the key, never plaintext
const apiKeyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

// Use a prefix for key identification without exposing the secret
// e.g.: sk_live_<random32bytes>
const prefix = 'sk_live_';
const rawKey = prefix + crypto.randomBytes(32).toString('hex');

// Validate
const incomingKey = req.headers['x-api-key'];
const hash = crypto.createHash('sha256').update(incomingKey).digest('hex');
const keyRecord = await db.apiKeys.findOne({ hash });

if (!keyRecord || keyRecord.revokedAt) {
  return res.status(401).json({ error: 'Invalid API key' });
}
```

**Key management features to implement:**
- Key rotation (issue new, deprecate old)
- Per-key scopes/permissions
- Rate limiting per key
- Audit logs per key
- Expiry dates

---

### Multi-Factor Authentication (MFA)

MFA requires more than one verification factor:

| Factor Type | Examples |
|-------------|---------|
| Something you know | Password, PIN, security question |
| Something you have | TOTP app, SMS code, hardware key (YubiKey) |
| Something you are | Fingerprint, Face ID |

**TOTP (Time-based One-Time Password) — RFC 6238:**
```javascript
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

// Setup: generate secret for user
const secret = speakeasy.generateSecret({ name: `MyApp (${user.email})` });
// Store secret.base32 encrypted in DB
// Show secret.otpauth_url as QR code to user

const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);

// Verify: during login
const isValid = speakeasy.totp.verify({
  secret: user.totpSecret,
  encoding: 'base32',
  token: userProvidedCode,
  window: 1  // Allow 1 step clock drift
});
```

---

### Passwordless Authentication

Eliminates passwords entirely, reducing the largest attack surface.

**Magic Link:**
```javascript
// 1. User enters email
// 2. Generate a secure, short-lived token
const token = crypto.randomBytes(32).toString('hex');
const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

await db.magicLinks.create({
  email,
  tokenHash: hash(token),
  expiresAt
});

// 3. Send link via email
const link = `https://yourapp.com/auth/verify?token=${token}`;
await sendEmail(email, `Sign in: ${link}`);

// 4. On click — verify token
const record = await db.magicLinks.findOne({ tokenHash: hash(incomingToken) });
if (!record || record.expiresAt < new Date()) {
  return res.status(401).json({ error: 'Link expired or invalid' });
}
await db.magicLinks.delete({ id: record.id }); // Single-use
// Issue session/JWT...
```

**Passkeys (WebAuthn):** The modern standard — uses public key cryptography. The private key never leaves the user's device.

---

## Authorization Models

### Role-Based Access Control (RBAC)

Users are assigned roles; roles have permissions.

```
User → has Role(s) → Role has Permissions → Permission gates Resource
```

**Database schema:**
```sql
CREATE TABLE users (id UUID PRIMARY KEY, email TEXT);
CREATE TABLE roles (id UUID PRIMARY KEY, name TEXT UNIQUE);
CREATE TABLE permissions (id UUID PRIMARY KEY, name TEXT UNIQUE); -- e.g. "post:delete"
CREATE TABLE user_roles (user_id UUID, role_id UUID, PRIMARY KEY (user_id, role_id));
CREATE TABLE role_permissions (role_id UUID, permission_id UUID, PRIMARY KEY (role_id, permission_id));
```

**Middleware example:**
```javascript
const requirePermission = (permission) => async (req, res, next) => {
  const userPermissions = await getUserPermissions(req.user.sub);
  if (!userPermissions.includes(permission)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};

// Usage
router.delete('/posts/:id',
  verifyToken,
  requirePermission('post:delete'),
  deletePostHandler
);
```

**Roles hierarchy example:**
```
superadmin → admin → moderator → user → guest
```

---

### Attribute-Based Access Control (ABAC)

Fine-grained access control based on attributes of the user, resource, and environment.

```
ALLOW IF:
  user.department == resource.department
  AND user.clearanceLevel >= resource.sensitivityLevel
  AND environment.time BETWEEN 09:00 AND 18:00
```

**Implementation:**
```javascript
const canAccess = (user, resource, action, environment) => {
  const policies = [
    // Only same-department users can view docs
    {
      condition: () => action === 'read' &&
        resource.type === 'document' &&
        user.department === resource.department,
      effect: 'allow'
    },
    // Managers can approve in business hours
    {
      condition: () => action === 'approve' &&
        user.role === 'manager' &&
        environment.hour >= 9 && environment.hour < 18,
      effect: 'allow'
    }
  ];

  return policies.some(p => p.effect === 'allow' && p.condition());
};
```

---

### Permission-Based Access Control

Direct mapping of permissions to users (no intermediary roles).

```javascript
// Permissions stored per user
const permissions = {
  'user:123': ['posts:read', 'posts:write', 'comments:delete'],
  'user:456': ['posts:read']
};
```

Useful for fine-grained, per-user customization, often combined with RBAC.

---

### Policy-Based Access Control

Used in platforms like AWS IAM, where policies are documents evaluated at request time.

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::my-bucket/uploads/*",
  "Condition": {
    "StringEquals": { "s3:prefix": ["uploads/"] },
    "IpAddress": { "aws:SourceIp": "10.0.0.0/8" }
  }
}
```

---

## Password Security

Passwords must never be stored in plaintext. Use adaptive hashing algorithms.

**Algorithm Comparison:**

| Algorithm | Recommended | Notes |
|-----------|------------|-------|
| bcrypt | ✅ Yes | Work factor adjustable; memory cost limited |
| argon2id | ✅ Yes (preferred) | Winner of Password Hashing Competition; memory-hard |
| scrypt | ✅ Yes | Memory-hard; good alternative |
| PBKDF2 | ⚠️ Acceptable | FIPS-compliant; not memory-hard |
| SHA-256 (raw) | ❌ No | Not designed for passwords |
| MD5 | ❌ Never | Completely broken |

**Using argon2id:**
```javascript
const argon2 = require('argon2');

// Hash
const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536,  // 64 MB
  timeCost: 3,        // iterations
  parallelism: 4
});

// Verify
const isValid = await argon2.verify(storedHash, providedPassword);
```

**Password policies (recommended minimums):**
- Minimum 12 characters
- Check against breached password databases (HaveIBeenPwned API)
- No arbitrary complexity rules (NIST SP 800-63B)
- Allow paste in password fields
- Show strength meter

---

## Common Vulnerabilities & Mitigations

### 1. Broken Authentication

**Attack:** Brute-force or credential stuffing on login endpoints.

**Mitigations:**
```javascript
// Rate limiting with exponential backoff
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts'
});

// Account lockout after N failures
if (user.failedAttempts >= 5) {
  const lockoutUntil = new Date(user.lastFailedAt + 15 * 60 * 1000);
  if (new Date() < lockoutUntil) {
    return res.status(429).json({ error: 'Account temporarily locked' });
  }
}
```

### 2. JWT Algorithm Confusion (`alg: none`)

**Attack:** Attacker strips signature and sets `alg: none` to bypass verification.

**Mitigation:**
```javascript
// Always specify algorithm explicitly
jwt.verify(token, secret, { algorithms: ['HS256'] }); // NEVER allow 'none'
```

### 3. CSRF (Cross-Site Request Forgery)

**Attack:** Malicious site triggers state-changing requests using the victim's session cookie.

**Mitigations:**
- `SameSite=Strict` or `SameSite=Lax` on cookies
- CSRF tokens (synchronizer token pattern)
- Custom request headers (exploitable only from same origin)

```javascript
app.use(csrf({ cookie: { sameSite: 'strict', httpOnly: true } }));
```

### 4. Insecure Direct Object Reference (IDOR)

**Attack:** User changes `id=123` to `id=456` in API call and accesses another user's data.

**Mitigation:** Always verify ownership:
```javascript
const resource = await db.documents.findOne({ id: req.params.id });
if (!resource || resource.ownerId !== req.user.sub) {
  return res.status(403).json({ error: 'Forbidden' });
}
```

### 5. Token Leakage via URL

**Attack:** Access token stored in URL (`?token=...`) ends up in server logs, referrer headers, or browser history.

**Mitigation:** Always transmit tokens in `Authorization: Bearer` header or `httpOnly` cookies, never URL params.

### 6. Privilege Escalation

**Attack:** User modifies their role claim in a JWT or request payload.

**Mitigation:** Never trust client-supplied role/permission claims. Always re-derive from DB:
```javascript
// BAD: trusting JWT payload's role
const role = req.user.role;

// GOOD: re-fetch role from DB
const user = await db.users.findOne({ id: req.user.sub });
const role = user.role;
```

---

## Secure Token Storage

| Storage | XSS Safe | CSRF Safe | Recommendation |
|---------|----------|-----------|---------------|
| `httpOnly` Cookie | ✅ Yes | ⚠️ Need SameSite | ✅ Best for web |
| `localStorage` | ❌ No | ✅ Yes | ❌ Avoid for auth tokens |
| `sessionStorage` | ❌ No | ✅ Yes | ❌ Avoid for auth tokens |
| Memory (JS var) | ✅ Yes | ✅ Yes | ✅ OK for SPAs (lost on refresh) |

**Golden rule:** Store access tokens in memory; store refresh tokens in `httpOnly`, `Secure`, `SameSite=Strict` cookies.

---

---

## Interview Questions & Answers

### Fundamentals

---

**Q1. What is the difference between authentication and authorization? Give a real-world example.**

**A:** Authentication is the process of verifying *who* a user is — confirming their identity, typically via credentials like a password or biometric. Authorization is the process of determining *what* that authenticated user is allowed to do — checking their permissions against the requested action.

Real-world example: When you log in to a banking app (authentication), the system confirms you are who you claim to be. Once logged in, when you try to transfer money, it checks whether your account type and verification level permit that operation (authorization). A read-only user can view statements but gets a 403 Forbidden when trying to initiate a transfer.

---

**Q2. What HTTP status codes should be used for authentication vs. authorization failures, and why does it matter?**

**A:**
- `401 Unauthorized` — the request lacks valid authentication credentials. Despite the name, it means "unauthenticated." The client should retry with credentials.
- `403 Forbidden` — the request is authenticated but the caller lacks permission to access the resource. No amount of re-authenticating will help.

Using the wrong code misleads clients and can expose information. Returning `403` when the user isn't logged in could reveal that the resource exists. Returning `401` when a user simply lacks permission could confuse retry logic.

---

**Q3. What are the three types of authentication factors? Why does combining them increase security?**

**A:**
1. **Something you know** — password, PIN, security answer
2. **Something you have** — phone (TOTP), hardware key (YubiKey), smart card
3. **Something you are** — fingerprint, face ID, voice

Combining factors means an attacker must compromise multiple independent mechanisms. A stolen password alone is useless if the account also requires the user's physical phone for TOTP. The factors are independent by design — a data breach exposing passwords doesn't compromise physical devices.

---

### Sessions & Tokens

---

**Q4. Compare session-based and JWT-based authentication. When would you choose one over the other?**

**A:**

Session-based authentication is **stateful** — the server stores session data (in memory, Redis, or a DB) and the client holds only a session ID in a cookie. Revocation is instant (delete the session record). It works well for traditional server-rendered applications but requires a shared session store for horizontal scaling.

JWT-based authentication is **stateless** — the token itself carries all necessary claims and is verified cryptographically without a DB lookup on every request. This makes it easy to scale across multiple servers and ideal for microservices or mobile APIs. The downside is that JWTs cannot be revoked before expiry without introducing a blocklist (which partially reintroduces statefulness).

**Choose sessions when:**
- You need instant revocation (e.g., logout must be immediate)
- You have a monolith or a shared session store
- You prefer simplicity

**Choose JWTs when:**
- You have stateless microservices that need to share identity without shared storage
- You're building an API consumed by mobile apps or third parties
- Horizontal scaling is a priority

---

**Q5. Explain the access token + refresh token pattern. Why use two tokens instead of one long-lived token?**

**A:** A single long-lived token is risky because if it's intercepted, the attacker has prolonged access. The dual-token pattern mitigates this:

- **Access token:** Short-lived (15–60 minutes). Sent with every API request. If stolen, damage is time-limited.
- **Refresh token:** Long-lived (days to weeks). Stored securely (httpOnly cookie). Sent *only* to the token endpoint to obtain a new access token.

Since the access token expires quickly, you reduce the window of exploitation from a theft. The refresh token is sent far less frequently (only to one endpoint) and can be stored more securely. Additionally, refresh tokens can be stored and validated server-side (rotation + family tracking), enabling revocation when compromise is detected.

**Refresh token rotation:** Each use of a refresh token issues a new one and invalidates the old one. If a stolen refresh token is used, the legitimate session's next refresh detects the mismatch and invalidates the entire family.

---

**Q6. What is stored in a JWT? Is it encrypted? What should you never put in a JWT?**

**A:** A JWT has three Base64URL-encoded parts: a **header** (algorithm and type), a **payload** (claims), and a **signature**.

It is **not encrypted by default** — it is only *signed*. Anyone who intercepts a JWT can decode the header and payload and read its contents. The signature prevents tampering, not reading.

You should **never** store in a JWT:
- Passwords or secrets
- Sensitive PII like SSNs or credit card numbers
- Full session data that might reveal business logic
- Anything that would be harmful if exposed to the user or an attacker

For encrypted JWTs, the JWE (JSON Web Encryption) spec exists, but it's rarely needed in practice — the better approach is keeping tokens short-lived and not putting sensitive data in them.

---

**Q7. How would you implement JWT revocation? What are the trade-offs?**

**A:** JWTs are stateless by design, so revocation requires adding some statefulness back. Common approaches:

**1. Token blocklist (denylist):**
Store revoked `jti` (JWT IDs) in a fast store like Redis with TTL matching the token's expiry. On every request, check if the `jti` is in the blocklist.
```
PROS: Works immediately; targeted revocation
CONS: Requires a store lookup on every request; defeats some of the stateless benefit
```

**2. Short expiry:**
Use very short-lived tokens (5–15 min). "Revocation" just means waiting for natural expiry.
```
PROS: No infrastructure needed
CONS: Logout isn't instant; poor UX for high-security systems
```

**3. Token versioning:**
Store a `tokenVersion` counter on the user record. Include it in the JWT. On each request, check if the JWT's version matches the current user record.
```
PROS: Simple; invalidates all tokens for a user instantly
CONS: DB lookup per request
```

The right choice depends on your security requirements. For most applications, combining short expiry with refresh token rotation provides a good balance.

---

### OAuth & OIDC

---

**Q8. Explain the OAuth 2.0 Authorization Code flow step by step.**

**A:**

1. The client redirects the user to the **authorization server** with parameters: `client_id`, `redirect_uri`, `scope`, `state` (CSRF protection), and `response_type=code`.
2. The user authenticates with the authorization server and grants (or denies) the requested scopes.
3. The authorization server redirects the user back to the `redirect_uri` with a short-lived **authorization code** and the `state` value.
4. The client verifies the `state` matches what it sent, then makes a **server-to-server POST** to the token endpoint, exchanging the code for tokens using `client_id`, `client_secret`, and `code`.
5. The authorization server returns an **access token** and optionally a refresh token.
6. The client uses the access token to call the **resource server** (your API).

The code is single-use and short-lived. The critical security property is that tokens are never exposed in the browser URL — they travel only server-to-server in step 4.

---

**Q9. What is PKCE and why is it required for public clients?**

**A:** PKCE (Proof Key for Code Exchange, pronounced "pixie") is an extension to the Authorization Code flow that protects against **authorization code interception attacks** in environments where a client secret cannot be kept confidential (mobile apps, SPAs, desktop apps).

Without PKCE, a public client cannot use a `client_secret` (since it would be embedded in the app and easily extractable). An attacker who intercepts the authorization code could exchange it for tokens.

PKCE works by having the client:
1. Generate a random `code_verifier`
2. Compute `code_challenge = BASE64URL(SHA256(code_verifier))`
3. Send the `code_challenge` in the authorization request
4. Include the raw `code_verifier` in the token exchange

The authorization server verifies that `SHA256(code_verifier)` matches the stored `code_challenge`. Even if an attacker intercepts the `code`, they don't have the `code_verifier`, so they can't complete the exchange.

---

**Q10. What is the difference between OAuth 2.0 and OpenID Connect?**

**A:** OAuth 2.0 is an **authorization** framework — it allows a client to obtain limited access to a resource on behalf of a user. It says nothing about who the user is; it only says what the client is allowed to do with an access token.

OpenID Connect is an **authentication** layer built on top of OAuth 2.0. It answers the "who is this user?" question by introducing the **ID Token** — a JWT containing verified identity claims (name, email, subject identifier, etc.) about the authenticated user.

In practical terms:
- Use OAuth 2.0 when you want to allow your app to access a user's Google Drive.
- Use OIDC when you want users to *sign in with Google* — you want to know who they are.

OIDC adds a standardized `/userinfo` endpoint, a discovery document (`/.well-known/openid-configuration`), and the `openid` scope.

---

**Q11. What is the `state` parameter in OAuth 2.0 and why is it important?**

**A:** The `state` parameter is an opaque, random value generated by the client and included in the authorization request. After the user is redirected back from the authorization server, the client verifies that the returned `state` matches the one it originally sent.

This protects against **CSRF attacks on the OAuth flow**. Without it, an attacker could trick a user's browser into initiating or completing an OAuth callback that associates the attacker's authorization code with the victim's account — effectively linking the attacker's external account to the victim's account in your app.

Best practice: Generate a cryptographically random `state`, store it in the user's session, and reject any callback where the returned state doesn't match.

---

### Authorization Models

---

**Q12. Compare RBAC and ABAC. When would you use each?**

**A:**

**RBAC (Role-Based Access Control)** assigns users to roles, and roles have permissions. It's simple to reason about and audit — "admins can do X, users can do Y." It works well when access patterns map cleanly to job functions with a manageable number of roles.

**ABAC (Attribute-Based Access Control)** makes decisions based on arbitrary attributes of the subject (user), resource, action, and environment. It enables far more granular policies like "managers in the finance department can approve invoices above $10,000 only during business hours."

**Use RBAC when:**
- You have a small, stable set of roles
- Access is primarily function-based (admin, editor, viewer)
- You need simplicity and easy auditability

**Use ABAC when:**
- You need fine-grained, context-sensitive control
- Access depends on resource ownership, location, time, or other dynamic attributes
- A role explosion would otherwise occur (too many specialized roles)

In practice, many systems combine them: RBAC for coarse-grained access, with ABAC rules applied on top for fine-grained decisions.

---

**Q13. What is the principle of least privilege and how do you apply it in API design?**

**A:** Least privilege means granting users and services only the minimum permissions required to perform their intended function — nothing more.

Applied to API design:
- **Scope tokens narrowly:** OAuth scopes should be granular (`reports:read` not just `all`). Clients request only what they need.
- **Default deny:** Your authorization middleware should deny access unless a permission is explicitly granted, not allow unless explicitly denied.
- **Service accounts:** Internal microservices should have their own credentials with permissions limited to the operations they perform. A reporting service shouldn't have write access to the user database.
- **Time-limited access:** Use short token expiries and purpose-built tokens for sensitive operations.
- **Separation of duties:** Sensitive workflows (e.g., financial approval) should require multiple actors so no single account can complete the chain.
- **Audit regularly:** Review and revoke unused permissions.

---

### Security Vulnerabilities

---

**Q14. What is a timing attack in the context of authentication, and how do you prevent it?**

**A:** A timing attack exploits the fact that string comparison functions short-circuit on the first mismatched character. By measuring response times, an attacker can determine how many characters of a secret they've guessed correctly, allowing incremental brute-forcing.

For example, if comparing a submitted HMAC against the expected value with `===`, a value that matches the first 10 characters will return slightly slower than one that fails on the first character — because the comparison processes more bytes before returning `false`.

**Prevention:** Use **constant-time comparison** functions that always compare every byte regardless of where a mismatch occurs:

```javascript
const crypto = require('crypto');

// Safe: constant-time comparison
const isValid = crypto.timingSafeEqual(
  Buffer.from(providedToken),
  Buffer.from(expectedToken)
);

// UNSAFE: short-circuits
const isValid = providedToken === expectedToken;
```

This applies when comparing: HMAC values, API keys, password reset tokens, and any secret where the timing of a comparison could leak information.

---

**Q15. Explain the difference between storing tokens in localStorage vs httpOnly cookies. What are the security implications?**

**A:**

**localStorage:**
- Accessible by any JavaScript on the page
- Vulnerable to **XSS attacks** — if an attacker injects script, they can read and exfiltrate the token with `localStorage.getItem('token')`
- Not sent automatically — must be added to every request header manually
- Not subject to CSRF (since it's not sent automatically)

**httpOnly cookies:**
- Cannot be read by JavaScript (`document.cookie` won't show it)
- Immune to **XSS token theft** — a script injection can't steal what it can't read
- Sent automatically by the browser — requires **CSRF protection** (`SameSite=Strict/Lax`)
- `Secure` flag ensures HTTPS-only transmission

**Recommendation:** Store tokens in `httpOnly`, `Secure`, `SameSite=Strict` cookies. The CSRF risk is well-mitigated by `SameSite`. XSS is a harder attack surface to fully close, and `httpOnly` cookies remove the most damaging XSS consequence (credential theft).

---

**Q16. What is an IDOR vulnerability? How do you detect and prevent it?**

**A:** An Insecure Direct Object Reference (IDOR) occurs when an API exposes direct references to internal objects (like a database ID) without verifying the requesting user has authorization to access that specific object.

Example: `GET /api/invoices/5523` — if the backend only checks that the user is authenticated but not that invoice 5523 belongs to *them*, any authenticated user can access any invoice by changing the ID.

**Detection:**
- During testing, authenticate as User A, capture a resource URL, then access it as User B
- Automated tools (Burp Suite, OWASP ZAP) can fuzz object IDs
- Code review: look for queries that use request params as IDs without ownership checks

**Prevention:**
```javascript
// WRONG: only checks authentication
const invoice = await db.invoices.findById(req.params.id);

// CORRECT: checks ownership
const invoice = await db.invoices.findOne({
  id: req.params.id,
  userId: req.user.sub  // Must belong to the requesting user
});
if (!invoice) return res.status(404).json({ error: 'Not found' });
// Return 404, not 403 — don't confirm the resource exists
```

Using UUIDs instead of sequential integers also makes guessing harder, but this is defense-in-depth, not a substitute for authorization checks.

---

**Q17. How would you design a secure logout mechanism for a JWT-based API?**

**A:** This is a nuanced problem because JWTs are stateless. A complete logout implementation involves several layers:

1. **Client-side:** Delete the access token from memory and remove the refresh token cookie.

2. **Refresh token invalidation:** Mark the refresh token as revoked in the database. This prevents new access tokens from being issued.

3. **Access token invalidation (optional):** If the access token is short-lived (< 15 min), you may accept the risk of it remaining valid until expiry. For higher security, add the token's `jti` to a Redis blocklist with TTL equal to its remaining lifetime.

```javascript
// Logout endpoint
router.post('/auth/logout', verifyToken, async (req, res) => {
  // 1. Revoke refresh token in DB
  await db.refreshTokens.update(
    { userId: req.user.sub },
    { revokedAt: new Date() }
  );

  // 2. Optionally blocklist the current access token
  const ttlSeconds = req.user.exp - Math.floor(Date.now() / 1000);
  if (ttlSeconds > 0) {
    await redis.setex(`blocklist:${req.user.jti}`, ttlSeconds, '1');
  }

  // 3. Clear refresh token cookie
  res.clearCookie('refresh_token', { httpOnly: true, secure: true });
  res.json({ message: 'Logged out' });
});
```

---

### Advanced & System Design

---

**Q18. How does authentication work in a microservices architecture?**

**A:** In a microservices architecture, you typically offload authentication to a centralized component:

**Pattern 1: API Gateway handles auth**
The gateway validates the JWT (or session) on every inbound request. Once validated, it passes the user identity (user ID, roles) to downstream services via trusted internal headers (`X-User-Id`, `X-User-Roles`). Downstream services trust these headers since they come from the internal network.

**Pattern 2: Service-to-service with short-lived tokens**
Each service issues short-lived tokens for internal calls (client credentials flow). Services validate each other's tokens against a shared JWKS endpoint.

**Key considerations:**
- Use a **centralized auth service** or third-party IdP (Auth0, Keycloak) — don't re-implement auth in each service
- Propagate identity via **JWT claims** — services can verify tokens without calling back to the auth service on every request
- **mTLS (mutual TLS)** for service-to-service trust at the transport layer
- Implement **consistent audit logging** — all services should log `user_id` and `request_id` for tracing

---

**Q19. What is token introspection and when would you use it over JWT local verification?**

**A:** Token introspection (RFC 7662) is a mechanism where a resource server calls the authorization server's `/introspect` endpoint to validate a token and retrieve its metadata in real time.

```
Resource Server → POST /introspect { token: "..." } → Auth Server
Auth Server → { active: true, sub: "user123", scope: "read:reports", exp: ... }
```

**Local JWT verification** validates the token using a cached public key, without a network call. It's fast but cannot detect if a token has been explicitly revoked before expiry.

**Use introspection when:**
- Token revocation must be immediately effective (e.g., after a security event)
- Tokens are opaque (not JWTs) and carry no self-contained claims
- You're implementing a resource server that doesn't own the auth infrastructure

**Use local verification when:**
- Low-latency is critical (high-throughput APIs)
- You accept that revoked tokens remain valid until natural expiry
- You control the auth server and can use short token lifetimes

In practice, many systems use local verification for access tokens (short-lived) and introspection or DB checks for refresh tokens (long-lived, must be revocable).

---

**Q20. How would you implement row-level security — ensuring users can only access their own data at scale?**

**A:** Row-level security (RLS) can be enforced at multiple levels:

**1. Application layer (always required):**
Always scope queries by user ID. Never trust the client to supply the owner filter.
```javascript
const posts = await db.posts.findAll({ userId: req.user.sub });
```

**2. Database-level RLS (PostgreSQL):**
```sql
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_posts ON posts
  USING (user_id = current_setting('app.current_user_id')::uuid);

-- Set the user context per transaction
SET LOCAL app.current_user_id = 'user-uuid-here';
```

This provides a second layer of defense — even if application code has a bug and omits the user filter, the DB rejects unauthorized rows.

**3. At scale — tenant isolation in multi-tenant SaaS:**
- Separate schemas or databases per tenant (strong isolation, higher cost)
- Shared schema with `tenant_id` on every table and composite indexes `(tenant_id, id)`
- All queries must include `tenant_id` filter; enforced via middleware or ORM hooks

**4. Caching:**
Be careful with caching — never cache data by resource ID alone. Cache keys must include `userId` or `tenantId`:
```
cache key: `posts:${userId}:${postId}` not `posts:${postId}`
```

---

**Q21. How do you handle token refresh safely, especially against race conditions?**

**A:** In SPAs or mobile apps, multiple concurrent requests can all detect an expired access token simultaneously and each attempt to refresh, causing multiple token exchanges and potential refresh token invalidation issues.

**Solution: Refresh token locking / single-flight pattern:**

```javascript
let refreshPromise = null;

const getValidAccessToken = async () => {
  if (!isTokenExpired(accessToken)) return accessToken;

  // If a refresh is already in progress, wait for it
  if (refreshPromise) return await refreshPromise;

  // Start a single refresh
  refreshPromise = performTokenRefresh()
    .finally(() => { refreshPromise = null; });

  return await refreshPromise;
};
```

**Server-side refresh token rotation:**
When a refresh token is used, immediately issue a new one and invalidate the old one. If the same refresh token is used twice (replay attack), invalidate the entire token family:

```javascript
const existingToken = await db.refreshTokens.findOne({ tokenHash: hash(incomingToken) });

if (existingToken.used) {
  // Possible theft — invalidate entire session family
  await db.refreshTokens.deleteAll({ familyId: existingToken.familyId });
  throw new Error('Refresh token reuse detected');
}

await db.refreshTokens.update({ id: existingToken.id }, { used: true });
// Issue new token...
```

---

## Quick Reference Cheatsheet

```
Authentication Flows
──────────────────────────────────────────────────────────
Web App (traditional)     → Session + httpOnly cookie
SPA / Mobile              → JWT (access token in memory) + refresh token in httpOnly cookie
Server-to-server (M2M)    → OAuth Client Credentials / API keys
Third-party login         → OAuth 2.0 Authorization Code + PKCE + OIDC
High-security             → All above + MFA (TOTP / passkeys)

Authorization Models
──────────────────────────────────────────────────────────
Small set of roles        → RBAC
Fine-grained / dynamic    → ABAC
Microservices / cloud     → Policy-based (IAM-style)
Per-user customization    → Direct permission mapping

HTTP Status Codes
──────────────────────────────────────────────────────────
401 Unauthorized          → Not authenticated (missing/invalid credentials)
403 Forbidden             → Authenticated but lacks permission
404 Not Found             → Use instead of 403 to avoid leaking resource existence

Token Storage
──────────────────────────────────────────────────────────
Access Token              → In-memory JS variable (lost on refresh — that's OK)
Refresh Token             → httpOnly + Secure + SameSite=Strict cookie
API Keys                  → httpOnly cookie or secure vault; never localStorage
```

---

## Further Reading

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [The OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

---

*Built for backend engineers preparing for senior-level interviews and production system design.*
