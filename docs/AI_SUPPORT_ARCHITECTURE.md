# SentinelForge AI Support Assistant — Backend Architecture

## Overview

The SentinelForge AI Support Assistant ("SentinelForge AI Support") is a read-only support chatbot for visitors of the public SentinelForge website. It is **not** the Hermes Agent dashboard, and it does **not** expose Hermes Agent capabilities to public visitors.

## Architecture

```
Public Website (GitHub Pages)
        │ HTTPS (CORS-restricted)
        ▼
Secure Support Backend (server-side, hosted separately)
        │ server-to-server, authenticated
        ▼
Isolated Hermes Agent Profile (dedicated support profile)
        │ read-only tool access
        ▼
Curated SentinelForge Knowledge Base (public docs only)
```

### Components

1. **Public Website** — Static HTML/CSS/JS on GitHub Pages. Contains only the chat widget UI. No API keys, no secrets, no backend code.

2. **Secure Support Backend** — A separate server-side application (not part of the public website) that:
   - Receives chat messages from the website over HTTPS
   - Authenticates requests to the Hermes Agent API server
   - Validates and sanitizes user message payloads
   - Enforces rate limiting, request size limits, and timeouts
   - Restricts allowed origins (CORS)
   - Forwards only to the dedicated Hermes support profile
   - Returns model responses to the website

3. **Hermes Agent API Server** — Running with a dedicated support profile, isolated from the default/development profile. Configured to expose only read-only knowledge-base tools.

4. **Knowledge Base** — Curated, approved documentation only (README, CONTRIBUTING, SECURITY, installation docs, architecture, detection rules, demo docs, dashboard docs, FAQ). No real SOC data, no credentials, no personal memory.

## Security Controls

### Backend
- **Credentials server-side only** — `API_SERVER_KEY` and other secrets live in backend environment variables, never in browser code.
- **Authentication** — Backend authenticates to Hermes API server; website authenticates to backend via scoped tokens.
- **Input validation** — Message payloads validated for size, type, and content before forwarding.
- **Rate limiting** — Per-IP and per-session request limits to prevent abuse.
- **Request timeouts** — Bounded timeouts on all upstream calls.
- **CORS restriction** — Only the public website origin is allowed.
- **No arbitrary endpoint forwarding** — Backend only calls the designated Hermes chat endpoint.
- **Minimal logging** — No sensitive conversation content logged.
- **Error handling** — Failures return generic messages; no stack traces or internal details exposed.

### Frontend (Chat Widget)
- **No secrets in browser** — No API keys, tokens, or credentials in HTML/CSS/JS.
- **Safe rendering** — Model output treated as text, never as HTML (no `innerHTML`).
- **XSS prevention** — All user and model content escaped before DOM insertion.
- **CSP** — Content Security Policy restricts script and connection sources.
- **Accessibility** — ARIA labels, keyboard navigation, screen-reader support.

### Hermes Profile Isolation
The support profile is isolated from:
- The default Hermes profile
- Development sessions
- The project workspace
- Personal memory
- The Windows filesystem
- GitHub credentials and connected accounts

### Tool Restrictions
The support profile exposes **only** read-only knowledge-base tools:
- `search_sentinelforge_docs(query)`
- `get_sentinelforge_doc_section(document_id, section)`

The following are **explicitly denied**:
- File write, command execution, arbitrary path access
- GitHub modification, penetration testing, SQLite queries
- Personal memory access, external account access, email/sms
- Scheduled jobs, unrestricted web browsing, shell access

## Backend Hosting

GitHub Pages cannot execute the Hermes backend. The backend must be hosted separately over HTTPS.

### Options Evaluated
- **Existing Windows Hermes installation** — Not suitable for permanent public hosting (would require exposing local ports).
- **Free-tier serverless hosting** — Candidate (e.g., cloud functions), but requires separate deployment and may incur costs at scale.
- **No additional cost option** — Not currently available without user approval.

### Recommendation
Implement and test the support backend locally, then document exact deployment requirements. Do not purchase hosting or create recurring billing without explicit user approval.

## Status

### Implemented
- Chat widget UI (HTML/CSS/JS) on all 15 public pages
- Safe text-only DOM rendering (no `innerHTML` for dynamic content)
- Accessible panel with Escape key handling, focus management, focus restoration
- ARIA labels, dialog semantics, screen-reader support
- Mobile-responsive layout
- Preview notice clearly stating the AI backend is not hosted
- No API keys or secrets in browser code

### Not implemented
- Actual Hermes Agent API Server connection
- Public support backend (no `/api/support/chat` endpoint implemented)
- Backend authentication (no `API_SERVER_KEY` usage in browser — correctly absent)
- Backend rate limiting (not implemented — backend does not exist)
- Live SSE streaming responses
- Production session management (sessions are browser-session only, cleared on refresh)

### Backend connection status
The widget's `sendUserMessage()` does **not** make any API request. It displays a preview notice and does not simulate AI typing or responses. The code is structured for future backend integration but no backend endpoint is implemented or called.

