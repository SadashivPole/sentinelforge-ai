# SentinelForge AI Support Assistant — Security Review

## Threat Model

| Threat | Asset | Impact | Likelihood | Control | Residual Risk |
|--------|-------|--------|------------|---------|---------------|
| API key exfiltration from browser | Hermes API credentials | High | Low | No keys in frontend; backend-only | Low |
| Prompt injection | Knowledge base responses | Medium | Low | Read-only tools only; no tool escalation | Low |
| Malicious user input | Backend / model | Medium | Low | Input validation, size limits, sanitization | Low |
| Knowledge base poisoning | Model responses | Medium | Low | Curated, approved docs only; no user-contributed content | Low |
| CORS misconfiguration | Backend endpoint | Medium | Low | Origin restricted to public website domain | Low |
| Rate abuse / DoS | Backend availability | Medium | Medium | Rate limiting, timeouts, concurrency limits | Low |
| Conversation logging leakage | User messages | Low | Low | Minimal logging; no sensitive content retained | Low |
| XSS via model output | Website visitors | High | Low | Text-only rendering; no innerHTML; CSP | Low |
| Unrestricted tool access | Host system | Critical | Low | Hermes support profile with read-only tools only | Low |

## Frontend Security

### Content Security Policy
The chat widget operates within the website's CSP. Scripts and connections are restricted to same-origin and the designated backend endpoint.

### Safe Rendering
All model output is escaped using `textContent` — never inserted via `innerHTML`. User input is similarly escaped before display.

### No Third-Party Trackers
The chat widget loads only local CSS/JS. No external scripts, trackers, or analytics.

## Backend Security

### Authentication
- Website → Backend: scoped session tokens
- Backend → Hermes API: `API_SERVER_KEY` from server-side environment variables

### Input Validation
- Message size capped (e.g., 4000 characters)
- JSON schema validation on all payloads
- Rejection of non-chat message types

### Rate Limiting
- Per-IP request limits
- Per-session concurrent request limits
- Exponential backoff on repeated violations

### CORS
- `Access-Control-Allow-Origin` restricted to `https://sadashivpole.github.io`
- No wildcard origins

### Error Handling
- Upstream failures return generic messages to the client
- No stack traces, internal URLs, or system details exposed

## AI Security

### Prompt Injection Defense
- System prompt instructs model to treat user input as data, not instructions
- No tool execution based on model output
- Knowledge-base tools are read-only with fixed schemas

### Knowledge Base Protection
- Only approved, curated documentation is retrievable
- No user-submitted content can be added to the knowledge base
- No retrieval of arbitrary URLs or external sources

### Tool Restrictions
The Hermes support profile is configured with:
```
Allowed tools: search_sentinelforge_docs, get_sentinelforge_doc_section
Denied: file_write, command_execute, path_access, github_modify,
          pentest, sqlite_query, memory_access, external_account,
          email_send, schedule_job, unrestricted_browse, shell_access
```

## Session Isolation

- Each chat session is independent
- No cross-session state leakage
- No personal memory accessed
- No development environment access

## Data Retention

- Conversation history retained only for the active browser session
- Cleared on page refresh or "Clear conversation"
- No persistent storage of visitor conversations

## Residual Risks

1. **Backend not yet deployed** — The widget shows a status message explaining the backend is not yet hosted. Visitors cannot interact with a live AI assistant until a secure backend is deployed.

2. **Dependency on third-party model provider** — Model responses depend on the Hermes provider's safety filters. The backend applies additional validation but cannot guarantee provider-level safety.

## Review Status

- ✅ Frontend XSS prevention implemented
- ✅ No secrets in browser code
- ✅ Chat widget uses text-only rendering
- ✅ Hermes profile isolation documented
- ✅ Tool restrictions documented
- ✅ Backend security controls documented
- ❌ Backend not yet deployed — deployment requirements documented
