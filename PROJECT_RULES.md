# SentinelForge — Project Rules

## Project Purpose
SentinelForge is an open-source detection-engineering and security-monitoring platform/lab inspired by modern SIEM and Microsoft Sentinel workflows.

Core workflow:
```
Authorized Attack Simulation
        ↓
Endpoint/System Telemetry
        ↓
Log Collection
        ↓
Telemetry Processing
        ↓
Detection Rules
        ↓
Alert Generation
        ↓
Incident Investigation
        ↓
MITRE ATT&CK Mapping
        ↓
Response/Automation
        ↓
Detection Validation
        ↓
Detection-as-Code
```

## Architecture Principles
- Start as a modular monolith. Do not create microservices unless there is a demonstrated need.
- Keep modules loosely coupled.
- Use clear interfaces between telemetry, detection, alerts, investigation and response.
- Separate configuration from code.
- Design for future Azure integration without making Azure mandatory.
- Prefer maintainability over unnecessary abstraction.

## Technology Choices
| Layer | Technology |
|-------|------------|
| Frontend | React, TypeScript, Vite |
| Backend | Python, Flask, REST API |
| Database | PostgreSQL |
| Infrastructure | Docker, Docker Compose |
| Version Control | Git, GitHub |
| Security Frameworks | MITRE ATT&CK, Detection-as-Code, Secure coding practices |

## Development Workflow
For every stage:
1. Inspect the existing repository.
2. Explain what the stage will accomplish.
3. Create/modify only the files required for that stage.
4. Implement the stage.
5. Run appropriate tests/checks.
6. Review the implementation for obvious security problems.
7. Report exactly what changed.
8. Report how to verify it.
9. Tell the next stage.
10. STOP and wait for approval.

Do NOT:
- Rewrite unrelated files
- Install unnecessary dependencies
- Create fake functionality just to make tests pass
- Silently skip errors
- Create architecture that cannot realistically be implemented
- Over-engineer the project

## Security Principles
The application must eventually consider:
- Authentication
- Authorization
- RBAC
- Input validation
- SQL injection prevention
- XSS prevention
- CSRF protection
- IDOR prevention
- SSRF prevention
- Command injection prevention
- Path traversal prevention
- Unsafe file upload prevention
- Secrets management
- Rate limiting
- Audit logging
- Secure error handling
- Dependency security
- Least privilege

## Cyber-Safety Boundaries
- All attack simulation functionality must be designed for authorized labs and systems only.
- Do not implement destructive malware, uncontrolled persistence, credential theft, or harmful payload delivery.

## Demo Mode (Local)
SentinelForge MUST have a completely functional local/demo mode without Azure.
- No Azure credentials required
- No Azure resources required
- All core workflows operational locally

## Future Azure Mode
Planned integrations (optional, not required for demo):
- Azure Monitor
- Data Collection Rules
- Log Analytics
- Microsoft Sentinel
- KQL

## Coding & Testing Expectations
- Write practical, production-oriented code
- Keep implementation maintainable
- Do not introduce unnecessary complexity
- Teach architecture and important decisions during implementation
- Run lint/typecheck commands after changes
- Group changes logically for separate commits