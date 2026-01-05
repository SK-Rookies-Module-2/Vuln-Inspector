## Custom Instructions  
Guide Strix with custom testing instructions

Use instructions to provide context, credentials, or focus areas for your scan.
​
Inline Instructions  
```
strix --target https://app.com --instruction "Focus on authentication vulnerabilities"  
```

File-Based Instructions
For complex instructions, use a file:
```
strix --target https://app.com --instruction-file ./pentest-instructions.md
```
Common Use Cases
​
Authenticated Testing
```
strix --target https://app.com \
  --instruction "Login with email: test@example.com, password: TestPass123"
```

Focused Scope
```
strix --target https://api.example.com \
  --instruction "Focus on IDOR vulnerabilities in the /api/users endpoints"
```

Exclusions
```
strix --target https://app.com \
  --instruction "Do not test /admin or /internal endpoints"
```
API Testing
```
strix --target https://api.example.com \
  --instruction "Use API key header: X-API-Key: abc123. Focus on rate limiting bypass."
```

Instruction File Example
instructions.md
```
# Penetration Test Instructions

## Credentials
- Admin: admin@example.com / AdminPass123
- User: user@example.com / UserPass123

## Focus Areas
1. IDOR in user profile endpoints
2. Privilege escalation between roles
3. JWT token manipulation

## Out of Scope
- /health endpoints
- Third-party integrations
Be specific. Good instructions help Strix prioritize the most valuable attack paths.
```
## Scan mode
Choose the right scan depth for your use case  

Strix offers three scan modes to balance speed and thoroughness.
​
Quick
```
strix --target ./app --scan-mode quick  
```
Fast checks for obvious vulnerabilities. Best for:  
- CI/CD pipelines  
- Pull request validation  
- Rapid smoke tests  
Duration: Minutes   

Standard  
```
strix --target ./app --scan-mode standard
```
Balanced testing for routine security reviews. Best for:  
- Regular security assessments
- Pre-release validation
- Development milestones  
Duration: 30 minutes to 1 hour

Deep
```
strix --target ./app --scan-mode deep
```
Thorough penetration testing. Best for:  
- Comprehensive security audits
- Pre-production reviews
- Critical application assessments

Duration: 1-4 hours depending on target complexity
Deep mode is the default. It explores edge cases, chained vulnerabilities, and complex attack paths.

## CLI Reference
Command-line options for Strix

​
Basic Usage
```
strix --target <target> [options]
```
Options
​
--target, -t
stringrequired
Target to test. Accepts URLs, repositories, local directories, domains, or IP addresses. Can be specified multiple times.
​
--instruction
string
Custom instructions for the scan. Use for credentials, focus areas, or specific testing approaches.
​
--instruction-file
string
Path to a file containing detailed instructions.
​
--scan-mode, -m
stringdefault:"deep"
Scan depth: quick, standard, or deep.
​
--non-interactive, -n
boolean
Run in headless mode without TUI. Ideal for CI/CD.
​
--run-name
string
Custom name for this scan run.
​
Examples
```
# Basic scan
strix --target https://example.com

# Authenticated testing
strix --target https://app.com --instruction "Use credentials: user:pass"

# Focused testing
strix --target api.example.com --instruction "Focus on IDOR and auth bypass"

# CI/CD mode
strix -n --target ./ --scan-mode quick

# Multi-target white-box testing
strix -t https://github.com/org/app -t https://staging.example.com
```

Exit Codes  
Code	Meaning
0	Scan completed, no vulnerabilities found
2	Vulnerabilities found (headless mode only)

