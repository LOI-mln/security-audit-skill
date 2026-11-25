# Standards Mapping

#### When to use this file

Use it in every full audit: each reported record is classified against the standards below, and the report shows coverage per standard. In guidance mode, use it when the user names a standard or asks where a weakness falls in one.

The identifiers here and in `standards-index.json` are the only ones a record may cite. `standards.cjs` checks every reference against that index, so an identifier that no standard defines fails validation instead of reaching a report.

## Standards carried

| Standard | Edition | Reference form | What it classifies |
|---|---|---|---|
| MITRE CWE | current list | `CWE-79` | The weakness type behind the root cause |
| OWASP Top 10 | 2025, with 2021 for readers still on it | `A01:2025` | The risk category |
| OWASP ASVS | 5.0.0 | `v5.0.0-8.2.2` (requirement) or `v5.0.0-8.2` (section) | The verification requirement the code meets or fails |
| ISO/IEC 27001 Annex A | 2022 (same numbering as ISO/IEC 27002:2022) | `A.8.28` | The control the evidence is relevant to |

### When the request names a standard loosely

People name standards from memory. Resolve the name to the closest published standard, state the resolution in the first section of the report, and never invent an identifier to match the wording.

| The request says | Use |
|---|---|
| "OWASP", "OWASP 10", "OWASP 1000", "the OWASP list" | OWASP Top 10 for categories, OWASP ASVS for requirements |
| "CWE 1000", "the CWE list" | CWE references. CWE-1000 is the view that holds the complete weakness hierarchy; it is not a weakness and cannot be cited |
| "ISO 27000", "ISO 2700x", "ISO 7400", "the ISO security norm" | ISO/IEC 27001:2022 Annex A |
| PCI DSS, SOC 2, NIS2, HDS, GDPR articles, a national scheme | Not carried. Say so, map to the four standards above, and leave the named standard to its owner |

## Core discipline (include in every agent prompt that classifies records)

1. **Classify after the evidence, never before.** A reference does not raise or lower a verdict, a severity or a priority. Settle the record first, then classify it.
2. **Cite only identifiers from this file or `standards-index.json`.** When you are unsure of an ASVS requirement number, cite its section. A plausible-looking number that does not exist is worse than a coarser true one.
3. **CWE names the root cause.** Use the most specific Base or Variant weakness. Use a Class only when no Base fits. Never cite a view (CWE-1000, CWE-1003), a category (CWE-16, CWE-264, CWE-310) or a pillar (CWE-284, CWE-693, CWE-707): MITRE prohibits or discourages them as mapping targets and the validator rejects them. List the root cause first; add a second CWE only for a distinct weakness in the same record.
4. **Top 10 gets the 2025 category, plus the 2021 category when it differs.** Readers on either edition can then find the record.
5. **ISO/IEC 27001 is about a management system.** Source review produces evidence relevant to an Annex A control. It cannot establish conformity or nonconformity, which an auditor decides against the organization's Statement of Applicability. Write "relevant to A.8.28", never "violates ISO 27001" or "ISO 27001 compliant".
6. **A mapping is not a finding.** A deviation from a requirement with no demonstrated boundary failure belongs in the conformance review ([STANDARDS-CONFORMANCE.md](STANDARDS-CONFORMANCE.md)) as a `gap`. It never enters `findings.json` on the strength of its identifier.

## Crosswalk by attack class

Start from the row that names the root cause, then check each reference against the record. Top 10:2021 categories follow OWASP's published CWE lists; the 2025 column takes the category that succeeded it. When the 2025 edition's own list places a weakness elsewhere, follow the 2025 list.

| Root cause | CWE | Top 10:2025 | Top 10:2021 | ASVS 5.0.0 | ISO Annex A |
|---|---|---|---|---|---|
| SQL or other query injection | CWE-89, CWE-943 | A05 | A03 | 1.2.4 | A.8.28 |
| OS command or argument injection | CWE-78, CWE-88 | A05 | A03 | 1.2.5 | A.8.28 |
| Cross-site scripting (stored, reflected, DOM) | CWE-79 | A05 | A03 | 1.2.1, 1.2.3, 1.3.1, 3.2.2 | A.8.28 |
| Code or template injection, eval | CWE-95, CWE-1336 | A05 | A03 | 1.3.2, 1.3.7 | A.8.28 |
| Unsafe deserialization | CWE-502 | A08 | A08 | 1.5.2 | A.8.28 |
| XML external entities | CWE-611 | A02 | A05 | 1.5.1 | A.8.28 |
| CSV or formula injection | CWE-1236 | A05 | A03 | 1.2.10 | A.8.28 |
| Log injection | CWE-117 | A09 | A09 | 16.4.1 | A.8.15 |
| Prototype pollution | CWE-1321 | A08 | A08 | 15.3.6 | A.8.28 |
| Missing authentication on a function | CWE-306 | A07 | A07 | 8.2.1 | A.8.5 |
| Missing or wrong function-level authorization | CWE-862, CWE-863 | A01 | A01 | 8.2.1, 8.3.1 | A.5.15, A.8.3 |
| Object-level authorization bypass (IDOR) | CWE-639 | A01 | A01 | 8.2.2 | A.8.3 |
| Tenant isolation failure | CWE-639 | A01 | A01 | 8.4.1 | A.8.3 |
| Mass assignment, field-level authorization | CWE-915 | A08 (A01 when the field grants authority) | A08 | 8.2.3, 15.3.3 | A.8.3 |
| Privilege escalation, self-granted role | CWE-269 | A01 | A01 | 8.2.1 | A.8.2 |
| Cross-site request forgery | CWE-352 | A01 | A01 | 3.5.1 | A.8.26 |
| Server-side request forgery | CWE-918 | A01 | A10 | 1.3.6 | A.8.22 |
| Path traversal | CWE-22 | A01 | A01 | 5.3.2, 5.4.1 | A.8.28 |
| Unrestricted file upload | CWE-434 | A06 | A04 | 5.2.2, 5.3.1 | A.8.7 |
| Open redirect | CWE-601 | A01 | A01 | 3.7.2 | A.8.28 |
| Sensitive data in a response or export | CWE-201, CWE-359 | A01 | A01 | 15.3.1, 14.2.6 | A.8.11, A.5.34 |
| Brute force, missing throttle or lockout | CWE-307 | A07 | A07 | 6.3.1 | A.8.5 |
| Weak password policy | CWE-521 | A07 | A07 | 6.2.1 | A.5.17 |
| Weak password recovery or reset | CWE-640 | A07 | A07 | 6.4.3 | A.5.17 |
| Account enumeration | CWE-204 | A07 | A07 | 6.3.8 | A.8.5 |
| Hard-coded or default credentials | CWE-798, CWE-1392 | A07 | A07 | 13.3.1, 6.3.2 | A.5.17 |
| Session fixation | CWE-384 | A07 | A07 | 7.2.4 | A.8.5 |
| Session not expired or not terminated | CWE-613 | A07 | A07 | 7.3.1, 7.4.1 | A.8.5 |
| Certificate validation disabled | CWE-295 | A07 | A07 | 12.3.2 | A.8.24 |
| Weak password storage | CWE-916 | A04 | A02 | 11.4.2 | A.8.24 |
| Weak or broken cryptography | CWE-327, CWE-328 | A04 | A02 | 11.3.2, 11.4.1 | A.8.24 |
| Weak randomness for a security value | CWE-338 | A04 | A02 | 11.5.1 | A.8.24 |
| Missing signature or integrity verification | CWE-347 | A04 | A02 | 11.3.3 | A.8.24 |
| Cleartext transmission | CWE-319 | A04 | A02 | 12.2.1 | A.8.24 |
| Cookie without Secure, HttpOnly or SameSite | CWE-614, CWE-1004, CWE-1275 | A02 | A05 | 3.3.1, 3.3.2, 3.3.4 | A.8.26 |
| Permissive CORS | CWE-942 | A02 | A05 | 3.4.2 | A.8.26 |
| Debug feature reachable in production | CWE-489 | A02 | A05 | 13.4.2 | A.8.9 |
| Service or container with excessive privilege | CWE-250 | A02 | A05 | 13.2.2 | A.8.2 |
| Vulnerable or unmaintained dependency | CWE-1395, CWE-1104 | A03 | A06 | 15.2.1 | A.8.8 |
| Untrusted code or unpinned input in a build | CWE-829, CWE-494 | A03 | A08 | 15.2.4 | A.5.21, A.8.25 |
| Clickjacking | CWE-1021 | A06 | A04 | 3.4.6 | A.8.26 |
| Request smuggling, parser disagreement | CWE-444 | A06 | A04 | 4.2.1 | A.8.26 |
| Business logic or workflow bypass | CWE-841 | A06 | A04 | 2.3.1 | A.8.26 |
| Race condition, check-then-act | CWE-362, CWE-367 | A06 | A04 | 2.3.4, 15.4.2 | A.8.27 |
| Missing resource limit, amplification | CWE-770, CWE-1333 | A06 | A04 | 2.4.1, 15.2.2, 1.3.12 | A.8.6 |
| Sensitive data written to logs | CWE-532 | A09 | A09 | 16.2.5 | A.8.15 |
| Security event not logged | CWE-778 | A09 | A09 | 16.3.1, 16.3.2 | A.8.15 |
| Error message discloses internals | CWE-209 | A10 | A04 | 16.5.1 | A.8.26 |
| Control fails open on error | CWE-636 | A10 | A04 | 16.5.3 | A.8.27 |
| Memory safety (out of bounds, use after free, integer overflow) | CWE-787, CWE-125, CWE-416, CWE-190 | none fits | none fits | 1.4.1, 1.4.2, 1.4.3 | A.8.28 |
| Prompt injection into a model | CWE-1427 | none fits | none fits | none fits | A.8.28 |

When no Top 10 category fits, leave `owasp_top10` out and cite the other standards. The OWASP Top 10 for LLM Applications and the OWASP API Security Top 10 are separate lists; name them in prose when relevant, since their identifiers are not carried here.

## Reference: OWASP Top 10

| | 2025 | 2021 |
|---|---|---|
| A01 | Broken Access Control (now includes SSRF) | Broken Access Control |
| A02 | Security Misconfiguration | Cryptographic Failures |
| A03 | Software Supply Chain Failures | Injection |
| A04 | Cryptographic Failures | Insecure Design |
| A05 | Injection | Security Misconfiguration |
| A06 | Insecure Design | Vulnerable and Outdated Components |
| A07 | Authentication Failures | Identification and Authentication Failures |
| A08 | Software or Data Integrity Failures | Software and Data Integrity Failures |
| A09 | Security Logging and Alerting Failures | Security Logging and Monitoring Failures |
| A10 | Mishandling of Exceptional Conditions | Server-Side Request Forgery (SSRF) |

## Reference: OWASP ASVS 5.0.0 chapters

V1 Encoding and Sanitization · V2 Validation and Business Logic · V3 Web Frontend Security · V4 API and Web Service · V5 File Handling · V6 Authentication · V7 Session Management · V8 Authorization · V9 Self-contained Tokens · V10 OAuth and OIDC · V11 Cryptography · V12 Secure Communication · V13 Configuration · V14 Data Protection · V15 Secure Coding and Architecture · V16 Security Logging and Error Handling · V17 WebRTC

`standards-index.json` lists every section title and the number of requirements in each section. The requirement text itself lives in the ASVS; cite a requirement number only when it appears in this file, in `conformance-checklist.json`, or in a copy of the standard you have in hand.

## Reference: ISO/IEC 27001:2022 Annex A controls most often relevant to source

Organizational: A.5.14 Information transfer · A.5.15 Access control · A.5.16 Identity management · A.5.17 Authentication information · A.5.18 Access rights · A.5.19 Information security in supplier relationships · A.5.21 Managing information security in the ICT supply chain · A.5.23 Information security for use of cloud services · A.5.28 Collection of evidence · A.5.33 Protection of records · A.5.34 Privacy and protection of PII · A.5.37 Documented operating procedures

Technological: A.8.2 Privileged access rights · A.8.3 Information access restriction · A.8.4 Access to source code · A.8.5 Secure authentication · A.8.6 Capacity management · A.8.7 Protection against malware · A.8.8 Management of technical vulnerabilities · A.8.9 Configuration management · A.8.10 Information deletion · A.8.11 Data masking · A.8.12 Data leakage prevention · A.8.13 Information backup · A.8.15 Logging · A.8.16 Monitoring activities · A.8.19 Installation of software on operational systems · A.8.20 Networks security · A.8.21 Security of network services · A.8.22 Segregation of networks · A.8.24 Use of cryptography · A.8.25 Secure development life cycle · A.8.26 Application security requirements · A.8.27 Secure system architecture and engineering principles · A.8.28 Secure coding · A.8.29 Security testing in development and acceptance · A.8.30 Outsourced development · A.8.31 Separation of development, test and production environments · A.8.32 Change management · A.8.33 Test information · A.8.34 Protection of information systems during audit testing

Annex A has 93 controls in four themes: 5 organizational (37), 6 people (8), 7 physical (14), 8 technological (34). People and physical controls are almost never visible in a repository; do not cite them from source.

## Validation rules (apply before reporting ANY mapping)

1. Every reference resolves in `standards-index.json`, and each ASVS requirement cited appears in this file or the checklist.
2. The first CWE names the root cause in the record, not a consequence and not a broader family.
3. The Top 10 category matches the root cause, not the impact. An IDOR that leaks data is A01, not a cryptographic failure.
4. The mapping left the verdict, severity and priority exactly as the evidence set them.
5. No sentence in any report claims conformity or nonconformity with ISO/IEC 27001, and none calls a conformance gap a vulnerability.
