"""Researched security knowledge behind the budget plan: what each attack damages, which controls exist, what they cost
(published prices where a vendor publishes one) and how to sequence them. Framework-free.

Every number is either (a) a figure published by the cited source, written in our own words, or (b) an explicit modelling
assumption, labelled as such. Prices are list prices seen in November 2026 and converted at USD_INR; vendors change prices.
Control effectiveness values are ASSUMPTIONS informed by the evidence text beside them, not guarantees."""
from __future__ import annotations
import math

USD_INR = 88.0            # assumption for converting published USD prices; change to today's rate

SOURCES = {
    "ibm-in": ("IBM Cost of a Data Breach 2025, India edition", "https://in.newsroom.ibm.com/2025-08-07-India-Records-Highest-Average-Cost-of-a-Data-Breach-IBM"),
    "ibm-global": ("IBM Cost of a Data Breach 2025, global findings", "https://newsroom.ibm.com/2025-07-30-ibm-report-13-of-organizations-reported-breaches-of-ai-models-or-applications,-97-of-which-reported-lacking-proper-ai-access-controls"),
    "ibm-detect": ("Help Net Security on IBM 2025: internal detection saves $900,000", "https://www.helpnetsecurity.com/?p=337796"),
    "dbir25": ("Flare on Verizon DBIR 2025: credentials in 88% of basic web application attacks", "https://flare.io/learn/resources/blog/stolen-credentials-in-cybercrime-insights-2025-verizon-dbir"),
    "dbir25b": ("SpyCloud on Verizon DBIR 2025: stolen credentials the top initial access vector (22%)", "https://spycloud.com/blog/verizon-2025-data-breach-report-insights"),
    "dbir24": ("Verizon DBIR 2024: Basic Web Application Attacks", "https://espanol.verizon.com/business/resources/reports/dbir/2024/incident-classification-patterns-intro/basic-web-application-attacks"),
    "ms-mfa": ("Microsoft Research: How effective is MFA at deterring cyberattacks?", "https://www.microsoft.com/research/publication/how-effective-is-multifactor-authentication-at-deterring-cyberattacks/"),
    "cf-ddos": ("Cloudflare DDoS Threat Report H1 2026", "https://blog.cloudflare.com/ddos-threat-report-2026-h1/"),
    "tr-ddos": ("TechRepublic on Cloudflare's 2026 DDoS data and the 31.4 Tbps record", "https://www.techrepublic.com/article/news-cloudflare-ddos-attacks-1tbps-q2-2026/"),
    "imperva-ddos": ("Imperva: DDoS cost and downtime", "https://imperva.com/blog/?p=14924"),
    "neustar": ("Dark Reading on a Neustar survey: DDoS cost per hour", "https://www.darkreading.com/cyberattacks-data-breaches/what-a-ddos-can-cost"),
    "a10": ("A10 Networks: downtime cost (Gartner estimate)", "https://a10networks.com/blog/this-is-how-much-time-and-money-ddos-attack-will-cost-you"),
    "gl": ("Gordon-Loeb model (economics of security investment)", "https://en.wikipedia.org/wiki/Gordon%E2%80%93Loeb_model"),
    "gl-umd": ("University of Maryland Smith: Gordon-Loeb applied to AI-era threats", "https://www.rhsmith.umd.edu/research/smith-researchers-produce-new-framework-smarter-cybersecurity-budgeting"),
    "owasp-sqli": ("OWASP SQL Injection Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
    "owasp-qp": ("OWASP Query Parameterization Cheat Sheet (Top 10:2025 A05 Injection)", "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"),
    "h1-sqli": ("HackerOne on SQL injection impact (quoting OWASP)", "https://hackerone.com/blog/8-high-impact-bugs-and-how-hackerone-customers-avoided-breach-sql-injection"),
    "pib-dpdp": ("PIB (Govt. of India) DPDP Act penalty summary, Nov 2025", "https://static.pib.gov.in/WriteReadData/specificdocs/documents/2025/nov/doc20251117695301.pdf"),
    "certin": ("Baker McKenzie: CERT-In six-hour incident reporting", "https://resourcehub.bakermckenzie.com/en/resources/global-data-and-cyber-handbook/asia-pacific/india/topics/regulators-enforcement-priorities-and-penalties"),
    "aws-waf": ("AWS WAF pricing", "https://aws.amazon.com/waf/pricing"),
    "aws-waf-est": ("AWS: estimating WAF and Shield Advanced costs", "https://aws.amazon.com/blogs/aws-cloud-financial-management/how-to-estimate-your-aws-waf-and-aws-shield-advanced-costs/"),
    "aws-shield": ("AWS Shield pricing", "https://aws.amazon.com/shield/pricing"),
    "azure-ddos": ("Azure DDoS Protection pricing (India)", "https://azure.microsoft.com/en-in/pricing/details/ddos-protection/"),
    "gcp-armor": ("Google Cloud Armor pricing", "https://cloud.google.com/armor/pricing"),
    "cf-plans": ("Cloudflare plans", "https://developers.cloudflare.com/plans/"),
    "cf-free": ("Cloudflare: protect your website for free", "https://www.cloudflare.com/lp/pg-security-free/"),
    "cf-turnstile": ("Cloudflare Turnstile", "https://www.cloudflare.com/turnstile"),
    "captcha-cmp": ("Prosopo: hCaptcha vs Turnstile (incl. CAPTCHA farms)", "https://prosopo.io/blog/hcaptcha-vs-cloudflare-turnstile/"),
    "duo": ("Cisco Duo editions and pricing", "https://duo.com/editions-and-pricing"),
    "crs": ("OWASP ModSecurity project (free open-source WAF engine)", "https://owasp.org/projects/modsecurity"),
    "crs2": ("OWASP Core Rule Set: SQL injection, XSS and other common attacks", "https://owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project"),
    "bcs-waf": ("BCS: ModSecurity + CRS buys time while code is fixed", "https://bcs.org/content-hub/buying-time-against-attack"),
    "wazuh": ("Wazuh open-source SIEM/XDR", "https://wazuh.com/platform/"),
    "nist": ("NIST SP 800-63B-4: authenticators, rate limiting, blocklists", "https://pages.nist.gov/800-63-4/sp800-63b/authenticators"),
    "nginx": ("NGINX: fail2ban against brute-force logins", "https://www.nginx.com/?p=53511"),
    "vapt": ("TCSA: VAPT cost in India 2026", "https://www.tcsa.in/resources/vapt-cost-india-2026"),
    "gartner-waap": ("SDxCentral: Gartner names Akamai, Cloudflare, Imperva WAAP leaders (2022)", "https://www.sdxcentral.com/articles/news/gartner-names-akamai-cloudflare-imperva-cloud-waap-leaders/2022/09/"),
}


def inr_usd(usd: float) -> int:
    return int(round(usd * USD_INR, -2))


# ---- what each attack damages -------------------------------------------------------------------
ATTACK_INTEL = {
    "Brute force": {
        "severity": "High: leads to account takeover",
        "hampers": [
            "Customer and staff accounts taken over, so attackers act as real users (fraud, data theft, lateral movement).",
            "Genuine users locked out or slowed when lockouts and floods hit the login page.",
            "Credentials and personal data exposed. In Verizon's 2024 data, credentials were 71% of the data compromised in basic web application breaches.",
            "Legal exposure: CERT-In expects incident reports within 6 hours, and India's DPDP Act sets penalties up to ₹250 crore for failing to keep reasonable security safeguards.",
        ],
        "facts": [
            ("Credentials were involved in about 88% of basic web application attack breaches in Verizon's 2025 DBIR.", "dbir25"),
            ("Stolen credentials were the most common way in overall: 22% of breaches.", "dbir25b"),
            ("In the 2024 DBIR, stolen credentials drove 77% and brute force 21% of those breaches.", "dbir24"),
            ("MFA cut compromise risk by 99.22% overall and 98.56% when credentials had already leaked (Microsoft Research).", "ms-mfa"),
        ],
        "impact_note": "Default ₹4 lakh per successful incident covers investigation, forced resets, customer notification and fraud handling for a small to mid-size service. "
                       "IBM's average India breach of ₹22 crore is a much larger, multi-cause average, so raise this figure if your accounts hold sensitive data.",
        "sources": ["dbir25", "dbir25b", "dbir24", "ms-mfa", "certin", "pib-dpdp"],
    },
    "SQL injection": {
        "severity": "Critical: direct access to your database",
        "hampers": [
            "Database contents read: customer records, password hashes, payment and personal data.",
            "Data modified or deleted, which corrupts orders, balances and audit trails.",
            "Database administration actions run (even shutdown) and, in some setups, commands on the server's operating system.",
            "Heavy regulatory and reputation cost: DPDP penalties reach ₹250 crore for failing to maintain reasonable security safeguards.",
        ],
        "facts": [
            ("OWASP lists injection as A05 in its Top 10:2025; it held the top spot in older editions.", "owasp-qp"),
            ("Per OWASP, a successful SQL injection can read data, change data, run admin operations, recover files and sometimes run OS commands.", "h1-sqli"),
            ("The main defence is parameterized queries; escaping input is strongly discouraged as a primary defence.", "owasp-sqli"),
            ("India's average cost of a data breach reached ₹22 crore in 2025, and finding and containing one took about 263 days.", "ibm-in"),
        ],
        "impact_note": "Default ₹15 lakh per successful injection assumes a limited database leak at a small to mid-size business. "
                       "A leak of customer data can cost far more (IBM's India average is ₹22 crore), so adjust it to the sensitivity of your data.",
        "sources": ["owasp-qp", "owasp-sqli", "h1-sqli", "ibm-in", "pib-dpdp"],
    },
    "DDoS": {
        "severity": "High: the service goes unavailable",
        "hampers": [
            "Website, API or login unavailable, so orders and sign-ups stop while the flood lasts.",
            "Genuine customers see errors or timeouts, support load spikes and trust drops.",
            "Staff pulled into incident response; cloud bills can spike when autoscaling absorbs the flood.",
            "Floods are sometimes a smokescreen or paired with ransom demands.",
        ],
        "facts": [
            ("Cloudflare mitigated 23.2 million network-layer DDoS attacks in H1 2026, roughly 5,300 an hour.", "cf-ddos"),
            ("935 of them exceeded 1 Tbps; 96.62% stayed under 500 Mbps and 90.6% ended within 10 minutes, so small short floods are the norm.", "cf-ddos"),
            ("The largest recorded so far hit 31.4 Tbps (December 2025).", "tr-ddos"),
            ("Survey and vendor estimates of downtime cost range widely: $10,000 to $50,000 per hour of lost revenue (Neustar survey), about $100,000 per hour on average (Imperva), and Gartner's often-cited $5,600 per minute.", "imperva-ddos"),
        ],
        "impact_note": "Default ₹8 lakh per successful attack is roughly one hour of outage at the low end of the survey range above ($10,000 per hour). "
                       "A busy shop or API should raise it using its own revenue per hour.",
        "sources": ["cf-ddos", "tr-ddos", "imperva-ddos", "neustar", "a10"],
    },
}

# ---- the control catalogue ---------------------------------------------------------------------
# when: urgent = within 72 hours, soon = within 30 days, planned = within 90 days.  deploy_days is the realistic effort.
CONTROLS = [
    {"id": "C-RATE", "name": "Login rate limiting & lockout throttling", "category": "Identity & access", "cost_inr": 60_000,
     "effect": {"Brute force": 0.55, "DDoS": 0.15}, "when": "urgent", "deploy_days": 1,
     "action": "Limit attempts per IP and per account, add progressive delays and temporary lockout.",
     "buy": "Mostly configuration: free with nginx limit_req plus fail2ban, or a rate-based rule in a WAF/CDN. The cost is engineering time.",
     "steps": ["Add per-IP and per-account throttles on /login (for example 5 failures per 5 minutes triggers a delay or CAPTCHA).",
               "Use progressive delays or a CAPTCHA instead of hard permanent lockouts, so attackers cannot lock real users out.",
               "Alert on one account failing from many IPs: that is the distributed pattern this platform flags."],
     "options": [("nginx limit_req + fail2ban", "Free, open source. fail2ban bans IPs after repeated failed logins.", "nginx"),
                 ("AWS WAF rate-based rules", f"Rules cost $1 per month each plus $0.60 per million requests (about ₹{inr_usd(1):,} per rule per month).", "aws-waf"),
                 ("Cloudflare rate limiting", "Included in paid plans (Pro from about $20-25/month).", "cf-plans")],
     "evidence": "NIST SP 800-63B requires verifiers to rate-limit failed attempts per account and to screen passwords against blocklists.", "src": ["nist", "nginx"]},
    {"id": "C-MFA", "name": "Multi-factor authentication (MFA)", "category": "Identity & access", "cost_inr": 90_000,
     "effect": {"Brute force": 0.80}, "when": "urgent", "deploy_days": 3,
     "action": "Require MFA for all accounts, starting with admin and privileged users.",
     "buy": "Per-user MFA subscription. Budget covers about 25 users for a year at the Duo Essentials list price, or use free tiers for small teams.",
     "steps": ["Today: enforce MFA on every admin, database and cloud-console account.",
               "This week: require app-based MFA (authenticator or passkey) for all staff; offer it to customers.",
               "Prefer app or security-key MFA over SMS: Microsoft's study found app-based MFA outperformed SMS."],
     "options": [("Cisco Duo", f"Free for up to 10 users; Essentials $3, Advantage $6, Premier $9 per user per month (about ₹{inr_usd(3):,} per user per month for Essentials).", "duo"),
                 ("Microsoft Authenticator / Entra ID", "App-based MFA; Microsoft's own study found it outperforms SMS.", "ms-mfa"),
                 ("Passkeys / FIDO2 security keys", "One-time hardware cost per key; phishing-resistant.", "duo")],
     "evidence": "Microsoft Research: MFA reduced account-compromise risk by 99.22% overall and 98.56% for accounts with leaked credentials.", "src": ["ms-mfa", "duo"]},
    {"id": "C-BREACHPW", "name": "Breached-password screening", "category": "Identity & access", "cost_inr": 30_000,
     "effect": {"Brute force": 0.30}, "when": "soon", "deploy_days": 5,
     "action": "Reject passwords that appear in breach lists and common-password lists at sign-up and password change.",
     "buy": "A free breached-password API or list plus a few days of development.",
     "steps": ["Check new passwords against a breached-password list and reject matches.",
               "Force a reset for accounts whose credentials appear in a known breach.",
               "Drop arbitrary complexity rules in favour of length (NIST guidance)."],
     "options": [("Open breached-password lists / APIs", "Free to low cost; integrates at password change.", "nist")],
     "evidence": "NIST SP 800-63B-4 recommends blocklist screening and rate limiting over composition rules.", "src": ["nist"]},
    {"id": "C-BOT", "name": "CAPTCHA / bot challenge", "category": "Identity & access", "cost_inr": 50_000,
     "effect": {"Brute force": 0.35, "DDoS": 0.20}, "when": "soon", "deploy_days": 3,
     "action": "Challenge suspicious clients on login and expensive endpoints.",
     "buy": "Cloudflare Turnstile is free; the budget covers integration and tuning.",
     "steps": ["Show a challenge only to suspicious or high-volume clients on login, sign-up and search.",
               "Verify the token on the server, never only in the browser.",
               "Expect determined attackers to buy solved challenges: treat this as one layer, not a wall."],
     "options": [("Cloudflare Turnstile", "Free with no request cap on the Free plan (up to 20 widgets).", "cf-turnstile"),
                 ("hCaptcha", "Free basic tier; paid tiers roughly $99-139/month per comparison sites.", "captcha-cmp"),
                 ("Google reCAPTCHA", "Free tier cut to 10,000 assessments a month in 2025; paid beyond that.", "captcha-cmp")],
     "evidence": "Commercial CAPTCHA-solving farms can defeat both hCaptcha and Turnstile, so use CAPTCHA alongside rate limiting and MFA.", "src": ["captcha-cmp", "cf-turnstile"]},
    {"id": "C-WAF", "name": "Web application firewall (WAF)", "category": "Application protection", "cost_inr": 180_000,
     "effect": {"SQL injection": 0.70, "DDoS": 0.30, "Brute force": 0.10}, "when": "urgent", "deploy_days": 2,
     "action": "Enable managed SQL-injection rules and rate-based rules for floods, first in count mode, then in block mode.",
     "buy": "A managed WAF (cloud) or free ModSecurity + OWASP CRS. Budget covers licence plus a few weeks of rule tuning.",
     "steps": ["Turn on managed SQL-injection and common-attack rule groups in count mode for 24-48 hours to check false positives.",
               "Switch the rules to block mode and add rate-based rules for /login and other expensive endpoints.",
               "Keep fixing the code: a WAF buys time but cannot replace parameterized queries."],
     "options": [("AWS WAF", f"$5 per web ACL + $1 per rule + $0.60 per million requests; AWS's own example is about $87/month (₹{inr_usd(87):,}) for 100 million requests.", "aws-waf-est"),
                 ("Cloudflare WAF", "Free managed ruleset on the Free plan; Pro from about $20-25/month; OWASP-focused rules on paid plans.", "cf-free"),
                 ("OWASP ModSecurity + Core Rule Set", "Free and open source; covers SQL injection, XSS and other common attacks but needs tuning.", "crs"),
                 ("Akamai, Imperva, Cloudflare (enterprise WAAP)", "Named leaders in Gartner's 2022 cloud WAAP quadrant; quote-based pricing.", "gartner-waap")],
     "evidence": "OWASP CRS covers common attack classes including SQL injection; practitioners describe a WAF as buying time while attackers look for easier targets and code is fixed.", "src": ["crs2", "bcs-waf", "aws-waf"]},
    {"id": "C-CODE", "name": "Parameterized queries & input validation", "category": "Application protection", "cost_inr": 120_000,
     "effect": {"SQL injection": 0.60}, "when": "soon", "deploy_days": 21,
     "action": "Replace string-built SQL with parameterized queries; add allow-list validation and a code scan in CI.",
     "buy": "Developer time plus a free or paid code scanner in your pipeline.",
     "steps": ["Search the code for SQL built by string concatenation and replace each with a parameterized query or ORM method.",
               "Add allow-list validation for inputs that cannot be parameterized (sort columns, table names).",
               "Add a static-analysis check to CI so new injection bugs fail the build."],
     "options": [("OWASP cheat sheets (free)", "Prepared statements / parameterized queries are the primary defence.", "owasp-sqli"),
                 ("Static analysis in CI (e.g. Semgrep, CodeQL, Snyk)", "Free tiers exist for open-source and small teams.", "owasp-sqli")],
     "evidence": "OWASP names prepared statements with parameterized queries as the first-choice defence and strongly discourages escaping as the main defence.", "src": ["owasp-sqli", "owasp-qp"]},
    {"id": "C-DBPRIV", "name": "Least-privilege database accounts", "category": "Application protection", "cost_inr": 40_000,
     "effect": {"SQL injection": 0.30}, "when": "soon", "deploy_days": 7,
     "action": "Give the web app a database account that can only do what it must; separate read, write and admin roles.",
     "buy": "No product needed: configuration and review time.",
     "steps": ["Remove admin and file privileges from the application's database user.",
               "Use read-only accounts for reporting and read-heavy pages.",
               "Enable database audit logging so unusual queries are visible."],
     "options": [("Native database roles and grants", "Free in PostgreSQL, MySQL and SQL Server.", "owasp-sqli")],
     "evidence": "OWASP lists least privilege among the additional defences that limit what a successful injection can reach.", "src": ["owasp-sqli"]},
    {"id": "C-PENTEST", "name": "Web application penetration test (VAPT)", "category": "Assurance", "cost_inr": 120_000,
     "effect": {"SQL injection": 0.25, "Brute force": 0.10}, "when": "planned", "deploy_days": 30,
     "action": "Have the web app and login flow tested by a qualified tester, then fix and retest the findings.",
     "buy": "A one-off test from a CERT-In empanelled firm, typically ₹40,000 to ₹1.5 lakh for a typical single web app.",
     "steps": ["Scope the login, search, checkout and API endpoints.",
               "Fix critical and high findings first, then ask for a retest.",
               "Repeat after major releases."],
     "options": [("CERT-In empanelled Indian VAPT firms", "Web app VAPT about ₹40,000-₹1.5 lakh for a typical SaaS scope (2026 market ranges).", "vapt")],
     "evidence": "Testing finds the injection points and weak login flows that attackers would find first.", "src": ["vapt"]},
    {"id": "C-CDN", "name": "CDN with always-on DDoS protection", "category": "DDoS resilience", "cost_inr": 220_000,
     "effect": {"DDoS": 0.75}, "when": "urgent", "deploy_days": 2,
     "action": "Put the site behind a CDN/scrubbing service so floods are absorbed at the edge, and cache static content.",
     "buy": "A CDN plan with unmetered DDoS protection. The budget covers a Business-class plan for a year.",
     "steps": ["Point DNS at the CDN and lock the origin so it only accepts traffic from the CDN.",
               "Turn on rate-based and bot protections; cache static assets.",
               "Prepare a one-page runbook: who changes what when a flood starts."],
     "options": [("Cloudflare", "Unmetered DDoS protection is included on every plan including Free; Pro from about $20-25/month; Business about $200/month (older list price).", "cf-plans"),
                 ("AWS CloudFront + Shield Standard", "Shield Standard is automatic and free on AWS; CloudFront bills per use.", "aws-shield"),
                 ("Akamai / Imperva / Fastly", "Enterprise edge platforms; quote-based pricing.", "gartner-waap")],
     "evidence": "Most attacks are small and short (96.6% of network attacks stayed under 500 Mbps and 90.6% ended within 10 minutes), so always-on automatic protection matters more than a manual response.", "src": ["cf-ddos", "cf-plans"]},
    {"id": "C-SHIELD", "name": "Premium DDoS service with a response team", "category": "DDoS resilience", "cost_inr": inr_usd(36_000),
     "effect": {"DDoS": 0.45}, "when": "planned", "deploy_days": 14, "prerequisites": ["C-CDN"],
     "action": "Subscribe to an advanced DDoS tier that adds 24x7 response engineers and cost protection (best for revenue-critical services).",
     "buy": "AWS Shield Advanced is $3,000 per month on a one-year commitment plus data transfer; Azure DDoS IP Protection is $199 per month per public IP.",
     "steps": ["Only worth it when an hour of downtime costs more than the annual fee spread over expected incidents.",
               "Enrol your critical public endpoints and run a joint attack drill with the provider's response team.",
               "Ask about cost-protection credits for traffic spikes caused by an attack."],
     "options": [("AWS Shield Advanced", "$3,000/month + data transfer, 1-year commitment; includes a response team and cost protection.", "aws-shield"),
                 ("Azure DDoS IP Protection", "$199/month per protected public IP (Network Protection is a fixed monthly plan covering up to 100 IPs).", "azure-ddos"),
                 ("Google Cloud Armor Enterprise", "Pay-as-you-go or annual pricing; see Google's page.", "gcp-armor")],
     "evidence": "Adds expert help and spike-cost protection on top of an edge service; priced for organisations where an outage is expensive.", "src": ["aws-shield", "azure-ddos", "gcp-armor"]},
    {"id": "C-MON", "name": "Monitoring, alerting & detection", "category": "Detect & respond", "cost_inr": 100_000,
     "effect": {"Brute force": 0.15, "SQL injection": 0.15, "DDoS": 0.15}, "when": "soon", "deploy_days": 10,
     "action": "Alert on these detections around the clock and keep the logs needed to investigate.",
     "buy": "Free open-source SIEM (Wazuh) plus hosting and on-call time, or a managed detection service.",
     "steps": ["Send web, auth and database logs to one place and alert on this platform's detections.",
               "Define who is on call and how fast each severity is answered.",
               "Review the alert queue daily using this platform's review workflow."],
     "options": [("Wazuh (open source SIEM/XDR)", "Free software: intrusion detection, log analysis, file integrity. You pay for hosting and people; Wazuh Cloud is the paid managed option.", "wazuh"),
                 ("Managed detection and response services", "Quote-based; useful when you have no 24x7 staff.", "ibm-global")],
     "evidence": "IBM found breaches detected internally cost about $900,000 less than ones disclosed by attackers, and heavy AI/automation users saved $1.9 million and cut 80 days.", "src": ["ibm-detect", "ibm-global", "wazuh"]},
    {"id": "C-BLOCK", "name": "Automated IP-reputation blocking", "category": "Detect & respond", "cost_inr": 40_000,
     "effect": {"Brute force": 0.25, "DDoS": 0.15, "SQL injection": 0.10}, "when": "soon", "deploy_days": 5, "prerequisites": ["C-MON"],
     "action": "Feed confirmed attacker IPs from this platform into your firewall (needs monitoring in place).",
     "buy": "Small automation job against your firewall or WAF API; this platform exposes the blocklist endpoint.",
     "steps": ["Have your connector fetch GET /api/v1/telemetry/{id}/blocklist on a schedule.",
               "Apply entries as temporary blocks with an expiry, not permanent ones.",
               "Review blocked IPs weekly to avoid blocking shared or office addresses."],
     "options": [("fail2ban / firewall API / WAF IP sets", "Free to low cost; fail2ban bans IPs after repeated failures.", "nginx")],
     "evidence": "Blocking confirmed attacker sources removes repeat offenders cheaply, but shared IPs and botnets limit its reach.", "src": ["nginx"]},
    {"id": "C-IR", "name": "Incident-response plan & CERT-In reporting drill", "category": "Detect & respond", "cost_inr": 80_000,
     "effect": {"Brute force": 0.10, "SQL injection": 0.20, "DDoS": 0.10}, "when": "soon", "deploy_days": 14,
     "action": "Write and rehearse a response plan, including the 6-hour CERT-In report and customer notification.",
     "buy": "Internal time plus an optional external retainer; one tabletop exercise a year.",
     "steps": ["Name an incident lead and a communications lead; list the first 10 actions.",
               "Prepare the CERT-In report template (6-hour window) and a customer notice.",
               "Run a tabletop exercise and fix the gaps it shows."],
     "options": [("CERT-In reporting guidance", "Incidents must be reported within six hours of becoming aware.", "certin"),
                 ("External IR retainers", "Quote-based.", "ibm-global")],
     "evidence": "IBM links faster identification and containment to lower breach cost; Indian rules set a 6-hour reporting clock.", "src": ["ibm-global", "certin"]},
]

LAYER = {"C-CDN": "edge", "C-SHIELD": "edge", "C-WAF": "edge", "C-BLOCK": "edge",
         "C-RATE": "login", "C-MFA": "login", "C-BREACHPW": "login", "C-BOT": "login",
         "C-CODE": "app", "C-DBPRIV": "app", "C-PENTEST": "app", "C-MON": "response", "C-IR": "response"}
LAYERS = [("edge", "Network edge"), ("login", "Login & identity"), ("app", "App & database"), ("response", "Detect & respond")]
for _c in CONTROLS: _c["layer"] = LAYER[_c["id"]]
DEFAULT_CONTROLS = CONTROLS
BY_ID = {c["id"]: c for c in CONTROLS}
TIER_ORDER = {"urgent": 0, "soon": 1, "planned": 2}
TIER_LABEL = {"urgent": "Do now (within 72 hours)", "soon": "Within 30 days", "planned": "Within 90 days"}
CATEGORIES = ["Identity & access", "Application protection", "DDoS resilience", "Detect & respond", "Assurance"]


def _src(ids):
    return [{"id": i, "title": SOURCES[i][0], "url": SOURCES[i][1]} for i in ids if i in SOURCES]


def attack_intel() -> dict:
    out = {}
    for a, v in ATTACK_INTEL.items():
        out[a] = {"severity": v["severity"], "hampers": v["hampers"], "impact_note": v["impact_note"],
                  "facts": [{"text": t, "src": s, "url": SOURCES[s][1], "source": SOURCES[s][0]} for t, s in v["facts"]]}
    return out


def _residual(selected_ids, losses: dict) -> float:
    total = 0.0
    for a, d in losses.items():
        r = 1.0
        for i in selected_ids:
            r *= 1 - min(BY_ID[i]["effect"].get(a, 0), 0.999)
        total += d["expected_loss_inr"] * r
    return total


def action_plan(selected: list[dict], incident_counts: dict) -> list[dict]:
    """Order the funded controls by urgency. A control moves up to 'urgent' when it strongly (>= 50%) covers an attack that this server
    has actually seen incidents of, so a server already under brute force gets MFA and rate limiting first."""
    out = []
    for c in selected:
        tier, reasons = c.get("when", "soon"), []
        hit = [(a, e) for a, e in c["effect"].items() if incident_counts.get(a, 0) > 0 and e >= 0.5]
        if hit and tier != "urgent":
            tier = "urgent"
        for a, e in sorted(hit, key=lambda x: -x[1]):
            reasons.append(f"{incident_counts[a]} {a} incident(s) detected on this server; this control is modelled to cut that risk by about {round(e * 100)}%.")
        if not reasons:
            seen = [a for a in c["effect"] if incident_counts.get(a, 0) > 0]
            if seen: reasons.append("Covers " + ", ".join(seen) + ", which this server has seen.")
        out.append({"id": c["id"], "name": c["name"], "category": c["category"], "tier": tier, "when": TIER_LABEL[tier], "deploy_days": c["deploy_days"],
                    "cost_inr": c["cost_inr"], "layer": c["layer"], "action": c["action"], "why": reasons, "steps": c["steps"], "buy": c["buy"], "evidence": c["evidence"],
                    "options": [{"provider": p, "detail": d, "url": SOURCES[s][1]} for p, d, s in c["options"]], "sources": _src(c["src"])})
    out.sort(key=lambda x: (TIER_ORDER[x["tier"]], x["deploy_days"]))
    return out


def allocation(selected: list[dict], budget: float) -> dict:
    by = {k: {"category": k, "cost_inr": 0.0, "controls": []} for k in CATEGORIES}
    for c in selected:
        by[c["category"]]["cost_inr"] += c["cost_inr"]; by[c["category"]]["controls"].append(c["name"])
    spent = sum(v["cost_inr"] for v in by.values())
    rows = [{**v, "share": v["cost_inr"] / budget if budget else 0} for v in by.values() if v["controls"]]
    return {"rows": rows, "spent_inr": spent, "unspent_inr": max(0.0, budget - spent)}


def frontier_story(frontier: list[dict], baseline: float, controls: list[dict] | None = None) -> list[dict]:
    """Turn the efficient frontier into steps: what each extra rupee buys, and which control was added or swapped in."""
    names = {c["id"]: c["name"] for c in (controls or CONTROLS)}
    steps, prev_ids, prev = [], set(), {"cost_inr": 0.0, "loss_avoided_inr": 0.0}
    for p in frontier:
        ids = set(p["controls"])
        dc, dl = p["cost_inr"] - prev["cost_inr"], p["loss_avoided_inr"] - prev["loss_avoided_inr"]
        steps.append({"cost_inr": p["cost_inr"], "loss_avoided_inr": p["loss_avoided_inr"], "reduction_pct": p["loss_avoided_inr"] / baseline if baseline else 0,
                      "added": [names.get(i, i) for i in sorted(ids - prev_ids)], "dropped": [names.get(i, i) for i in sorted(prev_ids - ids)],
                      "marginal_return": (dl / dc) if dc > 0 else None})
        prev_ids, prev = ids, p
    return steps


def diminishing_point(steps: list[dict], share: float = 0.8):
    """Smallest spend that already delivers `share` of the best protection this catalogue can buy."""
    if not steps: return None
    top = steps[-1]["reduction_pct"]
    for s in steps:
        if s["reduction_pct"] >= share * top: return {"cost_inr": s["cost_inr"], "reduction_pct": s["reduction_pct"], "of_max_pct": top}
    return None


def gordon_loeb(baseline: float) -> dict:
    """Gordon-Loeb: for broad classes of breach-probability functions the optimal security spend is at most 1/e (about 37%) of the expected loss."""
    return {"cap_inr": baseline / math.e, "share": 1 / math.e, "baseline_loss_inr": baseline,
            "note": "Gordon-Loeb shows the economically optimal security spend does not exceed about 37% of the expected loss. Follow-up research argues that with a thinking attacker the optimum can be higher, so treat it as a sanity check, not a rule.",
            "sources": _src(["gl", "gl-umd"])}


def catalogue_with_marginal(selected_ids: list[str], losses: dict, controls: list[dict] | None = None) -> list[dict]:
    """Every control with its gist, published options, and what it would add on top of the current plan."""
    base = _residual(selected_ids, losses)
    out = []
    for c in (controls or CONTROLS):
        inside = c["id"] in selected_ids
        if inside:
            rest = [i for i in selected_ids if i != c["id"]]
            gain = _residual(rest, losses) - base
        else:
            gain = base - _residual(selected_ids + [c["id"]], losses)
        out.append({"id": c["id"], "name": c["name"], "category": c["category"], "cost_inr": c["cost_inr"], "layer": c["layer"], "prerequisites": c.get("prerequisites", []), "funded": inside, "effect": c["effect"],
                    "gain_inr": gain, "return_per_rupee": gain / c["cost_inr"] if c["cost_inr"] else None, "when": TIER_LABEL[c.get("when", "soon")],
                    "action": c["action"], "buy": c["buy"], "evidence": c["evidence"],
                    "options": [{"provider": p, "detail": d, "url": SOURCES[s][1]} for p, d, s in c["options"]], "sources": _src(c["src"])})
    return out


def all_sources(ids=None) -> list[dict]:
    ids = ids or list(SOURCES)
    return _src(ids)
