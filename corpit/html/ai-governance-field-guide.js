/* Field guidance from the reviewed workbook Field Guide tab; explanations only. */
window.AIGovernanceFieldGuide={
  "dept": [
    "Department",
    "Owning department."
  ],
  "name": [
    "Name of AI/ML use or system",
    "One row per use case, not per tool. A tool used for three purposes is three rows."
  ],
  "what": [
    "What it does / business process it supports",
    "Plain language. Include who or what consumes the output."
  ],
  "cat": [
    "Category",
    "Built in-house, AI feature embedded in a SaaS product (including features a vendor switched on in an already-approved product), standalone AI tool, or AI used in dev tooling. Allowed answers: Built in-house (API/agent/automation/app), Embedded AI feature in SaaS, Standalone AI tool/platform, Dev tooling (coding assistant / CI-CD / IDE), Other."
  ],
  "status": [
    "Status",
    "Production, Pilot / POC, In development, or Retired. Allowed answers: Production, Pilot / POC, In development, Retired."
  ],
  "golive": [
    "Go-live date (actual or planned)",
    "Enter a date (YYYY-MM-DD). Leave blank if not yet scheduled."
  ],
  "bowner": [
    "Business owner",
    "Name."
  ],
  "towner": [
    "Technical owner / custodian",
    "Name."
  ],
  "vendor": [
    "AI vendor / platform",
    "e.g. AWS Bedrock, OpenAI, Microsoft, in-house."
  ],
  "model": [
    "Model and version",
    "e.g. Claude Sonnet 4.6. Enter 'Unknown' for embedded features where the vendor does not disclose it."
  ],
  "access": [
    "Access method",
    "How the system calls or uses the AI. Allowed answers: API, MCP, Embedded SaaS feature, SDK / library, Browser or desktop app, In-house hosted model, Other."
  ],
  "agentic": [
    "Agentic? (multi-step actions without per-step human approval)",
    "Yes if the AI is given a goal and carries out multiple steps or tool calls autonomously. This is different from the human oversight field below. Allowed answers: Yes, No, Unsure."
  ],
  "agtools": [
    "If agentic: tools and permissions it holds",
    "What can it read, write, send, or execute? Which accounts or keys does it use?"
  ],
  "host": [
    "Hosting / runtime",
    "e.g. AWS, Azure / O365, vendor SaaS."
  ],
  "systems": [
    "Systems and data sources connected",
    "List each system, repository, or data store it reads from or writes to."
  ],
  "sso": [
    "Okta / SSO used?",
    "Yes, No, Partial, or N/A (no human login). Allowed answers: Yes, No, Partial, N/A."
  ],
  "keys": [
    "Service account / API key management",
    "Where keys are stored (e.g. secrets manager), who can access them, and rotation approach."
  ],
  "instance": [
    "Instance type",
    "Private / enterprise (company-controlled tenant) or Public / consumer. Allowed answers: Private / enterprise, Public / consumer, Unsure."
  ],
  "npi": [
    "Processes NPI?",
    "Nonpublic personal information. Allowed answers: Yes, No, Unsure."
  ],
  "pii": [
    "Processes other PII?",
    "Prompts, training, or output. Allowed answers: Yes, No, Unsure."
  ],
  "ip": [
    "Processes company IP / confidential?",
    "Includes source code, contracts, internal strategy. Allowed answers: Yes, No, Unsure."
  ],
  "client": [
    "Processes client data (incl. loan-level data, client O365 content)?",
    "Client data triggers client-approval and audit considerations. Allowed answers: Yes, No, Unsure."
  ],
  "clients": [
    "If client data: which client(s)?",
    "Needed to map to client contract and audit requirements."
  ],
  "consumer": [
    "Processes consumer (SmartSale) data?",
    "Seller / homeowner data in the SmartSale business. Allowed answers: Yes, No, Unsure."
  ],
  "third": [
    "Data sent to or retained by a third party?",
    "Includes the AI vendor and any subprocessors. Allowed answers: Yes, No, Unsure."
  ],
  "training": [
    "Vendor training / retention status",
    "Is the vendor prohibited from training on our data, and is retention/deletion defined? Allowed answers: Contractually prohibited, Opt-out configured, Not prohibited, Unknown."
  ],
  "siem": [
    "Logs sent to SIEM?",
    "Yes, No, Partial, or Unknown. Allowed answers: Yes, No, Partial, Unknown."
  ],
  "mon": [
    "Other monitoring",
    "Any other logging or monitoring tool, and whether prompts and outputs are retained."
  ],
  "aud": [
    "Users / audience",
    "Who uses it or receives its output. Allowed answers: Internal staff, Clients / customers, Buyers / sellers / consumers, Automated - no users, Mixed."
  ],
  "ext": [
    "Does any output reach clients, buyers, sellers, or consumers?",
    "Directly or after light editing. Allowed answers: Yes, No, Unsure."
  ],
  "oversight": [
    "Human oversight",
    "Is a person reviewing before anything happens, or do outputs drive actions automatically? Allowed answers: Human reviews before action, Human reviews after action, Fully automated, N/A."
  ],
  "contractors": [
    "Contractors / vendors involved in build or operation",
    "Names, or 'None'."
  ],
  "oss": [
    "Restrictive open-source components used or trained on?",
    "Yes / No / Unsure. If unsure, say so rather than guessing. Allowed answers: Yes, No, Unsure."
  ],
  "intake": [
    "Intake form submitted?",
    "Whether an AI Use Case Intake Form has been submitted for this use case. Allowed answers: Yes, No, Unsure."
  ],
  "notes": [
    "Notes / open issues",
    "Anything the reviewer should know."
  ],
  "window": [
    "Reported during disclosure window?",
    "InfoSec use. Applies only if the window is authorized. Allowed answers: Yes, No, Unsure. Completed by InfoSec / Legal."
  ],
  "tier": [
    "Risk tier (InfoSec / Legal)",
    "InfoSec and Legal set this after review. Allowed answers: Low, Medium, High. Completed by InfoSec / Legal."
  ],
  "capprov": [
    "Client approval required?",
    "InfoSec and Legal. Allowed answers: Yes, No, TBD. Completed by InfoSec / Legal."
  ],
  "revby": [
    "Reviewed by",
    "InfoSec use. Completed by InfoSec / Legal."
  ],
  "revdate": [
    "Review date",
    "InfoSec use. Date of most recent review. Completed by InfoSec / Legal."
  ],
  "followup": [
    "InfoSec follow-up / gaps",
    "InfoSec use. Completed by InfoSec / Legal."
  ]
};
