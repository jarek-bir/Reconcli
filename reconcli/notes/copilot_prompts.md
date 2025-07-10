# ✨ GitHub Copilot Prompts for `aicli.py`

## 🔍 Vulnerability Scanning
> "Refactor the --vuln-scan logic to support streaming large input files line by line."

> "Add support for scan profiles (preset dictionaries with recommended scan-type + persona)."

## 🧠 AI Interaction Improvements
> "Implement retry logic for OpenAI API in case of temporary failure or 429 errors."

> "Refactor interactive mode to support token-based stop sequences."

> "Add history preview for --load-chat before entering interactive mode."

## 📄 Report Generation
> "Automatically include CVSS scores in vuln reports based on payload impact."

> "Generate HTML version of Markdown reports with embedded payloads and color-coded risks."

## 🔗 ReconCLI Integration
> "When --integration is used, merge findings from `urlcli` JSON and pass context to AI."

> "Detect when `urlcli_output.json` is empty or malformed and alert the user before scan."

## 🤖 Personas & Techniques
> "Add new persona 'compliance_officer' focused on audit language and regulatory mapping."

> "Include a JSON mapping of each attack-flow to recommended payloads."

## 🧪 Prompt Mode Templates
> "Build a library of JSON-formatted prompt templates and auto-fill them based on --prompt-mode."

> "If --prompt-mode and --save-chat are used together, embed prompt template ID in chat name."

## 🧼 UX Enhancements
> "Display scan progress bar for --vuln-scan using tqdm."

> "Support --dry-run to validate inputs without executing any AI calls."

> "Colorize console output based on risk level (e.g., red = critical, yellow = medium)."
