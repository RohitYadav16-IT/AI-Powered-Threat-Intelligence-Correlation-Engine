🛡️ Unified Threat Reporter: AI-Powered Threat Intelligence Correlation Engine

Project Overview

The Unified Threat Reporter is a powerful Streamlit web application designed to bridge the gap between complex raw cybersecurity data and actionable, non-technical insights. It functions as a multi-source threat intelligence correlation engine, automatically analyzing potential threats across various indicators of compromise (IOCs).

The core value of the application lies in its ability to consume high-fidelity threat data from industry-leading APIs and synthesize that information into simple, clear reports using a Large Language Model (LLM).

🎯 Core Functionality

The application provides three distinct scanning modes for comprehensive coverage:

File Scan: Submits executable and document files to VirusTotal for deep analysis by numerous antivirus engines and security tools.

URL/Domain Scan: Queries VirusTotal for reputation, malicious flag counts, and categorization of web addresses and domains.

IP Reputation Check: Performs a dual-source check, correlating general threat data from VirusTotal with specific abuse and confidence scores from AbuseIPDB.

🧠 AI Interpretation Layer

The project employs the Google Gemini 2.5 Flash model as a crucial final step in the analysis chain. After aggregating raw JSON data from all security sources, the LLM performs the following tasks:

Threat Assessment: Generates an immediate, easy-to-understand threat rating (e.g., [CLEAN], [MEDIUM CONCERN], [SEVERE THREAT]).

Simple Explanation: Translates technical metrics (like "Malicious Detections" and "Abuse Confidence Score") into plain language.

Actionable Advice: Provides clear, non-technical instructions to the end-user (e.g., "Block this IP immediately" or "File is safe to open").

⚙️ Technology Stack

Component

Technology

Primary Role

Interface

Python Streamlit

Interactive web user interface and application framework.

AI/NLP

Google Gemini API (gemini-2.5-flash)

Natural language generation and security data interpretation.

Data Sources

VirusTotal API

File, URL, and general IP reputation data.

Data Sources

AbuseIPDB API

Specialized IP abuse reporting and confidence scoring.

Utilities

Python (requests, pandas, python-dotenv)

API communication, data parsing, flattening, and CSV export.
