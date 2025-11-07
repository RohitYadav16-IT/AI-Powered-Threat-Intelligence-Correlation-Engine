# AI-Powered-Threat-Intelligence-Correlation-Engine

# 🛡️ Unified Threat Reporter (SentinelScope)

## Project Overview

The **AI-Powered-Threat-Intelligence-Correlation-Engine** is a Streamlit web application designed to simplify cybersecurity threat analysis. It integrates data from major threat intelligence platforms (VirusTotal and AbuseIPDB) and leverages the Google Gemini API to translate complex, technical security reports into concise, human-readable summaries.

### 💡 Key Features

* **Multi-Source Scanning:** Analyze uploaded **files**, **URLs/Domains**, and **IP Addresses**.
* **Dual-API Intelligence (IPs):** Correlates data from **VirusTotal** (file/URL/IP reputation) and **AbuseIPDB** (IP abuse scoring).
* **AI Interpretation:** Uses the **Gemini 2.5 Flash** model to provide a **Threat Assessment** ([CLEAN], [MEDIUM CONCERN], etc.) and simple, actionable explanations for non-technical users.
* **Secure:** Configured to read all API keys securely from environment variables.
* **Data Export:** Allows users to download the raw JSON responses from all APIs as a CSV file for auditing.

---

## 🛠️ Technology Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Frontend/App** | Streamlit | Provides the interactive web UI and hosting framework. |
| **AI Interpreter** | Google Gemini API (`gemini-2.5-flash`) | Explains combined threat data in natural language. |
| **Threat Intel 1** | VirusTotal Public API | Provides reputation for files, URLs, and IPs. |
| **Threat Intel 2** | AbuseIPDB API (Free Tier) | Provides specialized abuse confidence score for IPs. |
| **Data Processing** | Python, `requests`, `pandas` | Handles API communication, JSON parsing, and CSV export. |

---

## 🚀 Getting Started

### Prerequisites

1.  **Python:** Python 3.9+ installed.
2.  **GitHub:** A GitHub account (required for Streamlit Community Cloud deployment).
3.  **API Keys (NEWLY GENERATED):**
    * **`GEMINI_API_KEY`** (from Google AI Studio)
    * **`VIRUSTOTAL_API_KEY`** (from VirusTotal)
    * **`ABUSEIPDB_API_KEY`** (from AbuseIPDB)

### Local Setup

1.  **Clone the Repository:**
    ```bash
    git clone [YOUR_REPO_URL]
    cd your-github-repo-name
    ```

2.  **Create and Activate Virtual Environment:**
    ```bash
    python -m venv env
    .\env\Scripts\Activate  # On Windows PowerShell
    # source env/bin/activate # On Linux/macOS
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(If you haven't created it yet, a basic `requirements.txt` should contain: `streamlit`, `requests`, `google-genai`, `pandas`)*

4.  **Run the Application:**
    ```bash
    streamlit run security_analyzer_app.py
    ```

---

## ☁️ Deployment to Streamlit Community Cloud

The application is specifically structured for easy, secure deployment on Streamlit's free platform.

### Crucial Security Step: Secrets Management

**Do not push your API keys to GitHub.** Follow these steps to deploy securely:

1.  **Push Code:** Ensure all your code (`security_analyzer_app.py`, `requirements.txt`) is pushed to your GitHub repository.
2.  **Go to Streamlit Cloud:** Log in with your GitHub account.
3.  **New App:** Click **"New app"** and point it to your repository, branch, and the main file (`security_analyzer_app.py`).
4.  **Add Secrets:** Click **"Advanced settings"** and, in the secrets text area, paste your configuration in TOML format:

    ```toml
    # Paste this entire block into the Streamlit Secrets text area
    GEMINI_API_KEY = "YOUR_KEY_HERE"
    VIRUSTOTAL_API_KEY = "YOUR_KEY_HERE"
    ABUSEIPDB_API_KEY = "YOUR_KEY_HERE"
    ```
    
5.  **Deploy:** Click Deploy. The app will launch and securely access your keys via `os.environ.get()`.

---

## 🤝 Contribution

Feel free to fork this project, improve the AI prompts for better interpretation, or add more API integrations (e.g., Shodan, Censys). Pull requests are welcome!


