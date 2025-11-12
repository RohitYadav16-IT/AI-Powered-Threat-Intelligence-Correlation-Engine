## 🛡️ AI-Powered Threat Intelligence Correlation Engine

This project is a proof-of-concept web application built with **Streamlit** that correlates and simplifies threat intelligence data from multiple security platforms. It transforms complex security metrics (from VirusTotal and AbuseIPDB) into simple, actionable advice using **Google Gemini**.

The primary goal is to provide non-security professionals with instant, easy-to-understand threat assessments for files, URLs, domains, and IP addresses.

### ✨ Key Features

* **Multi-Vector Analysis:** Scan and analyze four key threat vectors:
    * **File Analysis:** Upload file scanning and reputation lookups.
    * **Hash Analysis:** Check file hashes (SHA256, MD5, SHA1) against existing databases.
    * **URL/Domain Scan:** Assess web resource safety using VirusTotal.
    * **IP Reputation:** Correlate data from **VirusTotal** and **AbuseIPDB** for a comprehensive score.
* **AI Interpretation:** Uses the **Google Gemini 2.5 Flash** model to generate a real-time, non-technical summary, threat assessment, and actionable advice.
* **Performance Optimized:** File analysis includes a critical cache-check strategy by looking up the SHA256 hash before uploading the file, significantly improving performance for known files.
* **Transparent Status Tracking:** Utilizes Streamlit's `st.status` container to communicate multi-stage process progress, managing perceived latency during long-running tasks like file polling and complex, sequential tasks.

### 💻 Technology Stack

| Category | Component | Role |
| :--- | :--- | :--- |
| **Frontend/Framework** | Streamlit | Rapid development and interactive user interface. |
| **Generative AI** | Google Gemini 2.5 Flash | Interpretation and summarization of raw security data. |
| **Threat Intelligence** | VirusTotal (VT) | Core reputation data for files, URLs, domains, and IPs. |
| **Threat Intelligence** | AbuseIPDB (AIPDB) | Supplemental IP abuse confidence scoring. |

*(Dependencies listed in `requirements.txt` include `streamlit==1.39.0`, `numpy==1.26.4`, `pandas==2.2.2`, and `scikit-learn==1.5.2`)*

### 🚀 Getting Started

#### Prerequisites

You will need API keys for the following services:

1.  **Google Gemini** (for AI explanations)
2.  **VirusTotal** (for file, URL, and IP reputation)
3.  **AbuseIPDB** (for IP abuse confidence scoring)

#### Installation and Running

1.  **Clone the repository:**
    ```bash
    git clone [Your-Repo-Link]
    cd [Your-Repo-Name]
    ```

2.  **Install dependencies:**
    The required packages are listed in `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```

3.  **Set Environment Variables (Critical Security Step)**

    The application code currently contains a **CRITICAL** vulnerability where API keys are hardcoded. **Before running or deploying**, you must set up a secure secrets management system.

    **Recommendation:** Remove all hardcoded API keys and use environment variables (or Streamlit Secrets for deployment) to load the credentials at runtime.

    Create a file named `.env` or set the variables in your terminal:
    ```bash
    export GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
    export VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
    export ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_API_KEY"
    ```

4.  **Run the application:**
    ```bash
    streamlit run security_analyzer_app.py
    ```

### 🚨 Security Warning (MUST READ)

The included `security_analyzer_app.py` file is a **proof-of-concept only** and contains a **Severe Vulnerability**:

* **Vulnerability:** All three external API keys are hardcoded as plain strings at the top of the main script.
* **Risk:** This is a **CRITICAL** risk, as it leads to the public exposure of these keys, allowing unauthorized usage (financial liability) and key revocation by the vendor (service interruption).
* **Remediation
