import streamlit as st
import requests
import os
import time
import pandas as pd
import hashlib
import google.genai as genai 

# === API KEYS & CONFIGURATION ===
# IMPORTANT: Keys are read from environment variables.
GEMINI_API_KEY = "AIzaSyD2X4CLS8X-cpJugfV8NIiWzkadrPuWVGQ"
VIRUSTOTAL_API_KEY = "a2d225b2f50fb6416edbca75a99b1907208e81dcf1f3eb7e87b48d5d6eeaa230"
ABUSEIPDB_API_KEY = "53a1858bb3911cf8ca3294dd1133b4888804d10cfbec8169813ba791231fd86790bfffc0f14c9ad2"

# Check for required keys and stop execution if missing
if not all([GEMINI_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY]):
    st.error("🚨 Configuration Error: Missing one or more API keys.")
    st.markdown("""
        Please set the following environment variables (locally or in Streamlit Secrets):
        * `GEMINI_API_KEY`
        * `VIRUSTOTAL_API_KEY`
        * `ABUSEIPDB_API_KEY`
    """)
    st.stop()

try:
    gemini_client = genai.Client(api_key=GEMINI_API_KEY)
except Exception as e:
    st.error(f"Failed to initialize Gemini Client. Check your API key. Error: {e}")
    st.stop()


# === API ENDPOINTS ===
VT_FILE_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_URL = "https://www.virustotal.com/api/v3/urls"
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

# Polling parameters for file uploads (Increased for Free API)
POLL_INTERVAL_SECONDS = 10 
POLL_TIMEOUT_SECONDS = 300 

# === Streamlit Setup ===
st.set_page_config(page_title="🛡️ Security Analyzer", page_icon="🧠", layout="centered")
st.title("🛡️ AI-Powered Threat Intelligence Correlation Engine ")
st.markdown("""
Analyze **files**, **URLs/Domains**, and **IP addresses** using VirusTotal and AbuseIPDB, 
with AI explanations powered by **Google Gemini**.
""")

# === Helper Functions ===

def generate_ai_explanation(structured_data, analysis_type, status_tracker=None):
    """Use Google Gemini for AI explanations with a strong system prompt."""
    try:
        if status_tracker:
            status_tracker.update(label="🧠 **Step 3/3:** Invoking Gemini AI for Interpretation...", state="running")
            
        model_name = "gemini-2.5-flash"
        
        prompt = f"""
        You are an AI-powered Threat Intelligence Analyst. Your task is to analyze the following {analysis_type} scan data and explain it in a simple, non-technical, and actionable summary for an end-user.
        
        **Instructions:**
        1. **Assess Threat Level:** Start with an assessment: **[CLEAN]**, **[LOW CONCERN]**, **[MEDIUM CONCERN]**, or **[SEVERE THREAT]**.
        2. **Explain Metrics:** Define what the 'Malicious' counts (VT) and 'Confidence Scores' (AbuseIPDB) mean.
        3. **Actionable Advice:** Finish with one simple instruction (e.g., "Do not open this file," or "This IP is safe to block.").

        **RAW SCAN DATA:**
        {structured_data}
        """
        
        response = gemini_client.models.generate_content(
            model=model_name,
            contents=prompt
        )
        
        if status_tracker:
             status_tracker.update(label="✅ **Analysis Complete:** Results are ready.", state="complete")
             
        return response.text.strip() if response.text else "⚠️ No AI explanation generated."
    except Exception as e:
        if status_tracker:
            status_tracker.update(label="❌ **AI Step Failed:** Check Gemini API.", state="error")
        # Include detailed error for debugging
        return f"⚠️ Gemini API Error. Details: {e}"

def convert_to_csv(data: dict) -> bytes:
    """Converts a dictionary (or nested dictionaries) into a CSV format string."""
    df = pd.json_normalize(data, sep='_')
    return df.to_csv(index=False).encode('utf-8')

# Function to check for report via hash (faster if file is known)
def check_virustotal_hash(file_hash):
    """Check VirusTotal for an existing file report using its hash."""
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        # The endpoint for retrieving a file report by hash is /files/{hash}
        url = f"{VT_FILE_URL}/{file_hash}" 
        
        resp = requests.get(url, headers=headers)
        raw_data = resp.json()
        
        if resp.status_code == 200:
            # File is already known and scanned
            data = raw_data["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            summary_data = {
                "source": "VirusTotal (Hash Lookup)",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "status": "completed (cached)"
            }
            return summary_data, raw_data, True # Found
        
        # If status is 404 or other non-200, it's not known or not completed
        return {"error": "Report not found or not complete."}, raw_data, False
        
    except Exception as e:
        return {"error": str(e)}, {"raw_error": str(e)}, False

def check_abuseipdb(ip):
    """Query AbuseIPDB for IP reputation."""
    try:
        headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        r = requests.get(ABUSEIPDB_API_URL, headers=headers, params=params)
        
        raw_data = r.json()
        
        if r.status_code == 200:
            data = raw_data.get('data', {})
            summary_data = {
                "source": "AbuseIPDB",
                "ipAddress": ip,
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "countryCode": data.get("countryCode", "N/A"),
                "lastReportedAt": data.get("lastReportedAt", "N/A"),
            }
            return summary_data, raw_data
        else:
            error_data = {"error": f"AbuseIPDB API Error: {r.status_code} - {r.text}"}
            return error_data, raw_data
    except Exception as e:
        error_data = {"error": str(e)}
        return error_data, {"raw_error": str(e)}

def check_virustotal_url_or_domain(input_value):
    """Check URL or domain reputation using VirusTotal."""
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        if input_value.startswith("http"):
            import base64
            url_id = base64.urlsafe_b64encode(input_value.encode()).decode().strip("=")
            url = f"{VT_URL_URL}/{url_id}"
        else:
            url = f"{VT_DOMAIN_URL}{input_value}"

        resp = requests.get(url, headers=headers)
        raw_data = resp.json()
        
        if resp.status_code == 200:
            data = raw_data["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            summary_data = {
                "source": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": data.get("reputation", 0),
                "type": "URL/Domain"
            }
            return summary_data, raw_data
        else:
            error_data = {"error": f"VirusTotal API Error {resp.status_code}: {resp.text}"}
            return error_data, raw_data
    except Exception as e:
        error_data = {"error": str(e)}
        return error_data, {"raw_error": str(e)}

def check_virustotal_ip(ip):
    """Check IP reputation using the dedicated VirusTotal IP endpoint."""
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url = f"{VT_IP_URL}{ip}"
        
        resp = requests.get(url, headers=headers)
        raw_data = resp.json()
        
        if resp.status_code == 200:
            data = raw_data["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            summary_data = {
                "source": "VirusTotal (IP)",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": data.get("reputation", 0),
                "country": data.get("country", "N/A")
            }
            return summary_data, raw_data
        else:
            error_data = {"error": f"VirusTotal IP API Error {resp.status_code}: {resp.text}"}
            return error_data, raw_data
    except Exception as e:
        error_data = {"error": str(e)}
        return error_data, {"raw_error": str(e)}

def analyze_uploaded_file(file):
    """Upload file to VirusTotal and poll for final analysis."""
    try:
        file_bytes = file.getvalue()
        # 0. Calculate Hash
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        
        # 1. Check if file is already known (Fast Check)
        status_placeholder = st.empty()
        status_placeholder.info(f"Checking cache for existing report (Hash: {sha256_hash[:10]}...).")
        
        summary_data, raw_data, found_cached = check_virustotal_hash(sha256_hash)
        
        if found_cached:
            status_placeholder.success("✅ **Cache Hit!** Report found instantly.")
            return summary_data, raw_data

        # --- If not found, proceed to slow upload/polling ---
        
        status_placeholder.info("Report not found in cache. Uploading file for scan (low priority, might take up to 5 minutes)...")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        files = {"file": (file.name, file_bytes)}
        
        # 2. Upload File
        upload_resp = requests.post(VT_FILE_URL, headers=headers, files=files)
        upload_raw_data = upload_resp.json()
        
        if upload_resp.status_code not in [200, 201]:
            error_data = {"error": f"VirusTotal upload failed: {upload_resp.status_code} - {upload_resp.text}"}
            return error_data, upload_raw_data
        
        analysis_id = upload_resp.json()["data"]["id"]
        result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        # 3. Polling Loop
        poll_placeholder = st.empty()
        final_raw_data = upload_raw_data
        
        for i in range(POLL_TIMEOUT_SECONDS // POLL_INTERVAL_SECONDS):
            time.sleep(POLL_INTERVAL_SECONDS)
            poll_placeholder.info(f"Analysis status: Still analyzing... (Attempt {i+1} of {POLL_TIMEOUT_SECONDS // POLL_INTERVAL_SECONDS})")
            
            analysis_resp = requests.get(result_url, headers=headers)
            final_raw_data = analysis_resp.json()
            
            if analysis_resp.status_code != 200:
                error_data = {"error": f"VirusTotal analysis fetch error: {analysis_resp.status_code}"}
                return error_data, final_raw_data
            
            data = final_raw_data["data"]["attributes"]
            status = data.get("status", "queued")
            
            if status == "completed":
                poll_placeholder.success("✅ Analysis completed!")
                stats = data.get("stats", {})
                summary_data = {
                    "source": "VirusTotal (File)",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "status": "completed"
                }
                return summary_data, final_raw_data
            
        poll_placeholder.error(f"Analysis timed out after {POLL_TIMEOUT_SECONDS} seconds. Status was still '{status}' (Free API may have low priority).")
        error_data = {"error": f"Analysis timed out."}
        return error_data, final_raw_data

    except Exception as e:
        error_data = {"error": str(e)}
        return error_data, {"raw_error": str(e)}

def display_summary(results, type):
    """Displays key metrics in a clean markdown table."""
    st.markdown("### 📊 Key Metrics Summary")
    if type == "IP":
        vt = results['vt_data']
        abuse = results['abuse_data']
        
        st.markdown(f"""
        | Metric | VirusTotal (VT) | AbuseIPDB (AIPDB) |
        | :--- | :--- | :--- |
        | **Malicious/Confidence Score** | {vt.get('malicious', 'N/A')} engines reported malicious | {abuse.get('abuseConfidenceScore', 'N/A')}% confidence score |
        | Suspicious/Total Reports | {vt.get('suspicious', 'N/A')} engines reported suspicious | {abuse.get('totalReports', 'N/A')} total reports |
        | Country Origin | {vt.get('country', 'N/A')} | {abuse.get('countryCode', 'N/A')} |
        """)
    elif type in ["URL", "Domain", "File"]:
        vt = results['vt_data']
        st.markdown(f"""
        | Metric | Value |
        | :--- | :--- |
        | **Malicious Detections** | **{vt.get('malicious', 'N/A')}** |
        | Suspicious Detections | {vt.get('suspicious', 'N/A')} |
        | Harmless Detections | {vt.get('harmless', 'N/A')} |
        """)


# === Streamlit UI Tabs ===
tab1, tab2, tab3 = st.tabs(["📁 File Scan", "🌐 URL / Domain Scan", "📡 IP Reputation"])

# --- FILE SCAN ---
with tab1:
    st.subheader("📁 Upload a File for Analysis (VirusTotal)")
    # Removed the st.info() line about the timeout.
    uploaded_file = st.file_uploader("Choose a file", type=None)
    if uploaded_file and st.button("🚀 Scan File"):
        # The main status container is now used only for the AI step
        with st.status(label="Starting File Analysis...", expanded=True) as status:
            # Analyze function now handles hash check/upload/polling internally with its own placeholders
            status.update(label="1/3: Running VirusTotal check/upload...", state="running") 
            summary_data, raw_data = analyze_uploaded_file(uploaded_file)
            
            if "error" in summary_data:
                status.update(label="❌ File Scan Failed!", state="error")
                st.error(summary_data["error"])
            else:
                status.update(label="2/3: Scan complete. Processing results.", state="running")
                
                # Summary and Explanation
                display_summary({'vt_data': summary_data}, "File")
                # Step 3: AI Interpretation (Uses status_tracker)
                ai_text = generate_ai_explanation(summary_data, "file", status_tracker=status)
                
                st.success(f"✅ File analysis complete: {summary_data.get('malicious', 'N/A')} malicious detections.")
                st.markdown("### 🧠 Gemini AI Explanation")
                st.write(ai_text)
                
                st.markdown("---")
                st.markdown("#### 📜 Raw VirusTotal Data")
                st.json(raw_data)
                
                # Download Button
                csv_data = convert_to_csv(raw_data)
                st.download_button(
                    label="⬇️ Download Raw Data as CSV",
                    data=csv_data,
                    file_name=f"{uploaded_file.name}_VT_scan.csv",
                    mime="text/csv",
                )
                
                
# --- URL / DOMAIN SCAN ---
with tab2:
    st.subheader("🌐 Analyze URL or Domain (VirusTotal)")
    url_input = st.text_input("Enter a URL or Domain", placeholder="https://example.com or example.com")
    if url_input and st.button("🔍 Analyze URL/Domain"):
        with st.status(label="Starting URL/Domain Analysis...", expanded=True) as status:
            status.update(label="1/2: Querying VirusTotal for domain/URL reputation...", state="running")
            summary_data, raw_data = check_virustotal_url_or_domain(url_input)
            
            if "error" in summary_data:
                status.update(label="❌ URL/Domain Scan Failed!", state="error")
                st.error(summary_data["error"])
            else:
                status.update(label="2/2: Scan complete. Invoking AI Interpretation...", state="running")
                
                # Summary and Explanation
                display_summary({'vt_data': summary_data}, "URL/Domain")
                ai_prompt = generate_ai_explanation(summary_data, "URL/Domain", status_tracker=status)
                
                st.success(f"✅ Analysis completed: {summary_data['malicious']} malicious detections.")
                st.markdown("### 🧠 Gemini AI Explanation")
                st.write(ai_prompt)

                st.markdown("---")
                st.markdown("#### 📜 Raw VirusTotal Data")
                st.json(raw_data)
                
                # Download Button
                csv_data = convert_to_csv(raw_data)
                st.download_button(
                    label="⬇️ Download Raw Data as CSV",
                    data=csv_data,
                    file_name=f"{url_input.split('//')[-1]}_VT_scan.csv",
                    mime="text/csv",
                )


# --- IP REPUTATION ---
with tab3:
    st.subheader("📡 Check IP Reputation (AbuseIPDB + VirusTotal)")
    ip_input = st.text_input("Enter an IP address", placeholder="8.8.8.8")
    if ip_input and st.button("🛰️ Analyze IP"):
        
        # *** ENHANCEMENT: Use st.status for a visible, multi-step process ***
        with st.status(label="Starting IP Reputation Analysis...", expanded=True) as status:
            
            # Step 1: AbuseIPDB Check
            status.update(label="🌐 **Step 1/3:** Checking AbuseIPDB for abuse reports...", state="running")
            abuse_summary, abuse_raw = check_abuseipdb(ip_input)
            
            # Step 2: VirusTotal Check
            if "error" not in abuse_summary:
                status.update(label="🔍 **Step 2/3:** Consulting VirusTotal for engine detections...", state="running")
                vt_summary, vt_raw = check_virustotal_ip(ip_input)
            else:
                status.update(label="⚠️ **Step 2/3:** VirusTotal skipped due to AbuseIPDB error.", state="warning")
                vt_summary, vt_raw = {"error": "Skipped"}, {"raw_error": "Skipped"} # Set placeholders
            
            # Combine Data
            combined_summary = {
                "scanned_item": ip_input,
                "AbuseIPDB_summary": abuse_summary,
                "VirusTotal_summary": vt_summary
            }
            
            combined_raw = {
                "AbuseIPDB_raw": abuse_raw,
                "VirusTotal_raw": vt_raw
            }
            
            # Step 3: LLM Explanation
            ai_text = generate_ai_explanation(combined_summary, "IP Address", status_tracker=status)

            # Finalize Status based on results
            if "error" in abuse_summary or "error" in vt_summary:
                 status.update(label="❌ **Analysis Failed:** Check connection/keys for details.", state="error")
                 st.error("⚠️ Partial or full analysis failed. See logs for errors.")
            else:
                st.success("✅ All API checks and AI interpretation complete.")

        # --- Display Results Outside of Status Box ---
        
        # Summary and Explanation
        display_summary({'vt_data': vt_summary, 'abuse_data': abuse_summary}, "IP")
        st.markdown("### 🧠 Gemini AI Explanation")
        st.write(ai_text)
        
        st.markdown("---")
        st.markdown("#### 📜 Combined Raw Data")
        st.json(combined_raw)

        # Download Button
        csv_data = convert_to_csv(combined_raw)
        st.download_button(
            label="⬇️ Download Raw Data as CSV",
            data=csv_data,
            file_name=f"{ip_input}_combined_scan.csv",
            mime="text/csv",
        )