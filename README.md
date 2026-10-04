# Attack Surface Scanner

The **Attack Surface Scanner** is a modular command-line tool designed to automate the process of network-based attack surface discovery. It integrates Nmap for service enumeration, applies a custom risk analysis engine, and generates structured reports. The tool is built for students, analysts, and small organizations that require a lightweight but effective security assessment workflow.

---

## 1. Overview

The purpose of this tool is to provide a simplified, repeatable, and interpretable method for discovering exposed services and understanding their associated risks. While Nmap provides powerful raw data, this tool extends that capability by offering:

- Automated scanning
- Risk-level categorization
- Structured reporting
- Persistent scan storage for future comparison

This aligns with real-world security assessment workflows and academic requirements for incremental system development.

---


## 2. System Capabilities (Increment 1)

### **Network Scanning**
- Executes Nmap with service/version detection  
- Extracts ports, services, products, and versions  
- Supports multiple scan profiles (e.g., `network-basic`)

### **Risk Analysis**
- Automatically assigns HIGH / MEDIUM / LOW / UNKNOWN risk levels  
- Summarizes overall risk exposure

### **Reporting**
- Displays results using Rich-based tables  
- Generates a structured risk summary  
- Saves every scan as a timestamped JSON file inside `results/`

### **Core Functionality Included in Increment 1**
- Command-line interface  
- Target validation  
- Scan profile selection  
- Network scanning pipeline  
- Risk classification  
- Console report generation  
- Scan result storage system  

Increment 1 is **fully completed**.

---


## 3. Installation

### **Prerequisites**
- Python 3.8+  
- Nmap installed on system  
- WhatWeb installed and available in PATH (for `web-focused` profile)  
- Virtual environment recommended  

### **Setup Steps**
```bash
git clone <your-repo-url>
cd attack_surface_scanner
python -m venv .venv
```


### Activate environment:
```bash
.venv\Scripts\activate      # Windows
# OR
source .venv/bin/activate  # Linux/Mac
```


### Install dependencies:
```bash
pip install -r requirements.txt
```

Use only one environment for this project (`.venv`) to avoid IDE/dependency analysis mismatches.

---


## 4. Running the Tool

### - Basic Scan
python -m scanner.cli --target scanme.nmap.org

### - Scan with Profile
python -m scanner.cli --target example.com --profile network-basic

### - Web-Focused Scan (Nmap + WhatWeb)
python -m scanner.cli --target example.com --profile web-focused

### - Web-Focused Scan with Optional Directory Enumeration
python -m scanner.cli --target example.com --profile web-focused --dir-enum

### - Web-Focused Scan with Custom Timeouts
python -m scanner.cli --target example.com --profile web-focused --dir-enum --web-timeout 15 --dir-timeout 3

### - Web-Focused Scan with Raw WhatWeb Evidence in Exports
python -m scanner.cli --target example.com --profile web-focused --web-raw --export-formats txt,md

### - Web-Focused Scan with Custom Directory Wordlist
python -m scanner.cli --target example.com --profile web-focused --dir-enum --dir-wordlist wordlist.txt

### - Compare with Latest Previous Scan (same target/profile)
python -m scanner.cli --target example.com --profile network-basic --compare-latest

### - Compare with a Specific Previous Scan File
python -m scanner.cli --target example.com --profile network-basic --compare-file results/previous_scan.json

### - Export TXT and Markdown Reports
python -m scanner.cli --target example.com --profile network-basic --export-formats txt,md

### - Scan Output Location
All scans are saved in:
                    results/

Each file includes target, profile, timestamp, and full analysis.

---


## 5. Why This Tool Is More Than Nmap
  Nmap is a powerful scanner — but it provides raw data, not structured insights.
  
  
This tool adds:

###- Profiles (Simplified Usage)
  Instead of memorizing complex flags, users select:
    - network-basic
    - web-focused


###- Risk Engine
  Each exposed service is automatically classified using a built-in mapping.


###- Structured Output
  Readable tables and summaries improve understanding and reporting quality.


###- Historical Data
  Every scan is saved, enabling comparison over time (Increment 3).


###- Ready for Modular Expansion
  Additional modules (web scanning, diff engine) will integrate seamlessly.

This makes the tool suitable not only for learning but also for practical assessment workflows.

---


## 6. Roadmap (Increment 2 & Increment 3)

###- Increment 2 – Web Attack Surface Scanning
  Web-focused scanning is now completed:

    - WhatWeb integration for technology fingerprinting (implemented)
    - Web-focused scan profile (implemented)
    - Optional directory enumeration (implemented)
    - Combined network + web reporting (implemented)

###- Increment 3 – History and Change Detection
  Increment 3 is now implemented with:
    - Diff engine to compare scans over time (implemented)
    - Detection of:
        - Newly opened ports (implemented)
        - Closed ports (implemented)
        - Changed service versions/services (implemented)
        - Risk changes (implemented)
    - Exportable reports (TXT, Markdown) (implemented)
    - Basic attack surface scoring (implemented)

These enhancements align with real-world security processes and complete the incremental SDLC approach.

---


## 7. Project Status
### ** Component **  	                       ### ** Status ** 
Increment 1 (Core Network Scanner)	                Completed
Increment 2 (Web Scanning)	                        Completed
Increment 3 (Diff Engine & Scoring)	                Completed
Overall Completion	                                 ~90%

---


## 8. Author
M. Faisal
BS-IT (8th Semester) Sec. A
University of Agriculture Faisalabad
