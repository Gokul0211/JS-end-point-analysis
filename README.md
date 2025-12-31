
# JS Endpoint Analysis Tool 🚀

This tool performs dynamic and static analysis on JavaScript files to discover hidden API endpoints, routes, and configuration variables. It is designed to help security researchers and developers identify potential attack surfaces in modern web applications (e.g., Angular, React, Vue) by parsing obfuscated code and resolving method calls.

## Key Features 🔍

* **Method Call Resolution:** Automatically resolves dynamic endpoints constructed via functions like `this.getRootUrl()`.
* **Angular Service Support:** Detects and reconstructs endpoints defined in Angular service properties.
* **Hash Routing Support:** Correctly identifies and normalizes hash-based routing (`/#/path`).
* **Variable Extraction:** Extracts hardcoded variables, API keys, and configuration objects.
* **Report Generation:** Exports findings to `results.json` and `results.xlsx` for easy reporting.

## Installation 🛠️

1. Clone the repository:
```bash
git clone https://github.com/Gokul0211/JS-end-point-analysis.git
cd JS-end-point-analysis

```


2. Install the required Python packages:
```bash
pip install requests beautifulsoup4 pandas openpyxl playwright

```


3. Install Playwright browsers (required for dynamic analysis):
```bash
playwright install chromium

```



## How to Run 🏃‍♂️

To start the scanner, simply run the main script:

```bash
python python.py

```

*Note: You will be prompted to enter the target URL and optional cookies via the command line interface.*

## Usage Example 📝

1. Run the script: `python python.py`
2. Enter Target URL: `https://example.com`
3. Add Cookies (Optional): Type `n` to skip or `y` to add session cookies for authenticated scanning.
4. View Results: Check the generated `results.json` or `results.xlsx` files in the current directory.

## Disclaimer ⚠️

This tool is intended for security research and educational purposes only. Please ensure you have authorized permission to scan the target application.
