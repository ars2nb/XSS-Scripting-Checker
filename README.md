# XSS Testing Script

This script is designed to perform **Stored** and **Reflected XSS** (Cross-Site Scripting) vulnerability testing on web applications. It takes in a list of XSS payloads (from either files or a folder), and tests two types of XSS vulnerabilities across specified URLs.

### Features:
- **Stored XSS**: Tests POST requests to a URL for persistent XSS vulnerabilities.
- **Reflected XSS**: Tests GET requests to a URL for reflected XSS vulnerabilities.
- **Parallel Testing**: Runs both types of XSS tests concurrently using `ThreadPoolExecutor` to speed up the process.
- **Logging**: Logs the results of each payload test, including whether vulnerabilities were found or not.
- **Progress Bar**: Displays a progress bar (via `tqdm`) to show the status of ongoing tests.

---

## Prerequisites

Before running the script, you need to install the required Python libraries. You can install the dependencies using `pip`.

```bash
pip install requests tqdm
```

Ensure that your environment has the following libraries:
- `requests` (for sending HTTP requests)
- `tqdm` (for displaying a progress bar)

If you're running the script on a local machine, you'll need Python 3.x or later installed.

---

## How to Use

### 1. Prepare XSS Payloads:
The script reads payloads from either individual files or an entire folder containing `.txt` or `.payload` files. 

- **Create Payload Files**: Place XSS payloads into `.txt` or `.payload` files (e.g., `xss_payloads.txt`).
- **Directory Structure**: Place the payload files into a folder, say `payloads/`.

### 2. Running the Script:
Once the payload files are ready, you can execute the script. Follow these steps:

1. **Run the Script**:
   ```bash
   python xss_test_script.py
   ```

2. **Input the Details**:
   The script will prompt for the following:
   - **Stored XSS URL**: The URL where you want to test for stored XSS vulnerabilities (POST request).
   - **Reflected XSS URL**: The URL where you want to test for reflected XSS vulnerabilities (GET request with parameter).
   - **Payload Folder Path**: The folder path containing the payload files.
   - **Timeout**: Specify a timeout for HTTP requests (e.g., `10` seconds).

   Example input:
   ```
   Enter the URL for Stored XSS testing: https://example.com/store_xss
   Enter the URL for Reflected XSS testing (with GET parameter): https://example.com/reflect_xss?input=
   Enter the path to the folder containing payload files: ./payloads
   Enter the timeout value for requests (in seconds, e.g., 10): 10
   ```

3. **Review the Results**:
   After testing, the script will log the results in `xss_test_results.log` and print a summary to the terminal, showing how many payloads were tested and how many vulnerabilities were found.

   Example output:
   ```
   [+] Stored XSS Vulnerability Found with Payload: <script>alert(1)</script>
   [+] Reflected XSS Vulnerability Found with Payload: <img src="x" onerror="alert(1)">
   ```

4. **Logs**:
   All results are logged to `xss_test_results.log`. Each payload is tested for both stored and reflected XSS vulnerabilities, and the script will log whether it found a vulnerability or not for each payload.

---

## Example of Output

### Console:

```
Welcome to the XSS Testing Script!
Enter the URL for Stored XSS testing: https://example.com/store_xss
Enter the URL for Reflected XSS testing (with GET parameter): https://example.com/reflect_xss?input=
Enter the path to the folder containing payload files: ./payloads
Enter the timeout value for requests (in seconds, e.g., 10): 10
Do you want to proceed with testing? (yes/no): yes

Testing Stored XSS: 100%|███████████████████████████████████████████| 10/10
Testing Reflected XSS: 100%|███████████████████████████████████████████| 10/10

--- Summary of XSS Testing ---
Total Payloads Tested: 10
Stored XSS Vulnerabilities Found: 2
Reflected XSS Vulnerabilities Found: 1

XSS Tests Completed.
```

### Log File (`xss_test_results.log`):

```
2024-12-16 15:30:02 - [+] Stored XSS Vulnerability Found with Payload: <script>alert(1)</script>
2024-12-16 15:30:05 - [-] No Stored XSS Vulnerability Detected with Payload: <img src="x" onerror="alert(1)">
2024-12-16 15:30:10 - [+] Reflected XSS Vulnerability Found with Payload: <img src="x" onerror="alert(1)">
...
```

---

## Troubleshooting

### "No valid payloads found."
- Ensure that the payload files exist in the specified directory and contain valid payloads.
- Verify that the folder path and filenames are correct.

### "Error: The file '{file_path}' was not found."
- Check that the file exists and that the script has the necessary permissions to read it.

### "Error with request: ..."
- Check the URL you provided and ensure the server is reachable.
- Ensure that your firewall or security software isn't blocking requests.

---

## License

This script is provided for educational and testing purposes. Use it responsibly on applications you own or have explicit permission to test.
