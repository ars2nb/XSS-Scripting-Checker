---

# XSS Scripting-Checker

This Python script is designed for testing **Stored XSS** and **Reflected XSS** vulnerabilities on web applications. The script allows you to test a list of XSS payloads against specified URLs. It automatically finds and lists available payload files in the `payloads` directory and allows you to select one for testing.

### Features:
- **Stored XSS Testing**: Tests for vulnerabilities where payloads are stored on the server.
- **Reflected XSS Testing**: Tests for vulnerabilities where payloads are reflected immediately back to the user in the response.
- **Automatic Payload Selection**: Automatically detects and lists payload files in the `payloads` folder.
- **Flexible URL Input**: Allows users to specify the URLs for both Stored and Reflected XSS testing.
- **Logging**: Logs the results of the tests to a file for later review.
- **Threaded Testing**: Tests are run concurrently using multiple threads to speed up the process.

---

## Requirements

- **Python 3.x**  
  Ensure that Python 3.x is installed on your system. You can download Python from the [official website](https://www.python.org/downloads/).

- **Required Libraries**  
  The script requires the following Python libraries:
  - `requests`: For making HTTP requests to the target URLs.
  - `tqdm`: For displaying a progress bar during testing.
  - `concurrent.futures`: For running tests concurrently (multi-threading).

  You can install the required libraries using `pip`:

  ```bash
  pip install requests tqdm
  ```

---

## Setup

1. **Clone or Download the Repository**

   Clone or download the repository to your local machine:

   ```bash
   git clone https://github.com/fish-hue/XSS-Scripting-Checker.git
   ```

   or just download the ZIP file and extract it.

2. **Folder Structure**

   The folder structure should look like this:

   ```
   xss-check/
   ├── payloads/
   │   ├── payload1.txt
   │   └── payload2.txt
   └── xss-chk.py
   ```

   - `payloads/`: This folder contains the payload files. These files should have `.txt` extensions.
   - `xss-chk.py`: This is the main script that performs the XSS tests.

---

## How to Use

1. **Navigate to the `xss-check` Directory**  
   Open a terminal and navigate to the `xss-check` directory:

   ```bash
   cd path/to/xss-check
   ```

2. **Run the Script**  
   Execute the script using Python:

   ```bash
   python xss-chk.py
   ```

3. **Follow the Prompts**  
   The script will guide you through the testing process:

   - **Enter the URL for Stored XSS Testing**: Provide the URL of the page where stored XSS is possible (e.g., `http://example.com/submit`).
   - **Enter the URL for Reflected XSS Testing**: Provide the URL for reflected XSS testing (e.g., `http://example.com/search?q=`).
   - **Choose a Payload File**: The script will automatically list all available `.txt` payload files in the `payloads/` folder. Select the appropriate file by number.
   - **Set Timeout**: The script will ask for a timeout value (in seconds) for the HTTP requests.
   - **Confirm to Proceed**: You will be asked if you want to proceed with the testing.

4. **View the Results**  
   The script will display the results of the testing in the terminal. It will also log the results to a file called `xss_test_results.log` for future reference.

---

## Example

Here’s an example of how it might look when running the script:

```bash
Welcome to the XSS Testing Script!

Enter the URL for Stored XSS testing (e.g., example.com/submit): http://example.com/submit
Enter the URL for Reflected XSS testing (e.g., example.com/search?q=): http://example.com/search?q=

Available Payload Files:
1. payload1.txt
2. payload2.txt

Select a payload file by number: 1

Enter the timeout value for requests (in seconds, e.g., 10): 10

Do you want to proceed with testing? (yes/no): yes

Testing Stored XSS:
[+] Stored XSS Vulnerability Found with Payload: <script>alert('XSS')</script>
[-] No Stored XSS Vulnerability Detected with Payload: <img src="x" onerror="alert(1)">
...

Testing Reflected XSS:
[+] Reflected XSS Vulnerability Found with Payload: <script>alert('XSS')</script>
[-] No Reflected XSS Vulnerability Detected with Payload: <img src="x" onerror="alert(1)">
...

--- Summary of XSS Testing ---
Total Payloads Tested: 10
Stored XSS Vulnerabilities Found: 1
Reflected XSS Vulnerabilities Found: 1
```

---

## Troubleshooting

- **File Not Found**: If the script can't find the `payloads/` folder or the specified payload file, double-check that the folder and the `.txt` files are correctly placed in the same directory as `xss-chk.py`.
- **Missing Libraries**: If you encounter errors related to missing libraries (`requests` or `tqdm`), make sure to install them using `pip` as mentioned in the Requirements section.

---
