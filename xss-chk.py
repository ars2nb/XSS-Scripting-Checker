import os
import requests
from urllib.parse import quote
import logging
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm  # For progress bar

# Setting up logging
logging.basicConfig(filename='xss_test_results.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to read payloads from a file
def read_payloads_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            payloads = [line.strip() for line in file if line.strip()]
            if not payloads:
                print(f"Warning: The file '{file_path}' is empty.")
            return payloads
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return []
    except PermissionError:
        print(f"Error: Permission denied when accessing '{file_path}'.")
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

# Function to read all payload files in a folder (with file type filtering)
def read_payloads_from_folder(folder_path):
    payloads = []
    try:
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path) and (filename.endswith('.txt') or filename.endswith('.payload')):  # Filter for specific file types
                print(f"Reading payloads from file: {file_path}")
                file_payloads = read_payloads_from_file(file_path)
                payloads.extend(file_payloads)
        if not payloads:
            print(f"No valid payloads found in folder '{folder_path}'.")
    except FileNotFoundError:
        print(f"Error: The folder '{folder_path}' was not found.")
    except PermissionError:
        print(f"Error: Permission denied when accessing '{folder_path}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return payloads

# Function to test for Stored XSS
def test_stored_xss(stored_xss_url, payload, timeout):
    try:
        response = requests.post(stored_xss_url, data={'input': payload}, timeout=timeout)
        response.raise_for_status()  # Check for HTTP errors
        if response.status_code == 404:
            logging.warning(f"Page not found: {stored_xss_url} with payload {payload}")
        elif response.status_code == 500:
            logging.error(f"Server error at {stored_xss_url} with payload {payload}")
        return payload, "<script>" in response.text or "onerror" in response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error with request: {e} for payload: {payload}")
        return payload, False

# Function to test for Reflected XSS
def test_reflected_xss(reflected_xss_url, payload, timeout):
    try:
        response = requests.get(reflected_xss_url + quote(payload), timeout=timeout)
        response.raise_for_status()  # Check for HTTP errors
        if response.status_code == 404:
            logging.warning(f"Page not found: {reflected_xss_url} with payload {payload}")
        elif response.status_code == 500:
            logging.error(f"Server error at {reflected_xss_url} with payload {payload}")
        return payload, "<script>" in response.text or "onerror" in response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error with request: {e} for payload: {payload}")
        return payload, False

# Function to run stored and reflected XSS tests concurrently
def run_tests_concurrently(stored_xss_url, reflected_xss_url, payloads, timeout):
    stored_vulnerabilities = 0
    reflected_vulnerabilities = 0

    with ThreadPoolExecutor(max_workers=5) as executor:
        # Run Stored XSS tests
        stored_results = executor.map(lambda payload: test_stored_xss(stored_xss_url, payload, timeout), payloads)
        for payload, result in tqdm(stored_results, total=len(payloads), desc="Testing Stored XSS", ncols=100):
            if result:
                logging.info(f"[+] Stored XSS Vulnerability Found with Payload: {payload}")
                print(f"[+] Stored XSS Vulnerability Found with Payload: {payload}")
                stored_vulnerabilities += 1
            else:
                logging.info(f"[-] No Stored XSS Vulnerability Detected with Payload: {payload}")

        # Run Reflected XSS tests
        reflected_results = executor.map(lambda payload: test_reflected_xss(reflected_xss_url, payload, timeout), payloads)
        for payload, result in tqdm(reflected_results, total=len(payloads), desc="Testing Reflected XSS", ncols=100):
            if result:
                logging.info(f"[+] Reflected XSS Vulnerability Found with Payload: {payload}")
                print(f"[+] Reflected XSS Vulnerability Found with Payload: {payload}")
                reflected_vulnerabilities += 1
            else:
                logging.info(f"[-] No Reflected XSS Vulnerability Detected with Payload: {payload}")

    return stored_vulnerabilities, reflected_vulnerabilities

def print_summary(total_payloads, stored_vulnerabilities, reflected_vulnerabilities):
    print("\n--- Summary of XSS Testing ---")
    print(f"Total Payloads Tested: {total_payloads}")
    print(f"Stored XSS Vulnerabilities Found: {stored_vulnerabilities}")
    print(f"Reflected XSS Vulnerabilities Found: {reflected_vulnerabilities}")
    logging.info(f"Total Payloads Tested: {total_payloads}")
    logging.info(f"Stored XSS Vulnerabilities Found: {stored_vulnerabilities}")
    logging.info(f"Reflected XSS Vulnerabilities Found: {reflected_vulnerabilities}")

def main():
    print("Welcome to the XSS Testing Script!")

    # Get user input for URLs
    stored_xss_url = input("Enter the URL for Stored XSS testing: ")
    reflected_xss_url = input("Enter the URL for Reflected XSS testing (with GET parameter): ")

    # Validate URLs
    if not stored_xss_url.startswith("http") or not reflected_xss_url.startswith("http"):
        print("Invalid URL(s) entered. Please ensure they are complete URLs starting with 'http'.")
        return

    # Specify the payload folder
    payload_folder_path = input("Enter the path to the folder containing payload files: ")
    payloads = read_payloads_from_folder(payload_folder_path)

    # Check if there are any payloads to test
    if not payloads:
        print("No valid payloads found. Exiting.")
        return

    # Get timeout value
    try:
        timeout = float(input("Enter the timeout value for requests (in seconds, e.g., 10): "))
    except ValueError:
        print("Invalid timeout value. Using default timeout of 10 seconds.")
        timeout = 10.0

    # Confirm the user wants to proceed
    proceed = input("\nDo you want to proceed with testing? (yes/no): ")
    if proceed.lower() == 'yes':
        stored_vulnerabilities, reflected_vulnerabilities = run_tests_concurrently(stored_xss_url, reflected_xss_url, payloads, timeout)
        print_summary(len(payloads), stored_vulnerabilities, reflected_vulnerabilities)
    else:
        print("Testing aborted.")

    print("XSS Tests Completed.")

if __name__ == "__main__":
    main()
