import hashlib
import argparse
import mimetypes
import requests
from colorama import Fore, Style, init

# Initialize colorama
init()

def generate_file_hashes(file_path):
    hashes = {
        'MD5': hashlib.md5(),
        'SHA-1': hashlib.sha1(),
        'SHA-256': hashlib.sha256()
    }
    
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                for hash_alg in hashes.values():
                    hash_alg.update(chunk)
    except FileNotFoundError:
        print(f"{Fore.RED}File not found: {file_path}{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")
        return None
    
    return {name: hash_alg.hexdigest() for name, hash_alg in hashes.items()}

def get_file_type(file_path):
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type or "Unknown file type"

def check_virustotal(hash_value, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"{Fore.RED}Error: {response.status_code}{Style.RESET_ALL}")
        return None

def format_virustotal_results(results):
    if 'data' not in results:
        return "No data available."
    
    attributes = results['data']['attributes']
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    last_analysis_results = attributes.get('last_analysis_results', {})
    
    formatted_results = []
    
    file_info = [
        f"File name: {attributes.get('name', 'Unknown')}",
        f"File size: {attributes.get('size', 'Unknown')} bytes",
        f"Upload date: {attributes.get('first_submission_date', 'Unknown')}",
        f"Last analysis date: {attributes.get('last_analysis_date', 'Unknown')}",
    ]
    
    formatted_results.append(f"{Fore.BLUE}File Information:{Style.RESET_ALL}")
    formatted_results.extend(file_info)
    
    formatted_results.append(f"\n{Fore.GREEN}Detection Statistics:{Style.RESET_ALL}")
    formatted_results.append(f"Harmless: {last_analysis_stats.get('harmless', 0)}")
    formatted_results.append(f"Malicious: {last_analysis_stats.get('malicious', 0)}")
    formatted_results.append(f"Suspicious: {last_analysis_stats.get('suspicious', 0)}")
    formatted_results.append(f"Undetected: {last_analysis_stats.get('undetected', 0)}")
    
    total_engines = sum(last_analysis_stats.values())
    if total_engines > 0:
        detection_ratio = (last_analysis_stats.get('malicious', 0) / total_engines) * 100
        formatted_results.append(f"\n{Fore.YELLOW}Detection Ratio: {detection_ratio:.2f}%{Style.RESET_ALL}")
    
    formatted_results.append(f"\n{Fore.BLUE}Detailed Scan Results:{Style.RESET_ALL}")
    for engine, result in last_analysis_results.items():
        if result['category'] != 'undetected':
            color = Fore.YELLOW if result['category'] == 'suspicious' else Fore.RED
            formatted_results.append(f"{color}{engine}: {result['category']} ({result['result']}){Style.RESET_ALL}")
    
    return "\n".join(formatted_results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate multiple hashes for a file using hashlib and check them with VirusTotal.")
    parser.add_argument("file_path", type=str, help="Path to the file to hash")
    parser.add_argument("api_key", type=str, help="VirusTotal API key")
    
    args = parser.parse_args()
    file_path = args.file_path
    api_key = args.api_key

    file_type = get_file_type(file_path)
    print(f"{Fore.BLUE}File type: {file_type}{Style.RESET_ALL}\n")
    
    hashes = generate_file_hashes(file_path)
    
    if hashes:
        print(f"{Fore.BLUE}File hashes:{Style.RESET_ALL}")
        for name, hash_value in hashes.items():
            print(f"{Fore.CYAN}{name}: {hash_value}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}Checking {name} hash with VirusTotal...{Style.RESET_ALL}")
            result = check_virustotal(hash_value, api_key)
            if result:
                print(f"{Fore.BLUE}VirusTotal results for {name}:{Style.RESET_ALL}")
                print(format_virustotal_results(result))
            else:
                print(f"{Fore.RED}No results found for {name} hash.{Style.RESET_ALL}")
            print()
