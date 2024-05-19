import asyncio
import base64
import logging
import os
from concurrent.futures import ThreadPoolExecutor
import random
import shutil
import string
from tempfile import mkdtemp
import yara
from typing import List, Dict, Union
from tqdm.asyncio import tqdm 
import pandas as pd
from base64 import b64encode
from pathlib import Path

# Configuration for logging
logging.basicConfig(filename='yara_scan_errors.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Executor for running synchronous functions in an async manner
executor = ThreadPoolExecutor(max_workers=min(32, os.cpu_count() + 4 if os.cpu_count() else 4))

# Semaphore to limit concurrency
sem = asyncio.Semaphore(4)

async def extract_file_async(file_path: str, extract_to: str) -> None:
    """Asynchronously extract a file to a specified directory.

    Args:
        file_path: The path to the file to be extracted.
        extract_to: The directory where the file should be extracted.
    """
    cmd = [r'malwaredoc\extract\bin\amd64\7z.exe', 'x', file_path, f'-o{extract_to}', '-y']
    process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    _, stderr = await process.communicate()
    if process.returncode != 0:
        logging.error(f"Error extracting file {file_path}: {stderr.decode()}")

def scan_file(rules: yara.Rules, file_path: str) -> list[dict[str, Union[str, int, List[dict[str, Union[str, int, bytes]]]]]]:
    """Synchronously scan a file with provided YARA rules, returning detailed information about matches.

    Args:
        rules: Compiled YARA rules.
        file_path: Path to the file to be scanned.

    Returns:
        A list of dictionaries, each containing the matched rule name, matching content (as a string or bytes),
        identifier, and offset of the match within the file.
    """
    matches = rules.match(file_path)
    detailed_matches = []

    for match in matches:
        match_strings = []
        for string_match in match.strings:
            # Access properties of yara.StringMatch object
            identifier = string_match.identifier
            for instance in string_match.instances:
                # Access matched data and offset for each instance
                data = instance.matched_data
                offset = instance.offset

                match_strings.append({
                    "offset": offset,
                    "identifier": identifier,
                    "data": data.hex()  # or data if you prefer the raw bytes in some cases
                })

        detailed_matches.append({
            "rule": match.rule,
            "tags": match.tags,  # Including tags as they can be useful
            "namespace": match.namespace,
            "meta": match.meta,  # Metadata associated with the rule
            "matches": match_strings
        })

    return detailed_matches



async def scan_file_async(rules: yara.Rules, file_path: str) -> List[str]:
    """Asynchronously scan a file with provided YARA rules.

    Args:
        rules: Compiled YARA rules.
        file_path: Path to the file to be scanned.

    Returns:
        A list of matched rule names.
    """
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(executor, scan_file, rules, file_path)
    except yara.Error as e:
        logging.error(f"YARA could not open file {file_path}: {e}")
        return []

def sanitize_name(name: str) -> str:
    """Sanitize the filename or directory name to ensure it contains only printable characters.

    Args:
        name: The original name to be sanitized.

    Returns:
        The sanitized name.
    """
    return ''.join(c if c.isprintable() and not c.isspace() else '_' for c in name)

def sanitize_directory(directory: str) -> None:
    """Recursively sanitize all file and directory names within the given directory.

    Args:
        directory: The root directory to start sanitization from.
    """
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            sanitized_name = sanitize_name(name)
            original_path = os.path.join(root, name)
            new_path = os.path.join(root, sanitized_name)
            if original_path != new_path and not os.path.exists(new_path):
                os.rename(original_path, new_path)
        for name in dirs:
            sanitized_name = sanitize_name(name)
            original_path = os.path.join(root, name)
            new_path = os.path.join(os.path.dirname(root), sanitized_name)
            if original_path != new_path and not os.path.exists(new_path):
                os.rename(original_path, new_path)

def is_valid_path(path: str) -> bool:
    """Check if the path contains only ASCII, numeric, or printable characters.

    Args:
        path: The path to validate.

    Returns:
        True if valid, False otherwise.
    """
    printable = set(string.printable)
    return all(c in printable for c in path)

def clean_string(input_str: str, is_filename: bool = False) -> str:
    """Clean the string by removing non-ASCII, non-printable, and OS-specific invalid path characters.

    Args:
        input_str: The string to be cleaned.
        is_filename: Specifies if the cleaning rules should consider the string as a filename.

    Returns:
        The cleaned string.
    """
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    if os.name == 'nt':
        invalid_chars = '<>:"/\\|?*'
        valid_chars = valid_chars.replace(invalid_chars, '')
    if is_filename:
        return ''.join(c if c in valid_chars else random.choice(string.ascii_letters + string.digits) for c in input_str)
    else:
        return ''.join(c for c in input_str if c in valid_chars)

def clean_and_ensure_path(full_path: str) -> str:
    """Clean each part of the path and ensure that intermediary directories exist.

    Args:
        full_path: The full path to clean and ensure.

    Returns:
        The cleaned and ensured path.
    """
    path_parts = full_path.split(os.path.sep)
    cleaned_parts = [clean_string(part) for part in path_parts[:-1] if part]
    cleaned_filename = clean_string(path_parts[-1], is_filename=True)

    new_path = os.path.sep.join(cleaned_parts + [cleaned_filename])
    if not os.path.exists(os.path.dirname(new_path)):
        os.makedirs(os.path.dirname(new_path), exist_ok=True)
    
    return new_path

async def scan_and_extract_async(rules: yara.Rules, file_path: str) -> List[Dict[str, Union[str, int, bytes, List[Dict[str, Union[str, int, bytes]]]]]]:
    """Asynchronously scan and extract files, applying YARA rules to the original and extracted files.

    Args:
        rules: Compiled YARA rules.
        file_path: Path to the file to be scanned and extracted.

    Returns:
        A list of dictionaries, each containing detailed information about the scan matches.
    """
    if not os.path.isfile(file_path):
        logging.info(f"File not found: {file_path}")
        return []

    results = []
    temp_dir = mkdtemp()

    try:
        await extract_file_async(file_path, temp_dir)
        
        # Initialize the list of files to scan with the original file
        files_to_scan = [file_path]

        # Add paths of all extracted files to the list
        files_to_scan.extend(
            os.path.join(root, name) for root, _, files in os.walk(temp_dir) for name in files
        )

        number_of_files = len(files_to_scan)

        pbar = tqdm(total=number_of_files, desc="Scanning files")
        
        for full_path in files_to_scan:
            # Clean and ensure path for extracted files
            if full_path.startswith(temp_dir) and not is_valid_path(full_path):
                new_full_path = clean_and_ensure_path(full_path)
                shutil.move(full_path, new_full_path)
                full_path = new_full_path

            detailed_matches = await scan_file_async(rules, full_path)
            for match in detailed_matches:
                # Incorporate detailed match information into results
                result = {
                    "file_path": file_path,  # Reference to the original file path
                    "sub_file_basename": os.path.basename(full_path),  # Extracted file name or original
                    "number_of_files": number_of_files,
                    # Include all unique keys from the detailed match information
                    **match
                }
                results.append(result)

            pbar.update(1)

        pbar.close()
    finally:
        shutil.rmtree(temp_dir)  # Clean up the temporary directory

    return results


def compile_yara_rules_from_directory(yara_rules_path: str) -> yara.Rules:
    """Compile YARA rules from a specified directory.

    Args:
        yara_rules_path: The directory containing YARA rule files.

    Returns:
        Compiled YARA rules.
    """
    yara_files = {os.path.basename(file_path).replace(".yar", ""): file_path for root, dirs, files in os.walk(yara_rules_path) for file_path in [os.path.join(root, name) for name in files if name.endswith(".yar")]}
    return yara.compile(filepaths=yara_files)

async def run_yara_rules_async(yara_rules_path: str, files_to_scan: List[str]) -> List[Dict[str, str]]:
    """Asynchronously run YARA rules against a list of files, scanning and extracting each file.

    Args:
        yara_rules_path: The path to the directory containing YARA rule files.
        files_to_scan: A list of file paths to scan.

    Returns:
        A list of results, each a dictionary containing the file path, sub-file basename, and matched YARA rule.
    """
    rules = compile_yara_rules_from_directory(yara_rules_path)
    results = []
    pbar = tqdm(total=len(files_to_scan), desc="Overall Progress")
    tasks = [scan_and_extract_async(rules, file_path) for file_path in files_to_scan]
    all_results = await asyncio.gather(*tasks)
    for result in all_results:
        results.extend(result)
        pbar.update(1)
    pbar.close()
    return results


dataset_directory = os.path.join(os.path.dirname(os.getcwd()), "malware_samples")
files_list = [os.path.join(dataset_directory, os.path.join(file_name, file_name)) for file_name in os.listdir(dataset_directory)][:10]
yara_path = os.path.join(os.path.dirname(os.getcwd()), "yara_rules")
resa = asyncio.run(run_yara_rules_async(yara_path, files_list))

pd.DataFrame(resa).to_json("yara_rule_matches.json", orient="records")