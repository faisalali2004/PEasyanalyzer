import re
import math
from collections import defaultdict

def calculate_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log2(p) for p in prob)

def extract_suspicious_strings(file_path, show_all=False):
    """
    Extract and rank suspicious strings based on patterns and entropy.
    :param file_path: path to the file to analyze
    :param show_all: if True, return all matched strings, else top 50
    :return: list of suspicious strings
    """
    with open(file_path, 'rb') as f:
        content = f.read()

    # Extract printable ASCII strings
    ascii_strings = re.findall(rb"[\x20-\x7E]{5,}", content)
    decoded_strings = [s.decode('utf-8', 'ignore').strip() for s in ascii_strings if s.strip()]

    # Precompiled suspicious patterns
    patterns = {
        "URL": re.compile(r"http[s]?://[\w./%-]+", re.IGNORECASE),
        "FTP": re.compile(r"ftp://[\w./%-]+", re.IGNORECASE),
        "Email": re.compile(r"[\w.-]+@[\w.-]+\.[a-zA-Z]{2,6}", re.IGNORECASE),
        "IP Address": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "Shell/Commands": re.compile(r"\b(cmd\.exe|powershell|wget|curl|nc|telnet|ssh|scp|bash|sh)\b", re.IGNORECASE),
        "Credentials": re.compile(r"\b(admin|root|pass(word)?|key|token|secret|access|pwd|auth)\b", re.IGNORECASE),
        "Scripting": re.compile(r"\b(regsvr32|rundll32|vbs|js|hta|script|macro|mshta|comsvcs)\b", re.IGNORECASE),
        "Hexadecimal": re.compile(r"\b0x[a-fA-F0-9]{4,}\b"),
        "Encoding": re.compile(r"\b(base64|encode|decode|xor|encrypt|decrypt|rot13)\b", re.IGNORECASE),
        "Suspicious TLD": re.compile(r"\.(ru|cn|xyz|top|tk|info|biz)\b", re.IGNORECASE),
        "API Keys": re.compile(r"(AIza[0-9A-Za-z-_]{35}|sk_live_[0-9a-zA-Z]{24,})"),
        "C2 Domain": re.compile(r"\b([a-z0-9]{6,12}\.(com|net|xyz|tk))\b", re.IGNORECASE)
    }

    suspicious_scores = defaultdict(int)
    high_entropy_threshold = 4.2

    for string in decoded_strings:
        hit = False
        for name, pattern in patterns.items():
            if pattern.search(string):
                suspicious_scores[string] += 2  # Pattern match gets higher weight
                hit = True
        if not hit and len(string) >= 20:
            entropy = calculate_entropy(string)
            if entropy >= high_entropy_threshold:
                suspicious_scores[string] += 1  # High entropy string

    # Sort by suspicious score, then by string length
    sorted_suspicious = sorted(suspicious_scores.items(), key=lambda x: (-x[1], -len(x[0])))

    # Return based on user's preference
    result = [s for s, _ in sorted_suspicious]
    return result if show_all else result[:50]