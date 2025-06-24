import argparse
import os
import re
from collections import Counter

severity_words = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
purple_color = '\033[35m'
green_color = '\033[32m'
red_color = '\033[31m'
reset_color = '\033[0m'


def count_severity_words_and_cves_in_file(file_path):
    counts = {sev: 0 for sev in severity_words}
    pattern = re.compile(r'\bcve-\d{4}-\d+\b', re.VERBOSE)
    cve_counter = Counter()
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            text = file.read()
            cve_matches = pattern.findall(text)
            cve_counter.update(cve_matches)
            for w in severity_words:
                counts[w] += text.count(w)
    except IOError as e:
        print(f"{red_color}Error during processing file {file_path}: {e}{reset_color}")
    total_count = sum(cve_counter.values())
    return counts, total_count, cve_counter.most_common()


def process_folder_files(folder_path, output_path):
    most_common_cves = [tuple[str, int]]
    total = 0
    total_counts = {severity: 0 for severity in severity_words}
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".txt"):
                file_path = os.path.join(root, file)
                severity_count, total, most_common_cves = count_severity_words_and_cves_in_file(file_path)
                print(f"{purple_color}Processing file {file_path}{reset_color}")
                for severity_word in severity_words:
                    total_counts[severity_word] += severity_count[severity_word]
    if output_path:
        with open(output_path, "w", encoding="utf-8") as file:
            for cve in most_common_cves:
                file.write(f"{cve[0]}: {cve[1]}\n")
                file.flush()
    print(f"{green_color}Total number of CVE matches: {total}{reset_color}")
    print(f"{purple_color}Most repeated CVE's: ")
    for cve_id, cve_count in most_common_cves:
        print(f"{cve_id}: {cve_count}")
    print(f"{reset_color}")
    return total_counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--folder", help="Path to the folder containing files", required=True)
    parser.add_argument("-o", "--output", help="Path to the folder containing files", required=False)
    args = parser.parse_args()
    results = process_folder_files(args.f, args.o)
    for word, count in results.items():
        print(f"[+] {green_color}Total severity found in files {word}: {count}{reset_color}")
