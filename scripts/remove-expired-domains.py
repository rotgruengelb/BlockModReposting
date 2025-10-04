import subprocess, re

INPUT_FILE = "list.txt"
OUTPUT_FILE = "list_filtered.txt"

domain_pattern = re.compile(r"\|\|([^\\^]+)\^")

def whois_no_match(domain: str) -> bool:
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout.lower()
        return "no match for domain" in output
    except subprocess.TimeoutExpired:
        print(f"failed {domain}, took too long.")
        return False
    except Exception as e:
        print(f"failed for {domain}: {e}")
        return False

def main():
    kept_lines = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for index, line in enumerate(lines, start=1):
        if not line.startswith("||"):
            kept_lines.append(line)
            continue

        match = domain_pattern.search(line)
        if not match:
            print(f"Skipping malformed {line.strip()} @ {index}")
            continue
        domain = match.group(1)

        no_match = whois_no_match(domain)
        if not no_match:
            kept_lines.append(line)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.writelines(kept_lines)

    print(f"Kept {len(kept_lines)}/{len(lines)} entries.")

if __name__ == "__main__":
    main()
