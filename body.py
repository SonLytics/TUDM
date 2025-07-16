import csv
import json
from datetime import datetime
from pathlib import Path


class StatLogParser:
    def __init__(self, bodyfile_path: Path, hostname: str, uac_log_path: Path, output_dir: Path, tracker_path: Path):
        self.bodyfile_path = bodyfile_path
        self.hostname = hostname
        self.uac_log_path = uac_log_path
        self.output_path = output_dir / f"output_{hostname}.json"
        self.tracker_path = tracker_path
        self.fields = [
            "inode", "path", "block_count", "permissions",
            "uid", "gid", "size",
            "mtime", "ctime", "atime", "btime"
        ]

    def to_iso(self, ts: str):
        try:
            return datetime.fromtimestamp(int(ts), datetime.UTC).strftime('%Y-%m-%dT%H:%M:%S')
        except:
            return None

    def parse_line(self, log_line: str):
        parts = log_line.strip().split('|')
        if len(parts) != len(self.fields):
            print(f"[!] Skipping invalid line: {log_line}")
            return None
        raw = dict(zip(self.fields, parts))
        return {
            "target": {
                "file": {
                    "full_path": raw["path"],
                    "permissions": raw["permissions"],
                    "owner": {
                        "user_id": raw["uid"],
                        "group_id": raw["gid"]
                    },
                    "size": int(raw["size"]),
                    "inode": raw["inode"],
                    "block_count": raw["block_count"],
                    "accessed_time": self.to_iso(raw["atime"]),
                    "modified_time": self.to_iso(raw["mtime"]),
                    "metadata_change_time": self.to_iso(raw["ctime"]),
                    "created_time": self.to_iso(raw["btime"])
                }
            },
            "metadata": {
                "event_type": "FILE_READ",
                "product_name": "Linux",
                "description": "File metadata read"
            },
            "principal": {
                "process": {
                    "command_line": "stat"
                },
                "host_name": self.hostname
            }
        }

    def process(self):
        results = []
        with self.bodyfile_path.open("r", encoding="utf-8", errors="ignore") as infile:
            for line in infile:
                parsed = self.parse_line(line)
                if parsed:
                    results.append(parsed)

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="utf-8") as outfile:
            json.dump(results, outfile, indent=2)

        self._update_tracker()
        print(f"[✓] Parsed {len(results)} entries for host: {self.hostname}")
        print(f"[✓] Output saved to: {self.output_path}")

    def _update_tracker(self):
        header = ["hostname", "uac_log_path", "output_path"]
        rows = []

        if self.tracker_path.exists():
            with self.tracker_path.open("r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

        # Remove existing entry for this host+uac
        rows = [r for r in rows if (r["hostname"], r["uac_log_path"]) != (self.hostname, str(self.uac_log_path))]

        rows.append({
            "hostname": self.hostname,
            "uac_log_path": str(self.uac_log_path),
            "output_path": str(self.output_path)
        })

        with self.tracker_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            for r in rows:
                writer.writerow(r)


def load_evidence_records(evidence_csv: Path):
    if not evidence_csv.exists():
        raise FileNotFoundError(f"{evidence_csv} does not exist")

    with evidence_csv.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = [row for row in reader]
    return records


def load_processed_entries(tracker_path: Path):
    processed = set()
    if tracker_path.exists():
        with tracker_path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                processed.add((row["hostname"], row["uac_log_path"]))
    return processed


def main():
    # Locate folders
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent           # TUDM/
    evidence_dir = project_root / "Evidence"           # TUDM/Evidence
    output_dir = project_root / "output"               # TUDM/output
    evidence_csv = evidence_dir / "evidence_records.csv"
    tracker_csv = evidence_dir / "body_file_tracker.csv"

    records = load_evidence_records(evidence_csv)
    processed_set = load_processed_entries(tracker_csv)

    for record in records:
        uac_path = Path(record["uac_log_path"])
        hostname = record.get("hostname", "UNKNOWN").strip()

        if (hostname, str(uac_path)) in processed_set:
            print(f"[↪] Skipping already processed host: {hostname}")
            continue

        # Recursively find bodyfile.txt inside uac_log_path's folder
        bodyfile_path = None
        for path in uac_path.parent.rglob("bodyfile.txt"):
            bodyfile_path = path
            break

        if bodyfile_path:
            print(f"[•] Found bodyfile.txt for host: {hostname}")
            parser = StatLogParser(bodyfile_path, hostname, uac_path, output_dir, tracker_csv)
            parser.process()
        else:
            print(f"[!] bodyfile.txt not found for host: {hostname} under {uac_path.parent}")


if __name__ == "__main__":
    main()
