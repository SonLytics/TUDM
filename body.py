import csv
import json
from datetime import datetime
from pathlib import Path
from multiprocessing import Pool, Manager, cpu_count
from pygrok import Grok

GROK_PATTERNS = [
    Grok(r'%{NUMBER:inode}\|%{DATA:path}\|%{NUMBER:block_count}\|%{DATA:permissions}\|%{NUMBER:uid}\|%{NUMBER:gid}\|%{NUMBER:size}\|%{NUMBER:mtime}\|%{NUMBER:ctime}\|%{NUMBER:atime}\|%{NUMBER:btime}'),
    Grok(r'%{NUMBER:inode}\|%{DATA:symlink_path} -> %{DATA:symlink_target}\|%{NUMBER:block_count}\|%{DATA:permissions}\|%{NUMBER:uid}\|%{NUMBER:gid}\|%{NUMBER:size}\|%{NUMBER:mtime}\|%{NUMBER:ctime}\|%{NUMBER:atime}\|%{NUMBER:btime}'),
    Grok(r'%{NUMBER:inode}\|%{DATA:path}\|%{NUMBER:block_count}\|%{DATA:permissions}\|%{NUMBER:uid}\|%{NUMBER:gid}\|%{NUMBER:size}\|%{NUMBER:mtime}\|%{NUMBER:ctime}\|%{NUMBER:atime}'),
    Grok(r'%{NUMBER:inode}\|%{DATA:symlink_path} -> %{DATA:symlink_target}\|%{NUMBER:block_count}\|%{DATA:permissions}\|%{NUMBER:uid}\|%{NUMBER:gid}\|%{NUMBER:size}\|%{NUMBER:mtime}\|%{NUMBER:ctime}\|%{NUMBER:atime}')
]


class StatLogParser:
    fields = [
        "inode", "path", "block_count", "permissions",
        "uid", "gid", "size",
        "mtime", "ctime", "atime", "btime"
    ]

    def __init__(self, bodyfile_path, hostname, uac_log_path, output_dir, tracker_queue):
        self.bodyfile_path = Path(bodyfile_path)
        self.hostname = hostname
        self.uac_log_path = uac_log_path
        self.output_path = Path(output_dir) / f"output_{hostname}.jsonl"
        self.tracker_queue = tracker_queue

    @staticmethod
    def to_iso(ts):
        try:
            from datetime import timezone
            return datetime.fromtimestamp(int(ts), timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
        except:
            return None

    def process(self):
        try:
            results = []
            total_lines = 0
            success_count = 0
            fail_count = 0
            with self.bodyfile_path.open("r", encoding="utf-8", errors="ignore") as infile:
                for line in infile:
                    total_lines += 1
                    matched = False
                    for grok in GROK_PATTERNS:
                        match = grok.match(line.strip())
                        if match:
                            # Handle symlink
                            if "symlink_path" in match and "symlink_target" in match:
                                path = match["symlink_target"]
                                symlink_path = match["symlink_path"]
                            else:
                                path = match.get("path")
                                symlink_path = None

                            # Handle missing btime
                            btime = match.get("btime")

                            base_event = {
                                "target": {
                                    "file": {
                                        "full_path": path,
                                        "permissions": match["permissions"],
                                        "owner": {
                                            "user_id": match["uid"],
                                            "group_id": match["gid"]
                                        },
                                        "size": int(match["size"]),
                                        "inode": match["inode"],
                                        "block_count": match["block_count"],
                                        "accessed_time": self.to_iso(match["atime"]),
                                        "modified_time": self.to_iso(match["mtime"]),
                                        "metadata_change_time": self.to_iso(match["ctime"]),
                                        "created_time": self.to_iso(btime) if btime else None
                                    }
                                },
                                "metadata": {
                                    "event_type": "FILE_READ",
                                    "product_name": "Linux",
                                    "vendor_name": "Juniper",
                                    "log_type": "Host"
                                },
                                "principal": {
                                    "process": {
                                        "command_line": "stat"
                                    },
                                    "host_name": self.hostname
                                },
                                "intermediary": {"namespace": "UnixArtifactCollector"}
                            }
                            if symlink_path:
                                base_event["additional"] = {"symlink": symlink_path}
                            results.append(base_event)
                            success_count += 1
                            matched = True
                            break  # Only use the first matching pattern
                    if not matched:
                        fail_count += 1

            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            with self.output_path.open("w", encoding="utf-8") as outfile:
                outfile.write('[\n')
                for idx, item in enumerate(results):
                    json.dump(item, outfile)
                    if idx < len(results) - 1:
                        outfile.write(',\n')
                outfile.write('\n]')

            # Determine where to append the output file path
            evidence_dir = self.output_path.parent.parent / 'Evidence'
            uploader_txt = evidence_dir / 'uploader.txt'
            target_path = uploader_txt  # default
            if uploader_txt.exists():
                with uploader_txt.open('r', encoding='utf-8') as upf:
                    first_line = upf.readline().strip()
                    if first_line:
                        target_path = Path(first_line)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with target_path.open('a', encoding='utf-8') as upf:
                upf.write(str(self.output_path.resolve()) + '\n')

            print(f"[✓] Parsed {success_count} entries for host: {self.hostname}")
            print(f"[✓] Output saved to: {self.output_path}")
            print(f"[•] Stats for host {self.hostname}: Total lines: {total_lines}, Success: {success_count}, Fail: {fail_count}, Success rate: {success_count/total_lines*100 if total_lines else 0:.2f}%")
            print(f"[DEBUG] Putting record in tracker_queue for host: {self.hostname}")
            self.tracker_queue.put({
                "hostname": self.hostname,
                "uac_log_path": str(self.uac_log_path),
                "output_file": str(self.output_path),
                "total_lines": total_lines,
                "success_count": success_count,
                "fail_count": fail_count,
                "success_rate": f"{success_count/total_lines*100 if total_lines else 0:.2f}"
            })
        except Exception as e:
            print(f"[!] Failed to process {self.hostname}: {e}")


def load_tracker(tracker_path):
    if not tracker_path.exists():
        return set()
    with tracker_path.open("r", encoding="utf-8") as f:
        return set(
            (row["hostname"], row["uac_log_path"])
            for row in csv.DictReader(f)
        )


def update_tracker(tracker_path, queue, total):
    print(f"[DEBUG] Entered update_tracker with tracker_path: {tracker_path}")
    processed = []
    while len(processed) < total:
        record = queue.get()
        if record == "DONE":
            break
        processed.append(record)

    rows = []
    if tracker_path.exists():
        with tracker_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows.extend(reader)

    # Dynamically determine all fieldnames
    extra_fields = ["total_lines", "success_count", "fail_count", "success_rate"]
    fieldnames = ["hostname", "uac_log_path", "output_file"] + extra_fields
    # If there are more fields in the processed records, add them
    for rec in processed:
        for k in rec:
            if k not in fieldnames:
                fieldnames.append(k)

    print(f"[DEBUG] Processed records to write: {processed}")
    print(f"[DEBUG] Writing tracker CSV to: {tracker_path}")
    with tracker_path.open("w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        rows.extend(processed)
        for row in rows:
            writer.writerow(row)

    print(f"[✓] Tracker updated: {tracker_path}")


def find_evidence_records(evidence_csv_path):
    with evidence_csv_path.open("r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def worker(args):
    parser = StatLogParser(*args)
    parser.process()


def main():
    base_dir = Path(__file__).resolve().parent
    evidence_dir = base_dir.parent / "Evidence"
    output_dir = base_dir.parent / "output"
    tracker_file = evidence_dir / "body_file_tracker.csv"
    evidence_csv = evidence_dir / "evidence_records.csv"

    if not evidence_csv.exists():
        print(f"[!] evidence_records.csv not found at {evidence_csv}")
        return

    all_records = find_evidence_records(evidence_csv)
    already_done = load_tracker(tracker_file)
    to_process = []

    manager = Manager()
    tracker_queue = manager.Queue()

    for record in all_records:
        hostname = record["hostname"]
        uac_log_path = record["uac_log_path"]
        base_path = Path(record["base_path"])
        bodyfile_path = base_path / "bodyfile" / "bodyfile.txt"
        if not bodyfile_path.exists():
            print(f"[!] bodyfile.txt not found for host: {hostname} in {base_path}")
            continue
        if (hostname, uac_log_path) in already_done:
            print(f"[•] Already processed: {hostname}")
            continue
        to_process.append((bodyfile_path, hostname, uac_log_path, output_dir, tracker_queue))

    if not to_process:
        print("[✓] Nothing to process.")
        return

    total = len(to_process)

    with Pool(min(cpu_count(), total)) as pool:
        pool.map(worker, to_process)

    tracker_queue.put("DONE")
    print(f"[DEBUG] Calling update_tracker with tracker_file: {tracker_file}")
    update_tracker(tracker_file, tracker_queue, total)
    print(f"[DEBUG] update_tracker finished for tracker_file: {tracker_file}")


if __name__ == "__main__":
    main()
