import os
import zipfile
import csv
import multiprocessing

class EvidenceProcessor:
    def __init__(self, input_dir, evidence_dir=None):
        self.original_input_dir = os.path.abspath(input_dir)
        if evidence_dir is None:
            self.evidence_dir = os.path.join(os.path.dirname(__file__), 'Evidence')
        else:
            self.evidence_dir = os.path.abspath(evidence_dir)
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.output_csv = os.path.join(self.evidence_dir, 'evidence_records.csv')

    @staticmethod
    def extract_hostname_from_uac_log(uac_log_path):
        try:
            with open(uac_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if 'Hostname:' in line:
                        return line.split('Hostname:')[1].strip()
        except Exception as e:
            print(f"[!] Failed to extract hostname from {uac_log_path}: {e}")
        return None

    def unzip_all_in_dir(self, root_dir=None):
        if root_dir is None:
            root_dir = self.original_input_dir
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                if filename.lower().endswith('.zip'):
                    zip_path = os.path.join(dirpath, filename)
                    extract_dir = os.path.splitext(zip_path)[0]
                    if not os.path.exists(extract_dir):
                        os.makedirs(extract_dir, exist_ok=True)
                    try:
                        with zipfile.ZipFile(zip_path, 'r') as zf:
                            zf.extractall(extract_dir)
                    except Exception as e:
                        print(f"[!] Failed to extract {zip_path}: {e}")

    def find_uac_logs(self, root_dir=None):
        if root_dir is None:
            root_dir = self.original_input_dir
        uac_logs = []
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                if filename == 'uac.log':
                    uac_logs.append((os.path.join(dirpath, filename), dirpath))
        return uac_logs

    def write_evidence_csv(self, uac_log_records):
        with open(self.output_csv, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['uac_log_path', 'base_path', 'hostname']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for uac_log_path, base_path in uac_log_records:
                hostname = self.extract_hostname_from_uac_log(uac_log_path)
                writer.writerow({
                    'uac_log_path': uac_log_path,
                    'base_path': base_path,
                    'hostname': hostname or 'UNKNOWN'
                })

    @staticmethod
    def process_single_uac(args):
        uac_log_path, base_path, queue = args
        folders_to_search = ['bodyfile', 'hash_executables', 'live_response']
        file_records = []
        seen = set()
        for folder in folders_to_search:
            target_dir = os.path.join(base_path, folder)
            if os.path.isdir(target_dir):
                for root, _, files in os.walk(target_dir):
                    for fname in files:
                        full_path = os.path.join(root, fname)
                        if full_path not in seen:
                            file_records.append({'full_filepath': full_path, 'filename': fname})
                            seen.add(full_path)
        csv_path = os.path.join(base_path, 'evidence_path.csv')
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['full_filepath', 'filename'])
            writer.writeheader()
            for rec in file_records:
                writer.writerow(rec)
        print(f"[✓] Evidence path CSV created: {csv_path}")
        queue.put((uac_log_path, csv_path))

    def update_evidence_csv_with_queue(self, queue, total):
        records = []
        with open(self.output_csv, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or ['uac_log_path', 'base_path', 'hostname']
            for row in reader:
                records.append(row)
        if 'evidence_path' not in fieldnames:
            fieldnames.append('evidence_path')
        updated = 0
        while updated < total:
            msg = queue.get()
            if msg == 'DONE':
                break
            uac_log_path, csv_path = msg
            for row in records:
                if row['uac_log_path'] == uac_log_path:
                    row['evidence_path'] = csv_path
                    break
            updated += 1
        with open(self.output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in records:
                writer.writerow(row)
        print("[✓] evidence_records.csv updated with evidence_path info.")

    def process(self):
        print(f"[•] Unzipping all .zip files in {self.original_input_dir} ...")
        self.unzip_all_in_dir()

        print("[•] Searching for uac.log files...")
        uac_log_records = self.find_uac_logs()
        print(f"[✓] Found {len(uac_log_records)} uac.log files.")
        self.write_evidence_csv(uac_log_records)
        print(f"[✓] Initial CSV written to {self.output_csv}")
        if not uac_log_records:
            return

        max_cores = multiprocessing.cpu_count()
        try:
            user_cores = input(f"Enter cores to use (1-{max_cores}, default={max_cores}): ").strip()
            num_cores = int(user_cores) if user_cores else max_cores
            num_cores = max(1, min(num_cores, max_cores))
        except:
            num_cores = max_cores

        print(f"[•] Using {num_cores} core(s) for parallel evidence processing.")
        queue = multiprocessing.Manager().Queue()
        args_list = [(log, path, queue) for log, path in uac_log_records]

        if num_cores == 1 or len(uac_log_records) == 1:
            for args in args_list:
                self.process_single_uac(args)
            self.update_evidence_csv_with_queue(queue, len(uac_log_records))
        else:
            listener = multiprocessing.Process(target=self.update_evidence_csv_with_queue, args=(queue, len(uac_log_records)))
            listener.start()
            with multiprocessing.Pool(processes=num_cores) as pool:
                pool.map(EvidenceProcessor.process_single_uac, args_list)
            queue.put('DONE')
            listener.join()

# Entrypoint
if __name__ == "__main__":
    input_path = input("Enter path to folder containing evidence: ").strip()
    processor = EvidenceProcessor(input_path)
    processor.process()
