import argparse, os, json, hashlib, gzip, tempfile, time, sys, struct
from datetime import datetime, timezone

DEFAULT_CHUNK = 1024 * 1024
STATUS_THROTTLE_SECS = 1.0
MAGIC = b'CTNRv1__'  # 8 bytes

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def human_size(n):
    for unit in ("B","KiB","MiB","GiB","TiB"):
        if n < 1024.0:
            return f"{n:.2f}{unit}"
        n /= 1024.0
    return f"{n:.2f}PiB"

# index helpers: load old JSON array or NDJSON; append NDJSON batches
def load_index(index_path):
    entries = []
    if not os.path.exists(index_path):
        return {"version":1, "entries": []}
    try:
        with open(index_path, "rb") as f:
            data = f.read(4096)
            if not data:
                return {"version":1, "entries": []}
            s = data.lstrip()
            if not s:
                return {"version":1, "entries": []}
            first = chr(s[0])
            if first == '[':
                f.seek(0)
                obj = json.load(f)
                if isinstance(obj, dict) and "entries" in obj:
                    return obj
                elif isinstance(obj, list):
                    return {"version":1, "entries": obj}
                else:
                    return {"version":1, "entries": list(obj)}
            else:
                f.seek(0)
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line.decode("utf-8") if isinstance(line, bytes) else line)
                        entries.append(obj)
                    except Exception:
                        continue
                return {"version":1, "entries": entries}
    except Exception:
        return {"version":1, "entries": []}

def append_index_batch(index_path, batch_entries):
    if not batch_entries:
        return
    os.makedirs(os.path.dirname(index_path) or ".", exist_ok=True)
    with open(index_path, "ab") as f:
        for e in batch_entries:
            line = json.dumps(e, ensure_ascii=False).encode("utf-8") + b"\n"
            f.write(line)
        f.flush()
        os.fsync(f.fileno())

# status writers
def safe_write_status_kv(path, data):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for k, v in data.items():
                f.write(f"{k}={v}\n")
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        pass

def safe_write_status_json(path, data):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        pass

# filesystem helpers
def walk_files(src):
    stack = [src]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for entry in it:
                    # directories: push to stack for later processing
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        yield entry.path
        except PermissionError:
            continue

def truncate_to_expected(container_path, index):
    if not os.path.exists(container_path):
        return
    expected = 0
    for e in index.get("entries", []):
        end = e["offset"] + e["payload_size"]
        if end > expected:
            expected = end
    actual = os.path.getsize(container_path)
    if actual > expected:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] Truncating container from {actual} to {expected}")
        with open(container_path, "r+b") as f:
            f.truncate(expected)
            f.flush(); os.fsync(f.fileno())

# logger
def make_logger(verbosity):
    def log(level, *msgs, end="\n"):
        if verbosity >= level:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{ts}] {' '.join(str(m) for m in msgs)}", end=end, flush=True)
    return log

def now_s():
    return time.time()

class ShaWriter:
    def __init__(self, fileobj, shaobj):
        self.f = fileobj
        self.sha = shaobj
        self.written = 0
    def write(self, data):
        self.sha.update(data)
        self.f.write(data)
        self.written += len(data)
    def flush(self):
        try:
            self.f.flush()
        except Exception:
            pass

# finalize helpers

def _container_looks_finalized(container_path, lookback=1024*1024):
    """Search for MAGIC in the last `lookback` bytes of the container. If found, assume already finalized."""
    try:
        size = os.path.getsize(container_path)
        if size < len(MAGIC) + 8:
            return False
        read_sz = min(size, lookback)
        with open(container_path, "rb") as f:
            f.seek(size - read_sz)
            tail = f.read(read_sz)
        return MAGIC in tail
    except Exception:
        return False


def finalize_container(container_path, index_path, remove_index=False, verbosity=0):
    log = make_logger(verbosity)
    if not os.path.exists(index_path):
        log(0, f"Index file not found: {index_path}")
        return False
    if not os.path.exists(container_path):
        log(0, f"Container file not found: {container_path}")
        return False
    if _container_looks_finalized(container_path):
        log(0, "Container already contains a trailer (MAGIC found in tail). Skipping finalize.")
        return False

    with open(index_path, "rb") as f:
        idx = f.read()
    L = len(idx)
    with open(container_path, "ab") as c:
        c.write(MAGIC)
        c.write(struct.pack("<Q", L))
        c.write(idx)
        c.flush()
        os.fsync(c.fileno())
    log(0, "Finalized container. Embedded index length:", L)
    if remove_index:
        try:
            os.remove(index_path)
            log(1, "Removed standalone index file:", index_path)
        except Exception:
            log(0, "Failed to remove index file (ignored):", index_path)
    return True

# main

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--src", required=False)
    p.add_argument("--container", required=True)
    p.add_argument("--index", default=None)
    p.add_argument("--compress", action="store_true")
    p.add_argument("--tqdm", action="store_true")
    p.add_argument("--count", action="store_true")
    p.add_argument("--scan-sizes", action="store_true")
    p.add_argument("--print-each", action="store_true")
    p.add_argument("--status-file", default=None)
    p.add_argument("--status-format", choices=("kv","json"), default="kv")
    p.add_argument("--fsync-every", type=int, default=1)
    p.add_argument("--index-batch", type=int, default=None,
                   help="how many entries to buffer before committing index (default = fsync-every)")
    p.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK)
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--dry-run", action="store_true")
    # finalize-related options
    p.add_argument("--finalize", action="store_true", help="After processing, append index into container as trailer")
    p.add_argument("--finalize-only", action="store_true", help="Don't scan or append files; only append index into container and exit")
    p.add_argument("--remove-index-on-finalize", action="store_true", help="Remove standalone index file after embedding it into container")

    args = p.parse_args()

    src = args.src
    container_path = args.container
    index_path = args.index if args.index else container_path + ".idx"
    compress = args.compress
    use_tqdm = args.tqdm
    do_count = args.count
    do_scan_sizes = args.scan_sizes
    print_each = args.print_each
    status_path = args.status_file
    status_format = args.status_format
    fsync_every = max(1, args.fsync_every)
    index_batch = args.index_batch if args.index_batch is not None else fsync_every
    if index_batch < fsync_every:
        raise ValueError("--index-batch cannot be smaller than --fsync-every else it have a security risk to valid datas before save them.")
    chunk = max(1024, args.chunk_size)
    verbosity = args.verbose
    dry_run = args.dry_run

    log = make_logger(verbosity)

    # If user asked finalize-only, do that and exit
    if args.finalize_only:
        if dry_run:
            log(0, "Dry-run: would finalize (no changes).")
            return
        ok = finalize_container(container_path, index_path, remove_index=args.remove_index_on_finalize, verbosity=verbosity)
        if not ok:
            sys.exit(1)
        return

    # load index
    index = load_index(index_path)
    initial_entries = len(index.get("entries", []))
    log(1, f"Loaded index entries: {initial_entries}")

    processed = { e["relpath"]: e for e in index["entries"] }

    # optional counts
    total_files = None
    total_bytes = None
    if do_scan_sizes and src:
        log(1, "Scanning for file count and total bytes...")
        total_files = 0; total_bytes = 0
        for pth in walk_files(src):
            total_files += 1
            try:
                total_bytes += os.path.getsize(pth)
            except Exception:
                pass
        log(1, f"Scan: {total_files} files, {human_size(total_bytes)} total")
    elif do_count and src:
        log(1, "Counting files...")
        total_files = 0
        for _ in walk_files(src):
            total_files += 1
        log(1, f"Count: {total_files} files")

    # prepare tqdm if requested
    bar = None
    use_tqdm_real = False
    if use_tqdm and src:
        try:
            from tqdm import tqdm as _tqdm
            use_tqdm_real = True
            bar = _tqdm(total=total_files,
                        unit="files", mininterval=1.0, leave=True, dynamic_ncols=True)
        except Exception:
            # fallback sentinel: we still want periodic messages
            bar = object()
            log(1, "tqdm not available; --tqdm will fall back to periodic status messages.")

    # truncate container to last-known-good end
    truncate_to_expected(container_path, index)

    os.makedirs(os.path.dirname(container_path) or ".", exist_ok=True)
    container = None
    if not dry_run:
        container = open(container_path, "ab")

    start = now_s()
    processed_files = initial_entries
    bytes_written = sum(e["payload_size"] for e in index.get("entries", []))

    status = {
        "start_time": now_iso(),
        "total_files": total_files if total_files is not None else "",
        "total_bytes": total_bytes if total_bytes is not None else "",
        "processed_files": processed_files,
        "bytes_written": bytes_written,
        "current_file": "",
        "current_file_bytes": 0,
        "speed_bps": 0.0,
        "eta_seconds": "",
        "status": "running"
    }
    last_status_write = 0.0
    interrupted = False

    batch_entries = []
    files_since_last_fsync = 0

    try:
        if src:
            for fullpath in walk_files(src):
                # update tqdm/bar for each discovered file (so progress is visible)
                if bar is not None and use_tqdm_real:
                    try:
                        bar.update(1)
                    except Exception:
                        pass
                elif bar is not None and (not use_tqdm_real):
                    # fallback: occasionally print a light progress sample
                    if processed_files % 10000 == 0:
                        log(1, f"Scanned {processed_files} processed files...")

                rel = os.path.relpath(fullpath, src).replace("\\", "/")

                if rel in processed:
                    # skip already processed and continue
                    continue

                if print_each:
                    log(1, f"Appending: {rel}")
                elif verbosity >= 1:
                    log(1, f"[{processed_files+1}] Appending: {rel}")

                sha = hashlib.sha256()
                offset = 0 if dry_run else container.tell()
                payload_size = 0

                status["current_file"] = rel
                status["current_file_bytes"] = 0
                nowt = now_s()
                if status_path and (nowt - last_status_write > STATUS_THROTTLE_SECS):
                    elapsed = nowt - start
                    speed = bytes_written / elapsed if elapsed > 0 else 0.0
                    eta = ""
                    if total_bytes:
                        remaining = max(0, total_bytes - bytes_written)
                        eta = int(remaining / speed) if speed > 0 else ""
                    status.update({
                        "processed_files": processed_files,
                        "bytes_written": bytes_written,
                        "speed_bps": int(speed),
                        "eta_seconds": eta
                    })
                    if status_format == "kv":
                        safe_write_status_kv(status_path, status)
                    else:
                        safe_write_status_json(status_path, status)
                    last_status_write = nowt

                # write payload
                if compress:
                    writer = ShaWriter(container if not dry_run else open(os.devnull, "wb"), sha)
                    with gzip.GzipFile(fileobj=writer, mode="wb") as gz:
                        with open(fullpath, "rb") as fin:
                            while True:
                                chunkb = fin.read(chunk)
                                if not chunkb:
                                    break
                                gz.write(chunkb)
                    payload_size = writer.written
                else:
                    with open(fullpath, "rb") as fin:
                        while True:
                            b = fin.read(chunk)
                            if not b:
                                break
                            sha.update(b)
                            payload_size += len(b)
                            if not dry_run:
                                container.write(b)
                            nowt = now_s()
                            if status_path and (nowt - last_status_write > STATUS_THROTTLE_SECS):
                                elapsed = nowt - start
                                speed = (bytes_written + payload_size) / elapsed if elapsed > 0 else 0.0
                                eta = ""
                                if total_bytes:
                                    remaining = max(0, total_bytes - (bytes_written + payload_size))
                                    eta = int(remaining / speed) if speed > 0 else ""
                                status.update({
                                    "processed_files": processed_files,
                                    "bytes_written": bytes_written + payload_size,
                                    "current_file": rel,
                                    "current_file_bytes": payload_size,
                                    "speed_bps": int(speed),
                                    "eta_seconds": eta
                                })
                                if status_format == "kv":
                                    safe_write_status_kv(status_path, status)
                                else:
                                    safe_write_status_json(status_path, status)
                                last_status_write = nowt

                # buffer entry
                entry = {
                    "relpath": rel,
                    "offset": offset,
                    "payload_size": payload_size,
                    "orig_size": os.path.getsize(fullpath),
                    "sha256": sha.hexdigest(),
                    "compressed": bool(compress)
                }
                batch_entries.append(entry)
                processed[rel] = entry
                processed_files += 1
                bytes_written += payload_size
                files_since_last_fsync += 1

                # commit policy: fsync container every fsync_every (if set) and/or when batch fills
                do_commit = False
                if files_since_last_fsync >= fsync_every:
                    if not dry_run:
                        container.flush(); os.fsync(container.fileno())
                    files_since_last_fsync = 0
                    do_commit = True
                if len(batch_entries) >= index_batch:
                    do_commit = True

                if do_commit and batch_entries:
                    append_index_batch(index_path, batch_entries)
                    batch_entries.clear()
                    nowt = now_s()
                    elapsed = nowt - start
                    speed = bytes_written / elapsed if elapsed > 0 else 0.0
                    eta = ""
                    if total_bytes:
                        remaining = max(0, total_bytes - bytes_written)
                        eta = int(remaining / speed) if speed > 0 else ""
                    status.update({
                        "processed_files": processed_files,
                        "bytes_written": bytes_written,
                        "current_file": "",
                        "current_file_bytes": 0,
                        "speed_bps": int(speed),
                        "eta_seconds": eta
                    })
                    if status_path and (nowt - last_status_write > STATUS_THROTTLE_SECS):
                        if status_format == "kv":
                            safe_write_status_kv(status_path, status)
                        else:
                            safe_write_status_json(status_path, status)
                        last_status_write = nowt

                # feedback
                if print_each:
                    log = make_logger(verbosity)
                    log(1, f"Completed: {rel} ({human_size(payload_size)}) sha={sha.hexdigest()[:12]} offset={offset}")
                elif verbosity >= 2:
                    log = make_logger(verbosity)
                    log(2, f"Completed: {rel} ({human_size(payload_size)}) sha={sha.hexdigest()[:12]} offset={offset}")

    except KeyboardInterrupt:
        log = make_logger(verbosity)
        log(0, "Interrupted by user. Exiting. The last file(s) in the in-memory batch (if any) may be retried on next run.")
        interrupted = True

    finally:
        if batch_entries:
            if not dry_run and container:
                container.flush(); os.fsync(container.fileno())
            append_index_batch(index_path, batch_entries)
            batch_entries.clear()

        if container:
            container.close()

        if bar is not None and use_tqdm_real:
            try:
                bar.close()
            except Exception:
                pass

        status["status"] = "interrupted" if interrupted else "finished"
        status["processed_files"] = processed_files
        status["bytes_written"] = bytes_written
        status["finished_time"] = now_iso()
        elapsed = now_s() - start
        status["speed_bps"] = int(bytes_written / elapsed) if elapsed > 0 else 0
        if status_path:
            if status_format == "kv":
                safe_write_status_kv(status_path, status)
            else:
                safe_write_status_json(status_path, status)

        log = make_logger(verbosity)
        log(0, "Done.")
        log(0, f"Index file (NDJSON): {index_path}")
        log(0, f"Container file: {container_path} (dry-run={dry_run})")
        log(0, f"Processed files: {processed_files}  bytes: {human_size(bytes_written)}")

        # If requested, append the index into the container as a trailer
        if args.finalize and not dry_run:
            finalize_container(container_path, index_path, remove_index=args.remove_index_on_finalize, verbosity=verbosity)

if __name__ == "__main__":
    main()
