import argparse, os, json, struct, hashlib, time, tempfile, zlib, shutil
from datetime import datetime, timezone

MAGIC = b'CTNRv1__'  # 8 bytes
MAGIC_LEN = len(MAGIC)
TAIL_HDR = MAGIC_LEN + 8
DEFAULT_CHUNK = 1024 * 1024
STATUS_THROTTLE_SECS = 1.0


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def human_size(n):
    for unit in ("B","KiB","MiB","GiB","TiB"):
        if n < 1024.0:
            return f"{n:.2f}{unit}"
        n /= 1024.0
    return f"{n:.2f}PiB"


# index loaders
def load_index_file(index_path):
    # Accept full JSON object, JSON array, or NDJSON
    with open(index_path, "rb") as f:
        data = f.read()
    return parse_index_bytes(data)


def parse_index_bytes(data_bytes):
    # try JSON
    try:
        s = data_bytes.decode("utf-8")
    except Exception:
        raise ValueError("Index bytes are not valid UTF-8")
    s_strip = s.lstrip()
    if not s_strip:
        return {"version": 1, "entries": []}
    first = s_strip[0]
    try:
        if first == '[' or first == '{':
            obj = json.loads(s)
            if isinstance(obj, dict) and "entries" in obj:
                return obj
            elif isinstance(obj, list):
                return {"version": 1, "entries": obj}
            else:
                return {"version": 1, "entries": list(obj)}
    except Exception:
        # fallthrough to NDJSON
        pass
    # NDJSON fallback
    entries = []
    for line in s.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            # skip unparsable lines
            continue
    return {"version": 1, "entries": entries}


# trailer/embedded index
def find_embedded_index(container_path, lookback=4 * 1024 * 1024):
    """Search the last `lookback` bytes for the MAGIC trailer and return parsed index or None."""
    size = os.path.getsize(container_path)
    if size < TAIL_HDR:
        return None
    read_len = min(size, lookback)
    with open(container_path, "rb") as f:
        f.seek(size - read_len)
        tail = f.read(read_len)
    pos = tail.rfind(MAGIC)
    if pos == -1:
        return None
    trailer_start = size - read_len + pos
    with open(container_path, "rb") as f:
        f.seek(trailer_start + MAGIC_LEN)
        raw = f.read(8)
        if len(raw) != 8:
            raise IOError("Failed to read embedded index length")
        L = struct.unpack("<Q", raw)[0]
        # sanity-check length
        if L == 0 or L > size:
            raise IOError(f"Embedded index length appears invalid: {L}")
        f.seek(trailer_start + TAIL_HDR)
        idx_bytes = f.read(L)
        if len(idx_bytes) != L:
            raise IOError("Failed to read full embedded index bytes")
    return parse_index_bytes(idx_bytes)


# status writers (same as create)
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


def make_logger(verbosity):
    def log(level, *msgs, end="\n"):
        if verbosity >= level:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{ts}] {' '.join(str(m) for m in msgs)}", end=end, flush=True)
    return log


# helpers
class LimitedReader:
    """A simple reader wrapper around a file that reads up to `limit` bytes."""
    def __init__(self, f, limit):
        self.f = f
        self.remaining = limit
    def read(self, n=-1):
        if self.remaining <= 0:
            return b""
        if n is None or n < 0:
            n = self.remaining
        else:
            n = min(n, self.remaining)
        data = self.f.read(n)
        if not data:
            return b""
        self.remaining -= len(data)
        return data


def extract_one_entry(container_f, entry, outdir, chunk, verify_existing, skip_existing, dry_run, log):
    rel = entry["relpath"]
    outpath = os.path.join(outdir, rel)
    os.makedirs(os.path.dirname(outpath), exist_ok=True)

    # skip-existing short-circuit: same size
    if skip_existing and os.path.exists(outpath):
        try:
            if os.path.getsize(outpath) == entry.get("orig_size", -1):
                if verify_existing and not entry.get("compressed"):
                    # compute sha of existing final file and compare with entry['sha256'] (only valid when not compressed)
                    h = hashlib.sha256()
                    with open(outpath, "rb") as ef:
                        while True:
                            b = ef.read(chunk)
                            if not b: break
                            h.update(b)
                    if h.hexdigest() == entry.get("sha256"):
                        log(1, f"Skipping existing verified file: {rel}")
                        return True, "skipped"
                    else:
                        log(1, f"Existing file sha mismatch; re-extracting: {rel}")
                else:
                    log(1, f"Skipping existing file (size match): {rel}")
                    return True, "skipped"
        except Exception:
            pass

    # Prepare temp final path in same dir for atomic replace
    fd_final, tmp_final = tempfile.mkstemp(prefix=os.path.basename(outpath) + ".tmp.final.", dir=os.path.dirname(outpath))
    os.close(fd_final)

    payload_size = entry["payload_size"]
    sha = hashlib.sha256()

    try:
        if dry_run:
            # just advance the file pointer in container
            remaining = payload_size
            while remaining > 0:
                toread = min(chunk, remaining)
                chunkb = container_f.read(toread)
                if not chunkb:
                    raise IOError("Unexpected EOF while dry-run consuming payload")
                sha.update(chunkb)
                remaining -= len(chunkb)
            # no file written
            try:
                os.remove(tmp_final)
            except Exception:
                pass
            return True, "dry-run"

        # Normal extraction path
        if not entry.get("compressed"):
            # stream payload directly to tmp_final while computing sha
            with open(tmp_final, "wb") as outf:
                remaining = payload_size
                while remaining > 0:
                    toread = min(chunk, remaining)
                    chunkb = container_f.read(toread)
                    if not chunkb:
                        raise IOError("Unexpected EOF while extracting payload")
                    sha.update(chunkb)
                    outf.write(chunkb)
                    remaining -= len(chunkb)
                outf.flush(); os.fsync(outf.fileno())
        else:
            # compressed payload: stream compressed bytes through a zlib decompressobj to tmp_final
            # while computing sha on compressed bytes
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip header
            with open(tmp_final, "wb") as outf:
                remaining = payload_size
                while remaining > 0:
                    toread = min(chunk, remaining)
                    chunkb = container_f.read(toread)
                    if not chunkb:
                        raise IOError("Unexpected EOF while extracting compressed payload")
                    sha.update(chunkb)
                    # decompress chunk (may produce empty output until headers available)
                    try:
                        dec = decompressor.decompress(chunkb)
                        if dec:
                            outf.write(dec)
                    except Exception as e:
                        raise IOError(f"Decompression error for {rel}: {e}")
                    remaining -= len(chunkb)
                # flush any remaining decompressed bytes
                try:
                    tail = decompressor.flush()
                    if tail:
                        outf.write(tail)
                except Exception:
                    raise
                outf.flush(); os.fsync(outf.fileno())

        # verify payload sha
        if sha.hexdigest() != entry.get("sha256"):
            try:
                os.remove(tmp_final)
            except Exception:
                pass
            raise IOError(f"sha mismatch for payload of {rel} (expected {entry.get('sha256')[:12]}, got {sha.hexdigest()[:12]})")

        # atomic replace
        try:
            os.replace(tmp_final, outpath)
        except Exception:
            # fallback copy
            with open(tmp_final, "rb") as sf, open(outpath, "wb") as df:
                while True:
                    b = sf.read(chunk)
                    if not b: break
                    df.write(b)
                df.flush(); os.fsync(df.fileno())
            try:
                os.remove(tmp_final)
            except Exception:
                pass

        # fsync parent dir
        try:
            dfd = os.open(os.path.dirname(outpath) or ".", os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            except Exception:
                pass
            finally:
                os.close(dfd)
        except Exception:
            pass

        return True, "ok"

    except Exception as e:
        # remove tmp_final on error
        try:
            os.remove(tmp_final)
        except Exception:
            pass
        raise


# main

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--container", required=True)
    p.add_argument("--index", default=None)
    p.add_argument("--outdir", required=True)
    p.add_argument("--lookback", type=int, default=128*1024*1024, help="bytes to search from end of file for MAGIC trailer")
    p.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK)
    p.add_argument("--tqdm", action="store_true", help="show tqdm progress (if installed)")
    p.add_argument("--status-file", default=None)
    p.add_argument("--status-format", choices=("kv","json"), default="kv")
    p.add_argument("--skip-existing", action="store_true", help="skip extraction when target file exists with same size (fast)")
    p.add_argument("--verify-existing", action="store_true", help="verify existing target by SHA (slower); implies --skip-existing")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    container_path = args.container
    index_path = args.index
    outdir = args.outdir
    lookback = args.lookback
    chunk = max(1024, args.chunk_size)
    use_tqdm = args.tqdm
    status_path = args.status_file
    status_format = args.status_format
    skip_existing = args.skip_existing or args.verify_existing
    verify_existing = args.verify_existing
    verbosity = args.verbose
    dry_run = args.dry_run

    log = make_logger(verbosity)

    # load index (embedded or external)
    index = None
    if index_path and os.path.exists(index_path):
        index = load_index_file(index_path)
        log(1, f"Loaded index from {index_path} ({len(index.get('entries', []))} entries)")
    else:
        index = find_embedded_index(container_path, lookback=lookback)
        if index is None:
            raise SystemExit("No index found (embedded) and no index file provided.")
        log(1, f"Loaded embedded index ({len(index.get('entries', []))} entries)")

    entries = index.get('entries', [])
    total_files = len(entries)
    total_bytes = sum(e.get('payload_size', 0) for e in entries)

    # tqdm init
    bar = None
    use_tqdm_real = False
    if use_tqdm:
        try:
            from tqdm import tqdm as _tqdm
            use_tqdm_real = True
            bar = _tqdm(total=total_files, unit=" files", mininterval=1.0, leave=True)
        except Exception:
            log(1, "tqdm not available; falling back to periodic status output.")
            bar = object()

    # status init
    status = {
        "start_time": now_iso(),
        "start_ts": time.time(),
        "total_files": total_files,
        "total_bytes": total_bytes,
        "processed_files": 0,
        "bytes_extracted": 0,
        "current_file": "",
        "current_file_bytes": 0,
        "speed_bps": 0,
        "eta_seconds": "",
        "status": "running"
    }
    last_status_write = 0.0

    processed_files = 0
    bytes_extracted = 0
    interrupted = False

    with open(container_path, "rb") as cf:
        try:
            for entry in entries:
                rel = entry["relpath"]
                offset = entry["offset"]
                payload_size = entry["payload_size"]
                log(2, f"Extracting entry: {rel} (offset={offset} size={payload_size})")

                cf.seek(offset)

                status["current_file"] = rel
                status["current_file_bytes"] = 0
                nowt = time.time()
                if status_path and (nowt - last_status_write > STATUS_THROTTLE_SECS):
                    status.update({
                        "processed_files": processed_files,
                        "bytes_extracted": bytes_extracted,
                    })
                    if status_format == "kv":
                        safe_write_status_kv(status_path, status)
                    else:
                        safe_write_status_json(status_path, status)
                    last_status_write = nowt

                # existing target logic
                outpath = os.path.join(outdir, rel)
                if skip_existing and os.path.exists(outpath):
                    try:
                        if os.path.getsize(outpath) == entry.get("orig_size", -1):
                            if verify_existing and not entry.get("compressed"):
                                # compute sha of existing final file and compare
                                h_exist = hashlib.sha256()
                                with open(outpath, "rb") as ef:
                                    while True:
                                        b = ef.read(chunk)
                                        if not b: break
                                        h_exist.update(b)
                                if h_exist.hexdigest() == entry.get("sha256"):
                                    log(1, f"Skipping existing verified file: {rel}")
                                    processed_files += 1
                                    if bar is not None and use_tqdm_real:
                                        bar.update(1)
                                    continue
                                else:
                                    log(1, f"Existing file sha mismatch; re-extracting: {rel}")
                            else:
                                log(1, f"Skipping existing file (size match): {rel}")
                                processed_files += 1
                                if bar is not None and use_tqdm_real:
                                    bar.update(1)
                                continue
                    except Exception:
                        pass

                ok, why = extract_one_entry(cf, entry, outdir, chunk, verify_existing, skip_existing, dry_run, log)
                if not ok:
                    raise IOError(f"Failed to extract {rel}: {why}")

                processed_files += 1
                bytes_extracted += payload_size

                # update status and tqdm
                nowt = time.time()
                elapsed = nowt - status.get("start_ts", nowt)
                status["processed_files"] = processed_files
                status["bytes_extracted"] = bytes_extracted
                status["speed_bps"] = int(bytes_extracted / elapsed) if elapsed > 0 else 0
                if total_bytes and status["speed_bps"]:
                    remaining = max(0, total_bytes - bytes_extracted)
                    status["eta_seconds"] = int(remaining / status["speed_bps"]) if status["speed_bps"] else ""

                if status_path and (nowt - last_status_write > STATUS_THROTTLE_SECS):
                    if status_format == "kv":
                        safe_write_status_kv(status_path, status)
                    else:
                        safe_write_status_json(status_path, status)
                    last_status_write = nowt

                if (bar is not None) and use_tqdm_real:
                    try:
                        bar.update(1)
                    except Exception:
                        pass
                elif (bar is not None) and (not use_tqdm_real):
                    if processed_files % 1000 == 0:
                        log(1, f"Extracted {processed_files}/{total_files} files, {human_size(bytes_extracted)}")

        except KeyboardInterrupt:
            log(0, "Interrupted by user. Exiting.")
            interrupted = True
        finally:
            if (bar is not None) and use_tqdm_real:
                try:
                    bar.close()
                except Exception:
                    pass

    status["status"] = "interrupted" if interrupted else "finished"
    status["processed_files"] = processed_files
    status["bytes_extracted"] = bytes_extracted
    status["finished_time"] = now_iso()
    if status_path:
        if status_format == "kv":
            safe_write_status_kv(status_path, status)
        else:
            safe_write_status_json(status_path, status)

    log(0, "Done.")
    log(0, f"Extracted files: {processed_files}/{total_files}  bytes: {human_size(bytes_extracted)}")


if __name__ == "__main__":
    main()
