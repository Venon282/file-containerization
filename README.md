# Container tools — `create_container.py` & `extract_container_updated.py`

## Overview

Two scripts:

* `create_container.py` — traverse a source directory and append file payloads into a single **container file** (binary). Writes an NDJSON index alongside the container (or embeds it as a trailer with `--finalize`). Supports compression, batching, resumability and status reporting.

* `extract_container_updated.py` — extract files from a container using either an embedded index (trailer) or an external `.idx` file. Safe extraction: writes to temp files, verifies payload SHA, atomically replaces targets. Supports streamed decompression.

### Trailer / embedded index format

When `create_container.py --finalize` is used the index is appended to the container as a trailer:

* magic 8 bytes: `b'CTNRv1__'`
* 8-byte little-endian unsigned integer: length `L` of the index in bytes
* `L` bytes: raw index bytes (utf-8, NDJSON or JSON)

The extractor looks for that MAGIC in the container tail to find an embedded index.

---

## Quick examples

Create container (balanced configuration — good performance + modest crash window):

```bash
python create_container.py \
  --src /path/to/data \
  --container /path/to/my.container \
  --chunk-size 65536 \
  --fsync-every 1000 \
  --index-batch 1000 \
  --tqdm \
  --finalize
```

Extract container:

```bash
python extract_container_updated.py \
  --container /path/to/my.container \
  --outdir /path/to/outdir \
  --chunk-size 65536 \
  --tqdm
```

If extractor cannot find embedded index (e.g. index is very large), provide the index file:

```bash
python extract_container_updated.py \
  --container /path/to/my.container \
  --index /path/to/my.container.idx \
  --outdir /path/to/outdir
```

---

## `create_container.py` — arguments & explanation

```
usage: create_container.py [options]

Options:
  --src PATH                 Source directory to walk and add to container. Optional when using --finalize-only.
  --container PATH           Path to output container file (required).
  --index PATH               Path to index file (default: <container>.idx).
  --compress                 gzip-compress payloads before writing to container.
  --tqdm                    Show progress bar (if tqdm installed).
  --count                   Just count files (fast).
  --scan-sizes              Walk and compute total bytes and file count (for ETA).
  --print-each              Verbose per-file log.
  --status-file PATH        Write status (kv or json) periodically to this file.
  --status-format {kv,json}
  --fsync-every N           Call fsync on the container every N files (default: 1).
  --index-batch N           Commit N index entries at once (default = fsync-every).
  --chunk-size BYTES        Read/write chunk size (default: 1_048_576). Minimum 1024.
  -v, --verbose             Increase verbosity (repeatable).
  --dry-run                 Do everything except write payloads to the container.
  --finalize                After processing, append the index into the container trailer.
  --finalize-only           Do not scan files; only append the index into the container.
  --remove-index-on-finalize
                            Remove standalone index file after embedding it into the container.
```

### Important behavior & notes

* **`--src` is not required** because the script supports `--finalize-only` (useful when the index already exists and you only want to embed it).
* The index written by the script is NDJSON (one JSON object per line). The index entries currently describe **files** (not empty directories) unless you modify the script to add directory entries.
* An index entry looks like:

  ```json
  {
    "relpath": "path/relative/to/src",
    "offset": 123456,              # byte offset in the container where the payload starts
    "payload_size": 4096,          # stored payload size (maybe compressed)
    "orig_size": 4096,             # original file size before compression
    "sha256": "hex...",            # sha256 of *payload bytes written into the container*
    "compressed": true|false
  }
  ```
* **Trailer embedding**: `--finalize` writes the index bytes to the container with `MAGIC + 8-byte length + index` and fsyncs the container after writing.

  * If your index is very large (hundreds of MB or more) the extractor's default lookback window may not find the trailer. See troubleshooting.
* **Crash-safety & fsync semantics**:

  * `--fsync-every N` controls how often `os.fsync(container)` is called.
  * `--index-batch M` controls how many index entries are buffered before appending to the `.idx` file.
  * **Rule:** to maintain consistency, **always ensure**

    ```
    index_batch >= fsync_every
    ```

    or preferably `index_batch == fsync_every`. If `index_batch < fsync_every`, you may end up with container payloads fsynced but their index not yet persisted — this can make the container inconsistent on restart.
* **`--chunk-size`** is the read/write block size used when copying file payloads; it applies per-file streaming. For millions of very small files a smaller chunk (64 KiB or even 16 KiB) reduces per-operation memory but does not materially change syscall counts for 4 KiB files.
* **Compression**: if `--compress` is enabled the script gzip-compresses each payload. The index `sha256` will be of the **stored** payload (i.e., compressed bytes). This is important for verification semantics.

---

## `extract_container_updated.py` — arguments & explanation

```
usage: extract_container_updated.py [options]

Options:
  --container PATH           Path to container file (required).
  --index PATH               Path to index file (optional). If omitted the script tries to find an embedded index trailer.
  --outdir PATH              Output directory to extract files to (required).
  --chunk-size BYTES        Read/write chunk size (default: 1_048_576). Minimum 1024.
  --tqdm                    Show progress bar (if tqdm installed).
  --status-file PATH        Write status periodically.
  --status-format {kv,json}
  --skip-existing           Skip extraction of a target file if a file with the same size already exists.
  --verify-existing         When skipping, verify existing file by SHA if possible. Implies --skip-existing.
  -v, --verbose             Increase verbosity.
  --dry-run                 Do not write files; just validate and advance stream positions.
```

### Important behavior & notes

* The extractor will **prefer an external index** if `--index` is provided. If not, it attempts to find an embedded index trailer in the container tail.
* The extractor verifies **payload SHA** against the index entry `sha256`. The value in the index is the SHA of the **stored payload** (which may be compressed). The extractor computes that same SHA while streaming the payload out of the container to ensure integrity.
* For **compressed** entries, the index's `sha256` is the SHA of the compressed payload. The extractor:

  * computes the SHA on compressed-bytes as it reads them from the container,
  * streams decompresses them to the output file,
  * then verifies the compressed-bytes SHA — this protects against container corruption.
* `--skip-existing` simply compares existing file size to `orig_size`. If `--verify-existing` is used and the entry is **uncompressed**, the extractor will compute SHA of the existing final file and compare it to the entry `sha256`. (When entry is compressed, the `sha256` is of the compressed payload and thus **not directly comparable** to the final file's SHA; in that case the script re-extracts.)
* **If extractor cannot find the embedded index**, supply `--index <file.idx>` or increase the extractor's lookback in the source code (see Troubleshooting).
* The extractor supports directory entries if present in the index (entry with `"entry_type": "dir"`). If your index does not include directory entries, empty directories will not be recreated.

---

## Recommended settings for heavy workloads (example: 4,000,000 files ~4KiB each)

**Constraints**

* ~4,000,000 × 4 KiB ≈ 16 GiB data.
* NDJSON index ~ 250–300 B/entry → index ~ 1.0–1.2 GiB.

**Suggested configuration (balanced, production)**

```bash
--chunk-size 65536        # 64 KiB, good tradeoff for many tiny files
--fsync-every 1000        # fsync every 1000 files (small crash-loss window)
--index-batch 1000        # must be >= fsync-every (prefer equal)
--tqdm                    # optional
# --compress              # enable only if CPU available and you need space savings
```

**For maximum speed (larger crash window)**

```bash
--fsync-every 5000 --index-batch 5000
```

**For maximum safety (very small loss window)**

```bash
--fsync-every 100 --index-batch 100
```

**Important:** `index_batch` must be `>= fsync_every` (ideally equal) to avoid inconsistent states on crash.

---

## Performance & operational recommendations

* Do not keep the entire index in RAM for millions of files. Use batch append to NDJSON (`--index-batch`), which the script supports.
* Tune `--chunk-size` for your storage: SSD/NVMe can benefit from larger chunk sizes (256 KiB–1 MiB) for throughput; for tiny files chunking mainly affects memory. For many 4KiB files 64 KiB is a reasonable default.
* Test on a sample (10k–100k files) and measure throughput before large runs.
* If you use `--compress` the CPU cost may dominate — benchmark to ensure throughput is acceptable.

---

## Safety and resume behavior

* The creator script keeps a rolling NDJSON index. On restart, it loads the existing index and skips already-processed files (by `relpath`).
* `truncate_to_expected()` will truncate the container to the last known-good end (based on index) to recover from partial writes.
* Because `index_batch` and `fsync_every` determine batching of index writes vs data durability, pick values that match your crash-durability requirements. **Never set `index_batch` smaller than `fsync_every`.**
* Extraction validates payload SHA (`sha256` stored in index), raising an error if mismatch occurs.

---

## Troubleshooting

### `No index found (embedded) and no index file provided`

This happens when the extractor cannot find the trailer MAGIC in the container tail. Common causes:

* The index was embedded but is **larger than the extractor's default lookback window** (default may be e.g. 4 MiB). If your index is tens or hundreds of MB, the trailer is far from the file end relative to the default scan window.

  * **Workarounds:**

    * Pass the external index: `--index /path/to/my.container.idx`.
    * Edit `extract_container_updated.py` and increase the lookback limit in `find_embedded_index(container_path, lookback=...)` (e.g. use `128*1024*1024` or larger), or implement a dynamic search to expand the window.
    * Re-run `create_container.py` with an external index or use smaller index (store fewer metadata fields) — typically not desirable.

### `Missing directories after extract`

* By default the creator may not add explicit directory entries for empty directories. If your tree contains empty dirs and you need them preserved:

  * Modify `create_container.py` to emit `"entry_type": "dir"` entries for directories (and append them to the index before files), and the extractor will create them on extract.
  * The README's code examples and suggestions above show how to add directory entries.

### Corruption or SHA mismatch

* If extractor reports a SHA mismatch for a payload, this indicates container corruption or a bug during creation. Check:

  * Whether the container file was transferred intact.
  * Whether compression flags differed between create/extract (the index records per-entry `compressed` flag).
  * Re-run creation with `--dry-run` to validate behavior or run a subset test.

---

## On preserving extra metadata

Current scripts record `orig_size`, offset, payload_size, sha256 and `compressed` flag. If you need to preserve file permissions, ownership or timestamps, extend the index entries in `create_container.py` (e.g. add `mode`, `mtime`) and apply them in the extractor after creation (`os.chmod`, `os.utime`). Be careful with platform differences (Windows vs POSIX).

---

## Suggested small code improvements (if you want to harden for huge-scale)

* **Make `find_embedded_index` lookback configurable** via `--lookback` in the extractor CLI, or implement dynamic expansion to safely find large appended indices.
* **Add directory indexing** to `create_container.py` so empty dirs are preserved.
* **Avoid keeping `processed` dict for millions of files** — instead:

  * use a lightweight on-disk database (SQLite) for deduping/resume state, or
  * rely on atomic index appends and re-scan the index file in resume mode without caching everything in memory, or
  * stream entries to NDJSON immediately and consult the index file rather than a RAM dict.
* **Optional parallel I/O**: read/compute hashes in worker threads to utilize multi-core CPUs while ensuring ordered writes to the container.

---

## Example end-to-end (Windows-like path style)

Create and finalize:

```powershell
py .\create_container.py --src "D:\Folders\Machine2Learn" `
  --container "D:\Folders\my_container3" `
  --tqdm --fsync-every 1000 --index-batch 1000 --chunk-size 65536 --finalize
```

Extract:

```powershell
py .\extract_container_updated.py --container "D:\Folders\my_container3" --outdir "D:\Folders\m2l" --tqdm
# if extractor fails to find embedded index:
py .\extract_container_updated.py --container "D:\Folders\my_container3" --index "D:\Folders\my_container3.idx" --outdir "D:\Folders\m2l"
```
