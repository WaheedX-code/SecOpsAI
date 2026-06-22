"""
SecOpsAI — Telemetry Ingestion Pipeline
Loads, validates, hashes, and streams network flow data
"""

import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Iterator

import pandas as pd
import redis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("secopsai.ingestion")


# ----- Hash Chaining (Tamper-Evident Logging) ───────────────────────────────────

class HashChain:
    """
    Append-only hash chain for tamper-evident event logging.
    Each record's hash includes the previous hash — 
    tampering with any record breaks the chain.
    """

    def __init__(self, chain_file: str = "data/processed/chain.jsonl"):
        self.chain_file = Path(chain_file)
        self.chain_file.parent.mkdir(parents=True, exist_ok=True)
        self.previous_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.chain_file.exists():
            return "GENESIS"
        with open(self.chain_file, "rb") as f:
            # Read last line efficiently
            try:
                f.seek(-2, os.SEEK_END)
                while f.read(1) != b"\n":
                    f.seek(-2, os.SEEK_CUR)
            except OSError:
                f.seek(0)
            last_line = f.readline().decode()
            if last_line:
                return json.loads(last_line)["hash"]
        return "GENESIS"

    def append(self, record: dict) -> str:
        """Append a record to the chain. Returns the record hash."""
        record_str = json.dumps(record, sort_keys=True)
        combined = f"{self.previous_hash}:{record_str}"
        record_hash = hashlib.sha256(combined.encode()).hexdigest()

        chain_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "previous_hash": self.previous_hash,
            "hash": record_hash,
            "record": record
        }

        with open(self.chain_file, "a") as f:
            f.write(json.dumps(chain_entry) + "\n")

        self.previous_hash = record_hash
        return record_hash

    def verify(self) -> bool:
        """Verify the entire chain — detect any tampering."""
        if not self.chain_file.exists():
            return True

        prev_hash = "GENESIS"
        with open(self.chain_file) as f:
            for i, line in enumerate(f):
                entry = json.loads(line)
                if entry["previous_hash"] != prev_hash:
                    logger.error(f"Chain broken at record {i}")
                    return False
                combined = f"{prev_hash}:{json.dumps(entry['record'], sort_keys=True)}"
                expected = hashlib.sha256(combined.encode()).hexdigest()
                if entry["hash"] != expected:
                    logger.error(f"Hash mismatch at record {i}")
                    return False
                prev_hash = entry["hash"]

        logger.info("Hash chain verified — no tampering detected")
        return True


# ─── Schema Validation ────────────────────────────────────────────────────────

# Expected feature bounds — anything outside is flagged as potential adversarial injection
FEATURE_BOUNDS = {
    "duration": (0, 86400),          # seconds — max 24h flow
    "packet_count": (1, 1_000_000),
    "byte_count": (0, 10_000_000_000),
    "flow_bytes_per_sec": (0, 1_000_000_000),
    "flow_packets_per_sec": (0, 1_000_000),
    "entropy": (0.0, 8.0),           # Shannon entropy — max 8 bits
}

def validate_record(record: dict) -> tuple[bool, list[str]]:
    """
    Validate a single flow record against expected bounds.
    Returns (is_valid, list_of_violations).
    """
    violations = []
    for field, (low, high) in FEATURE_BOUNDS.items():
        if field in record:
            val = record[field]
            if not (low <= val <= high):
                violations.append(f"{field}={val} out of bounds [{low}, {high}]")
    return len(violations) == 0, violations


# ─── CICIDS 2017 Loader ───────────────────────────────────────────────────────

CICIDS_LABEL_MAP = {
    "BENIGN": 0,
    "Bot": 1,              # C2 beaconing
    "Infiltration": 2,     # Lateral movement
    "Web Attack": 3,
    "DoS": 4,
    "DDoS": 4,
    "FTP-Patator": 5,
    "SSH-Patator": 5,
    "PortScan": 6,
}

def load_cicids(data_dir: str = "data/raw/cicids2017") -> pd.DataFrame:
    """Load and merge all CICIDS 2017 CSV files."""
    data_path = Path(data_dir)
    csv_files = list(data_path.glob("**/*.csv"))

    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    logger.info(f"Loading {len(csv_files)} CICIDS 2017 files...")

    dfs = []
    for f in csv_files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()  # CICIDS has trailing spaces in column names
        dfs.append(df)
        logger.info(f"  Loaded {f.name}: {len(df):,} records")

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"Total CICIDS records: {len(combined):,}")
    return combined


def load_unswnb15(data_dir: str = "data/raw/unswnb15") -> pd.DataFrame:
    """Load UNSW-NB15 dataset."""
    data_path = Path(data_dir)
    csv_files = list(data_path.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    logger.info(f"Loading {len(csv_files)} UNSW-NB15 files...")
    dfs = [pd.read_csv(f, low_memory=False) for f in csv_files]
    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"Total UNSW-NB15 records: {len(combined):,}")
    return combined


# ─── Redis Stream Producer ────────────────────────────────────────────────────

class StreamProducer:
    """
    Publishes validated, hashed flow records to Redis Streams.
    Consumer (ML pipeline) reads from the same stream.
    """

    def __init__(self, stream_name: str = "secopsai:flows",
                 redis_url: str = "redis://localhost:6379"):
        self.stream_name = stream_name
        self.client = redis.from_url(redis_url)
        self.chain = HashChain()
        logger.info(f"StreamProducer connected — stream: {stream_name}")

    def publish(self, records: Iterator[dict], max_records: int = None):
        published = 0
        rejected = 0

        for record in records:
            # Validate bounds
            is_valid, violations = validate_record(record)
            if not is_valid:
                logger.warning(f"Record rejected — violations: {violations}")
                rejected += 1
                continue

            # Append to hash chain
            record_hash = self.chain.append(record)
            record["_hash"] = record_hash

            # Publish to Redis Stream
            self.client.xadd(
                self.stream_name,
                {k: str(v) for k, v in record.items()}
            )
            published += 1

            if max_records and published >= max_records:
                break

        logger.info(f"Published: {published:,} | Rejected: {rejected:,}")
        return published, rejected


# ─── Adversarial Injection Test ───────────────────────────────────────────────

def test_adversarial_injection(producer: StreamProducer):
    """
    STRIDE T3 / T5 Test Case:
    Simulate an attacker injecting malformed/adversarial records
    into the pipeline to test validation controls.
    """
    logger.info("=== Adversarial Injection Test ===")

    adversarial_samples = [
        # Out-of-bounds entropy (impossible value)
        {"duration": 10, "packet_count": 100, "byte_count": 5000,
         "flow_bytes_per_sec": 500, "flow_packets_per_sec": 10, "entropy": 99.9},

        # Negative packet count (malformed record)
        {"duration": 5, "packet_count": -1, "byte_count": 100,
         "flow_bytes_per_sec": 20, "flow_packets_per_sec": -1, "entropy": 3.2},

        # Impossibly high throughput
        {"duration": 1, "packet_count": 999999999, "byte_count": 999999999999,
         "flow_bytes_per_sec": 999999999999, "flow_packets_per_sec": 999999999,
         "entropy": 7.9},
    ]

    published, rejected = producer.publish(iter(adversarial_samples))

    assert rejected == 3, f"Expected 3 rejections, got {rejected}"
    assert published == 0, f"Expected 0 published, got {published}"

    logger.info("✅ Adversarial injection test PASSED — all malformed records rejected")


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Verify hash chain integrity on startup
    chain = HashChain()
    chain.verify()

    # Load data
    cicids_df = load_cicids()

    # Run adversarial injection test first
    producer = StreamProducer()
    test_adversarial_injection(producer)

    logger.info("Ingestion pipeline ready.")
