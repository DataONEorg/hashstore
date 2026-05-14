"""Implements a multi-process safe logger for generating a cid-pid index.

This implementation writes an NDJSON file with each line containing a json array
with elements:
    [0] timestamp
    [1] cid
    [2] pid

The logging module is used because it is multi-thread and -process safe.

The resulting ndjson file can be loaded into duckdb for example with:

    CREATE TABLE pids AS SELECT
        to_timestamp(json[1]::DOUBLE) AS ctime,
        json[2]->> '$' AS cid,
        json[3]->>'$' AS pid
    FROM read_json('pid_index.ndjson');

or create a parquet representation:

    duckdb -c "COPY (SELECT to_timestamp(json[1]::DOUBLE) AS ctime,
    json[2]->> '\\$' AS cid, json[3]->>'\\$' AS pid FROM
    read_json('pid_index.ndjson')) TO 'pid_index.parquet' (FORMAT parquet)"
"""

import json
import logging

from hashstore.basehashstore import PidObserver


class PidIndexFormatter(logging.Formatter):
    def format(self, record) -> str:
        pid_record = (
            record.created,
            record.getMessage().strip(),
            record.pid if hasattr(record, "pid") else None,
        )
        return json.dumps(pid_record)


class PidLogObserver(PidObserver):
    def __init__(self, log_file_name: str | None = None):
        self.logger = logging.getLogger("pid_logger")
        self.logger.handlers.clear()
        self.logger.propagate = False
        if log_file_name is None:
            return
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(log_file_name)
        handler.setFormatter(PidIndexFormatter())
        self.logger.addHandler(handler)

    def update(self, cid: str, pid: str | None = None):
        self.logger.info(cid, extra={"pid": pid})
