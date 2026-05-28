"""Implements FolderEntry class."""

import dataclasses
import json
import logging
import os

import pyarrow
import pyarrow.parquet

# TODO: Ratify this key
PARQUET_METADATA_KEY = b"https://ns.dataone.org/types/FolderEntries"
"""Key in parquet file metadata pointing to dict of properties."""
PARQUET_READ_BATCH_SIZE = 10000
"""Number of entries to read at a time from FolderEntries parquet file."""
PATH_DELIMITER = "⫽"


def get_logger():
    return logging.getLogger("FolderEntry")


def split_pidpath(pidpath: str, delimiter: str = PATH_DELIMITER) -> list[str]:
    pathpid = pidpath.strip(delimiter)
    parts = pathpid.split(delimiter)
    return parts


def join_pidpath(path: list[str], delimiter: str = PATH_DELIMITER) -> str:
    # remove "", strings with only white space
    cleaned = [s.strip() for s in path]
    return delimiter.join(list(filter(str.strip, cleaned)))


@dataclasses.dataclass
class FolderEntry:
    """Represents a file or folder entry in a folder manifest."""

    name: str
    """The name portion of the path (not full path) for the file or folder."""
    cid: str
    """The content hash (CID) for the entry."""
    is_file: bool  # True for file, False for Folder
    """The type of manifest entry: False for folder, True for file."""
    size: int = 0
    """Size of the file in bytes or number of entries for folders."""
    formatid: str | None = None
    """Optional format identifier for files."""

    def __repr__(self) -> str:
        # Representation of a FolderEntry
        return json.dumps(
            {
                "cid": self.cid,
                "is_file": self.is_file,
                "name": self.name,
                "size": self.size,
                "formatid": self.formatid,
            },
            ensure_ascii=False,
        )

    @classmethod
    def parquet_schema(cls):
        return pyarrow.schema(
            (
                ("cid", pyarrow.string()),
                ("is_file", pyarrow.bool_()),
                ("name", pyarrow.string()),
                ("size", pyarrow.int64()),
                ("formatid", pyarrow.string()),
            )
        )


class FolderEntries(list[FolderEntry]):
    def entry_by_name(self, name) -> FolderEntry | None:
        """Find the entry with name that matches."""
        for entry in self:
            if entry.name == name:
                return entry
        return None

    def to_parquet(self, pq_path: str, pid: str, writer_args: dict = {}) -> int:
        """Writes the list of folder entries to a parquet file.

        See also: https://arrow.apache.org/docs/python/generated/pyarrow.parquet.write_table.html

        #TODO: There are quite a few options for tweaking the written parquet file,
        # e.g. with respect to column sorting, a UI may prefer sorting by type or formatid

        args:
            pq_path: path to destination parquet file
            pid: PID+path used to create this folder.
            writer_args: optional dict of arguments for the parquet writer.
        """
        # Add some metadata to the parquet file to help identify it as a list of FolderEntries
        pq_metadata = {
            "type": "FolderEntries",
            "version": "1.0",
            "pid": pid,
        }
        pq_schema = FolderEntry.parquet_schema()
        metadata_bytes = json.dumps(pq_metadata).encode("utf-8")
        table = pyarrow.Table.from_pylist(
            [dataclasses.asdict(entry) for entry in self],
            schema=pq_schema,
        )
        table = table.replace_schema_metadata({PARQUET_METADATA_KEY: metadata_bytes})
        pyarrow.parquet.write_table(table, pq_path, **writer_args)
        return os.path.getsize(pq_path)

    @classmethod
    def from_parquet(cls, pq_path) -> "FolderEntries":
        """Create an instance of FolderEntries from a parquet source."""
        pq_metadata = pyarrow.parquet.read_metadata(pq_path)
        try:
            metadata = json.loads(pq_metadata.metadata[PARQUET_METADATA_KEY].decode())
            _ = metadata["version"]
        except KeyError:
            raise ValueError(f"File {pq_path} is not a FolderEntry list.")

        pq_file = pyarrow.parquet.ParquetFile(pq_path)
        entries = cls()
        for batch in pq_file.iter_batches(batch_size=PARQUET_READ_BATCH_SIZE):
            for row in batch.to_pylist():
                entries.append(
                    FolderEntry(
                        name=row["name"],
                        cid=row["cid"],
                        is_file=row["is_file"],
                        size=row["size"],
                        formatid=row["formatid"],
                    )
                )
        return entries


def is_folder(path: str) -> bool:
    """Test if the target of the path is a folder object.

    This test is fast, reading just a few bytes, but there
    is of course associated file IO, so avoid use in loops etc.
    """
    try:
        pq_metadata = pyarrow.parquet.read_metadata(path)
        try:
            metadata = json.loads(pq_metadata.metadata[PARQUET_METADATA_KEY].decode())
            _ = metadata["version"]
        except KeyError:
            return False
        return True
    except Exception:
        pass
    return False
