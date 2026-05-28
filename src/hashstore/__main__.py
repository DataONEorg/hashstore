import concurrent.futures
import dataclasses
import datetime
import json
import logging
import os
import pathlib
import queue
import re
import sys
import typing

import click
import rich
import rich.tree
import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

import hashstore
import hashstore.filehashstore_exceptions
import hashstore.folderentry

HASHSTORE_FOLDER_NAME = ".hashstore"
DEFAULT_HASHSTORE = f"./{HASHSTORE_FOLDER_NAME}"


def get_logger():
    return logging.getLogger("hs")


def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def enumerate_dict(d):
    for key, value in d.items():
        if isinstance(value, dict):
            for subkey, subvalue in enumerate_dict(value):
                yield f"{key}.{subkey}", subvalue
        else:
            yield key, value


def load_hashstore_properties(path: pathlib.Path) -> dict:
    properties_file = path / "hashstore.yaml"
    if not properties_file.exists():
        raise FileNotFoundError(
            f"Hashstore properties file not found: {properties_file}"
        )
    with open(properties_file, "r") as f:
        properties = yaml.load(f, Loader=Loader)
    properties["store_path"] = str(path)
    return properties


def locate_hashstore(path: pathlib.Path) -> pathlib.Path | None:
    # Iterate through the current directory and all its parents
    for directory in [path] + list(path.parents):
        # Use glob() to find files matching the pattern within the current directory
        for file_path in directory.glob(HASHSTORE_FOLDER_NAME):
            if file_path.is_dir():
                return file_path
    return None


# ctime, cid_value, pid
def _handle_cid_ref_file(
    cids_path: str, cid_entry: os.DirEntry, rpattern: re.Pattern | None
) -> list[tuple[float, str, str]]:
    result = []
    # print(cids_root, cids_path, cid_entries)
    fname = cid_entry.path
    try:
        cid_value = fname.replace(cids_path, "").replace("/", "")
        ctime = cid_entry.stat().st_ctime
        for _, entry in enumerate(open(fname, "r", encoding="utf-8")):
            pid = entry.strip()
            if len(pid) > 0:
                if rpattern is not None:
                    if rpattern.fullmatch(pid):
                        result.append(
                            (
                                ctime,
                                cid_value,
                                pid,
                            )
                        )
                else:
                    # print(pid)
                    result.append(
                        (
                            ctime,
                            cid_value,
                            pid,
                        )
                    )
    except Exception as e:
        print(e)
    return result


def enumerate_hs_files(
    refs_cids_root: str, pattern: str | None = None, max_workers: int = 2
) -> typing.Generator:
    """Perform a depth first scan of the hashshore refs/cids to yield PIDs.

    This operation will perform a multi-threaded depth first traversal of the
    hashstore refs/cids hierarchy, read each file, and yield a three-tuple of
      create time, cid, pid

    This process is efficient, but still slow due to the number of files that
    need to be processed in even modeterate sized hash stores. For example,
    on an m5 mac running with 10 threads on a hashstore with 4 million entries,
    the process takes about 20 minutes to complete.
    """
    _L = get_logger()
    rpattern = None
    if pattern is not None:
        rpattern = re.compile(pattern)
    ignore_names = [
        ".DS_Store",
    ]
    # Use a LIFO queue for the dirs so we do depth first processing
    dirs_queue = queue.LifoQueue()
    # starting point is root of refs/cids
    dirs_queue.put(refs_cids_root)
    workers = {}
    ticker = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # keep doing stuff untill both the dirs_queue and the workers dict are empty
        while not dirs_queue.empty() or len(workers) > 0:
            try:
                current_dir = dirs_queue.get(timeout=0.01)
                try:
                    with os.scandir(current_dir) as entries:
                        for entry in entries:
                            if entry.name in ignore_names:
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                # entry is a folder, add it to the dirs_queue
                                dirs_queue.put(entry.path)
                            else:
                                # entry is a file. Create a task to process it on a worker
                                future = executor.submit(
                                    _handle_cid_ref_file,
                                    refs_cids_root,
                                    entry,
                                    rpattern,
                                )
                                workers[future] = entry
                except PermissionError:
                    _L.error("Permission denied for %s", current_dir)
                except Exception as e:
                    _L.error("Error at %s: %s", current_dir, e)
            except queue.Empty:
                # no more dirs to process
                pass
            # simple UI feedback
            if ticker % 1000 == 0:
                print(f"{ticker:,} {dirs_queue.qsize():,} {len(workers):,}")
            ticker += 1
            try:
                # yield results from workers as they complete. Also remove completed
                # from the workers dict to keep things compact
                for worker in concurrent.futures.as_completed(workers, timeout=0.01):
                    for result in worker.result():
                        yield result
                    del workers[worker]
            except TimeoutError:
                pass


@click.group()
@click.option(
    "--store",
    type=click.Path(path_type=pathlib.Path, file_okay=False),
    envvar="HASHSTORE_PATH",
    default=None,
)
@click.option(
    "--config",
    default="~/.config/hashstore/defaults.yml",
    type=click.Path(),
    help="Path to configuration file",
)
@click.option("--log-level", default=None, help="Set the logging level (INFO)")
@click.pass_context
def main(ctx, store, config, log_level):
    """Implements a high level file and folder operations CLI for hashstore."""
    ctx.ensure_object(dict)
    # Load defaults from config file
    config = os.path.expanduser(config)
    if os.path.exists(config):
        with open(config, "r") as f:
            cfg = yaml.load(f, Loader=Loader)
            ctx.default_map = cfg
    if store is None:
        store = locate_hashstore(pathlib.Path.cwd())
        if store is not None:
            ctx.obj["hashstore_path"] = store
    else:
        store.expanduser()
        ctx.obj["hashstore_path"] = store
    ctx.obj["module_name"] = ctx.default_map.get(
        "module_name", "hashstore.filehashstore"
    )
    ctx.obj["class_name"] = ctx.default_map.get("class_name", "FileHashStore")
    # Set up logging
    if log_level is None:
        log_level = (
            ctx.default_map.get("log_level", "INFO") if "cfg" in locals() else "INFO"
        )
    logger = get_logger()
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    logging.basicConfig(level=numeric_level)
    logger.setLevel(numeric_level)
    logger.debug(f"Logging initialized at level: {log_level}")
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Configuration:")
        for key, value in enumerate_dict(ctx.default_map):
            logger.debug(f"  {key}: {value}")
    return 0


@main.command()
@click.pass_context
def version(ctx):
    """Show the version of Hashstore."""
    print(f"Hashstore version {hashstore.__version__}")
    return 0


@main.command()
@click.pass_context
@click.option("--depth", "-d", type=int, default=3, help="Hashstore hierarchy depth")
@click.option("--width", "-w", type=int, default=2, help="Hashstore hierarchy width")
@click.option(
    "--algorithm", "-a", type=str, default="SHA-256", help="Hashstore algorithm"
)
@click.option(
    "--metadata_namespace", type=str, default=None, help="Hashstore metadata namespace"
)
def create(ctx, depth, width, algorithm, metadata_namespace):
    """Create a new hashstore at the specified root path."""
    logger = get_logger()
    store = ctx.obj["hashstore_path"]
    if not store.parent.exists():
        logger.error(f"Parent directory does not exist: {store.parent}")
        return 1
    if store.exists():
        if (store / "hashstore.yaml").exists():
            logger.error(f"Hashstore already exists at: {store}")
            return 1
    properties = {
        "store_path": store,
        "store_depth": depth,
        "store_width": width,
        "store_algorithm": algorithm,
        "store_metadata_namespace": metadata_namespace,
    }
    hashstore_factory = hashstore.HashStoreFactory()
    try:
        hash_store = hashstore_factory.get_hashstore(
            ctx.obj["module_name"], ctx.obj["class_name"], properties
        )
        logger.info(f"Hashstore created at: {store}")
    except Exception as e:
        logger.error(f"Failed to create hashstore: {e}")
        return 1
    return 0


@main.command(name="add_folder")
@click.pass_context
@click.argument(
    "root_path", type=click.Path(path_type=pathlib.Path, file_okay=False, exists=True)
)
@click.argument("pid", type=str)
@click.option(
    "-s",
    "--sysmeta_path",
    type=click.Path(path_type=pathlib.Path),
    default=None,
    help="Path to system metadata XML file",
)
@click.option(
    "-p",
    "--pattern",
    type=str,
    default=None,
    help="Glob pattern for files to include (defaults to all)",
)
def add_object(
    ctx,
    root_path: pathlib.Path,
    pid: str | None,
    sysmeta_path: pathlib.Path | None,
    pattern: str | None,
):
    """Add a folder to the hashstore.

    PID is required and is used to reference the folder root.

    If object_path is a folder, a PID is generated for the folder contents added
    recursively using the object relative paths as suffix to the PID.

    if the file doesn't exist:
        add bytes
        store pid
        store sysmeta if provided
    if the file exists:
        if pid doesn't exist:
            store pid by adding to list
        if sysmeta provided:
            store sysmeta
    """
    logger = get_logger()
    store = ctx.obj["hashstore_path"]
    logger.info(
        f"Adding folder at path: {store} with PID: {pid} and sysmeta: {sysmeta_path}"
    )
    properties = load_hashstore_properties(store)
    hashstore_factory = hashstore.HashStoreFactory()
    try:
        hash_store = hashstore_factory.get_hashstore(
            ctx.obj["module_name"], ctx.obj["class_name"], properties
        )
        logger.debug(f"Hashstore opened at: {store}")
    except Exception as e:
        logger.error(f"Failed to open hashstore: {e}")
        return 1
    # Does the object already exist in the store?
    try:
        info = hash_store._find_object(pid=pid)
        hash_store.tag_object(pid, info.get("cid"))
    except hashstore.filehashstore_exceptions.PidRefsDoesNotExist:
        info = None
    # Object doesn't exist in store
    root_path = root_path.absolute()
    if info is None:
        try:
            info = hash_store.commit_folder(
                pid=pid, root_path=root_path, pattern=pattern
            )
            print(json.dumps(dataclasses.asdict(info)))
        except Exception as e:
            logger.error(f"Failed to add object: {e}")
            return 1
    if sysmeta_path is not None and sysmeta_path.is_file():
        hash_store.store_metadata(
            pid=pid,
            metadata=str(sysmeta_path),
            format_id=properties.get("store_metadata_namespace"),
        )
        return 1
    return 0


@main.command("get")
@click.pass_context
@click.argument("pid", type=str)
@click.option("-s", "--stream", is_flag=True, help="Stream to stdout")
@click.option(
    "-r", "--recursive", is_flag=True, help="Recurse into contents if PID is a folder."
)
def get_object(ctx, pid, stream, recursive):
    """Retrieve an object or folder from hashstore."""
    logger = get_logger()
    store = ctx.obj["hashstore_path"]
    properties = load_hashstore_properties(store)
    hashstore_factory = hashstore.HashStoreFactory()
    try:
        hash_store = hashstore_factory.get_hashstore(
            ctx.obj["module_name"], ctx.obj["class_name"], properties
        )
        logger.debug(f"Hashstore opened at: {store}")
    except Exception as e:
        logger.error(f"Failed to open hashstore: {e}")
        return
    pidpath = hashstore.folderentry.split_pidpath(pid, delimiter="|")
    info = hash_store.resolve_pidpath(pidpath)
    print(info)


@main.command("ls")
@click.pass_context
@click.option(
    "-p", "--pattern", default=None, help="Optional regex pattern for PID matching."
)
@click.option(
    "-h",
    "--human-readable",
    is_flag=True,
    help="Display sizes in human readable format.",
)
@click.option(
    "-m",
    "--show-metadata",
    is_flag=True,
    help="Show metadata for entry if available.",
)
@click.option("-r", "--reference", is_flag=True, help="Include path references.")
@click.option("-l", "--list-only", is_flag=True, help="Just list the cid, pid values.")
@click.option("-w", "--workers", default=2, help="Number of workers.")
@click.option("-o", "--output", default=None, help="Write output to file.")
def list_pids(
    ctx, pattern, human_readable, show_metadata, reference, list_only, workers, output
):
    """List PIDs in the hashstore (async).

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
    logger = get_logger()
    store = ctx.obj["hashstore_path"]
    properties = load_hashstore_properties(store)
    hashstore_factory = hashstore.HashStoreFactory()
    try:
        hash_store = hashstore_factory.get_hashstore(
            ctx.obj["module_name"], ctx.obj["class_name"], properties
        )
        logger.debug(f"Hashstore opened at: {store}")
    except Exception as e:
        logger.error(f"Failed to open hashstore: {e}")
        return 1
    total_objects = 0
    # iterate over the refs/cids folder, getting PIDs from each file.
    if not list_only:
        print(f"Hashstore: {str(store.relative_to(pathlib.Path.cwd(), walk_up=True))}")
    dest_file = sys.stdout
    if output is not None:
        dest_file = open(output, "w")
    try:
        for ctime, cid, pid in enumerate_hs_files(
            str(hash_store.cids), pattern=pattern, max_workers=workers
        ):
            if list_only:
                dest_file.write(
                    f"{json.dumps((ctime, cid, pid), ensure_ascii=False)}\n"
                )
                continue
            try:
                pid_stat = hash_store.get_object_status(pid)
                fsize = pid_stat.get("size", 0)
                total_objects += 1
                t_modified = pid_stat.get("modtime", "-")
                if t_modified != "-":
                    t_modified = datetime.datetime.fromtimestamp(t_modified).isoformat(
                        timespec="seconds"
                    )
                t_access = pid_stat.get("accesstime", "-")
                if t_access != "-":
                    t_access = datetime.datetime.fromtimestamp(t_access).isoformat(
                        timespec="seconds"
                    )
                if human_readable:
                    fsize = sizeof_fmt(fsize)
                if fsize > 0 or reference:
                    dest_file.write(f"{fsize}\t{t_modified}\t{t_access}\t{pid}\n")
                if show_metadata:
                    try:
                        meta = hash_store.retrieve_metadata(pid).read().decode()
                        print(meta)
                        # print(json.dumps(meta, indent=2))
                    except KeyError:
                        pass
            except KeyError:
                logger.warning(f"PID status not available in hashstore: {pid}")
        if not list_only:
            print(f"Total {total_objects}")
    finally:
        if output is not None:
            dest_file.close()


@main.command("meta")
@click.pass_context
@click.argument("pid", type=str)
def get_system_metadata(ctx, pid) -> None:
    """Retrieve system metadata for PID"""
    logger = get_logger()
    store = ctx.obj["hashstore_path"]
    properties = load_hashstore_properties(store)
    hashstore_factory = hashstore.HashStoreFactory()
    try:
        hash_store = hashstore_factory.get_hashstore(
            ctx.obj["module_name"], ctx.obj["class_name"], properties
        )
        logger.debug(f"Hashstore opened at: {store}")
    except Exception as e:
        logger.error(f"Failed to open hashstore: {e}")
        return

    pidpath = hashstore.folderentry.split_pidpath(pid, delimiter="|")

    info = {}
    sysm_found = False
    sysm_pid_path = pidpath
    while len(sysm_pid_path) > 0:
        print(" | ".join(sysm_pid_path))
        info = hash_store.resolve_pidpath(sysm_pid_path)
        print(info)
        if info.get("sysmeta_path") not in (None, "Does not exist."):
            sysm_found = True
            break
        sysm_pid_path.pop()
        print("===")
    if not sysm_found:
        print(f"No system metadata found for {pid}")
    sysm_pid = hashstore.folderentry.join_pidpath(sysm_pid_path)
    with hash_store.retrieve_metadata(
        sysm_pid, "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    ) as sysmf:
        sysm = sysmf.read()
        print(sysm.decode("utf-8"))


@main.command("info")
@click.pass_context
@click.argument("pid", type=str)
def get_object_info(ctx, pid) -> None:
    """Compute basic stats for a folder and sub-folders."""
    logger = get_logger()

    def iterate_folder(hs, stats, path, depth: int = 1):
        logger.debug("Current path=%s", path)
        if depth > stats["max_depth"]:
            stats["max_depth"] = depth
        target = hs.resolve_pidpath(path)
        cid_object_path = target.get("cid_object_path")
        if hashstore.folderentry.is_folder(cid_object_path):
            current_folder = hs.retrieve_folder(path)
        else:
            stats["total_files"] += 1
            stats["total_bytes"] += cid_object_path.stat().st_size
            return
        for entry in current_folder:
            logger.debug(str(entry))
            if entry.is_file:
                stats["total_bytes"] = stats["total_bytes"] + entry.size
                stats["total_files"] += 1
            else:
                stats["total_folders"] = stats["total_folders"] + 1
                _path = path + [
                    entry.name,
                ]
                iterate_folder(hs, stats, _path, depth=depth + 1)

    store = ctx.obj["hashstore_path"]
    properties = load_hashstore_properties(store)
    hashstore_factory = hashstore.HashStoreFactory()
    try:
        hash_store = hashstore_factory.get_hashstore(
            ctx.obj["module_name"], ctx.obj["class_name"], properties
        )
        logger.debug(f"Hashstore opened at: {store}")
    except Exception as e:
        logger.error(f"Failed to open hashstore: {e}")
        return 1

    info = {
        "total_files": 0,
        "total_bytes": 0,
        "total_folders": 0,
        "max_depth": 0,
    }
    path = hashstore.folderentry.split_pidpath(pid, delimiter="|")

    iterate_folder(hash_store, info, path, depth=0)
    print(json.dumps(info, indent=2))


@main.command("tree")
@click.pass_context
@click.argument("pid", type=str)
@click.option("-n", "--no-files", is_flag=True, help="Show folders but not content.")
def get_folder_tree(ctx, pid: str, no_files: bool) -> None:
    """Generate a tree representation of the folder and sub-folders."""
    logger = get_logger()

    def iterate_folder(hs, tree, path, with_files: bool = True):
        current_folder = hs.retrieve_folder(path)
        n = 0
        s = 0
        for entry in current_folder:
            if not entry.is_file or with_files:
                branch = tree.add(entry.name)
                if not entry.is_file:
                    _path = path + [entry.name]
                    iterate_folder(hs, branch, _path, with_files=with_files)
            else:
                n += 1
                s += entry.size
        if not with_files:
            branch = tree.add(f"{n:,} files, {s:,} bytes")

    store = ctx.obj["hashstore_path"]
    properties = load_hashstore_properties(store)
    hashstore_factory = hashstore.HashStoreFactory()
    try:
        hash_store = hashstore_factory.get_hashstore(
            ctx.obj["module_name"], ctx.obj["class_name"], properties
        )
        logger.debug(f"Hashstore opened at: {store}")
    except Exception as e:
        logger.error(f"Failed to open hashstore: {e}")
        return 1
    path = hashstore.folderentry.split_pidpath(pid, delimiter="|")
    tree = rich.tree.Tree(pid)
    iterate_folder(hash_store, tree, path, with_files=not no_files)
    rich.print(tree)


if __name__ == "__main__":
    sys.exit(main(auto_envvar_prefix="HASHSTORE"))
