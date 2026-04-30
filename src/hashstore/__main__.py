import dataclasses
import datetime
import json
import logging
import os
import pathlib
import sys
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


def load_hashstore_properties(path:pathlib.Path)-> dict:
    properties_file = path / "hashstore.yaml"
    if not properties_file.exists():
        raise FileNotFoundError(f"Hashstore properties file not found: {properties_file}")
    with open(properties_file, 'r') as f:
        properties = yaml.load(f, Loader=Loader)
    properties["store_path"] = str(path)
    return properties


def locate_hashstore(path:pathlib.Path)->pathlib.Path:
    # Iterate through the current directory and all its parents
    for directory in [path] + list(path.parents):
        # Use glob() to find files matching the pattern within the current directory
        for file_path in directory.glob(HASHSTORE_FOLDER_NAME):
            if file_path.is_dir():
                return file_path
    return None


@click.group()
@click.option(
    "--store", 
    type=click.Path(path_type=pathlib.Path, file_okay=False), 
    envvar="HASHSTORE_PATH", 
    default=None
)
@click.option("--config", default='~/.config/hashstore/defaults.yml', type=click.Path(), help="Path to configuration file")
@click.option("--log-level", default=None, help="Set the logging level (INFO)")
@click.pass_context
def main(ctx, store, config, log_level):
    """Implements a high level file and folder operations CLI for hashstore.
    """
    ctx.ensure_object(dict)
    # Load defaults from config file
    config = os.path.expanduser(config)
    if os.path.exists(config):
        with open(config, 'r') as f:
            cfg = yaml.load(f, Loader=Loader)
            ctx.default_map = cfg
    if store is None:
        store = locate_hashstore(pathlib.Path.cwd())
        if store is not None:
            ctx.obj["hashstore_path"] = store        
    else:
        store.expanduser()
        ctx.obj["hashstore_path"] = store
    ctx.obj["module_name"] = ctx.default_map.get("module_name", "hashstore.filehashstore")
    ctx.obj["class_name"] = ctx.default_map.get("class_name", "FileHashStore")
    # Set up logging
    if log_level is None:
        log_level = ctx.default_map.get('log_level', 'INFO') if 'cfg' in locals() else 'INFO'
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
@click.option("--algorithm", "-a", type=str, default="SHA-256", help="Hashstore algorithm")
@click.option("--metadata_namespace", type=str, default=None, help="Hashstore metadata namespace")
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
        hash_store = hashstore_factory.get_hashstore(ctx.obj["module_name"], ctx.obj["class_name"], properties)
        logger.info(f"Hashstore created at: {store}")
    except Exception as e:
        logger.error(f"Failed to create hashstore: {e}")
        return 1
    return 0


@main.command(name="add_folder")
@click.pass_context
@click.argument(
    "root_path", 
    type=click.Path(path_type=pathlib.Path, file_okay=False, exists=True)
)
@click.argument("pid", type=str)
@click.option(
    "-s", 
    "--sysmeta_path", 
    type=click.Path(path_type=pathlib.Path), 
    default=None, 
    help="Path to system metadata XML file"
)
@click.option(
    "-p",
    "--pattern",
    type=str,
    default=None,
    help="Glob pattern for files to include (defaults to all)"
)
def add_object(
    ctx, 
    root_path:pathlib.Path, 
    pid: str|None, 
    sysmeta_path:pathlib.Path|None,
    pattern:str|None,
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
    logger.info(f"Adding folder at path: {store} with PID: {pid} and sysmeta: {sysmeta_path}")
    properties = load_hashstore_properties(store)
    hashstore_factory = hashstore.HashStoreFactory()
    try:
        hash_store = hashstore_factory.get_hashstore(ctx.obj["module_name"], ctx.obj["class_name"], properties)
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
            info = hash_store.commit_folder(pid=pid, root_path=root_path, pattern=pattern)
            print(json.dumps(dataclasses.asdict(info)))
        except Exception as e:
            logger.error(f"Failed to add object: {e}")
            return 1
    if sysmeta_path is not None and sysmeta_path.is_file():
        hash_store.store_metadata(pid=pid, metadata=str(sysmeta_path), format_id=properties.get("store_metadata_namespace"))
        return 1
    return 0


@main.command("get")
@click.pass_context
@click.argument("pid", type=str)
@click.option("-s", "--stream", is_flag=True, help="Stream to stdout")
@click.option("-r", "--recursive", is_flag=True, help="Recurse into contents if PID is a folder.")
def get_object(ctx, pid, stream, recursive):
    """Retrieve an object or folder from hashstore."""
    store = ctx.obj["hashstore_path"]
    pass


@main.command("ls")
@click.pass_context
@click.option("-p", "--pattern", default=None, help="Optional regex pattern for PID matching.")
@click.option("-h", "--human-readable", is_flag=True, help="Display sizes in human readable format.")
@click.option("-r", "--reference", is_flag=True, help="Include path references.")
def list_pids(ctx, pattern, human_readable, reference):
    """List PIDs in the hashstore."""
    logger = get_logger()
    store = ctx.obj["hashstore_path"]
    properties = load_hashstore_properties(store)
    hashstore_factory = hashstore.HashStoreFactory()
    try:
        hash_store = hashstore_factory.get_hashstore(ctx.obj["module_name"], ctx.obj["class_name"], properties)
        logger.debug(f"Hashstore opened at: {store}")
    except Exception as e:
        logger.error(f"Failed to open hashstore: {e}")
        return 1
    total_objects = 0
    # iterate over the refs/cids folder, getting PIDs from each file.
    print(f"Hashstore: {str(store.relative_to(pathlib.Path.cwd(), walk_up=True))}")
    for pid in hash_store.list_pids(pattern=pattern):
        try:            
            pid_stat = hash_store.get_object_status(pid)
            fsize = pid_stat.get("size", 0)
            total_objects += 1
            t_modified = pid_stat.get("modtime", "-")
            if t_modified != "-":
                t_modified = datetime.datetime.fromtimestamp(t_modified).isoformat(timespec="seconds") 
            t_access = pid_stat.get("accesstime", "-")
            if t_access != "-":
                t_access = datetime.datetime.fromtimestamp(t_access).isoformat(timespec="seconds")
            if human_readable:
                fsize = sizeof_fmt(fsize)
            if fsize>0 or reference:
                print(f"{fsize}\t{t_modified}\t{t_access}\t{pid}")
            try:
                meta = hash_store.retrieve_metadata(pid)
                print(json.dumps(meta, indent=2))
            except KeyError:
                pass
        except KeyError:
            logger.warning(f"PID status not available in hashstore: {pid}")
    print(f"Total {total_objects}")


@main.command("tree")
@click.pass_context
@click.argument("pid", type=str)
def get_container_tree(ctx, pid)->None:
    logger = get_logger()
    store = ctx.obj["hashstore_path"]
    properties = load_hashstore_properties(store)
    hashstore_factory = hashstore.HashStoreFactory()
    try:
        hash_store = hashstore_factory.get_hashstore(ctx.obj["module_name"], ctx.obj["class_name"], properties)
        logger.debug(f"Hashstore opened at: {store}")
    except Exception as e:
        logger.error(f"Failed to open hashstore: {e}")
        return 1
    tree = {
        pid:rich.tree.Tree(pid),
    }
    for entry in hash_store.folder_content(pid, depth_first=True):
        print(f"{entry[0]} {entry[1]} {entry[3]} {entry[2]}")
        parts = entry[3].rsplit("/", 1)
        if entry[1] == 0:
            tree[entry[3]] = tree[parts[0]].add(entry[3])
        else:
            # file
            tree[parts[0]].add(entry[3])
    rich.print(tree[pid])


if __name__ == "__main__":
    sys.exit(main(auto_envvar_prefix="HASHSTORE"))
