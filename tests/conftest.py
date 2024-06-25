"""Pytest overall configuration file for fixtures"""

import pytest
from hashstore.filehashstore import FileHashStore


def pytest_addoption(parser):
    """Run slow tests only when a flag is set on pytest."""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests",
    )


@pytest.fixture(name="props")
def init_props(tmp_path):
    """Properties to initialize HashStore."""
    directory = tmp_path / "metacat" / "hashstore"
    directory.mkdir(parents=True)
    hashstore_path = directory.as_posix()
    # Note, objects generated via tests are placed in a temporary folder
    # with the 'directory' parameter above appended
    properties = {
        "store_path": hashstore_path,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "http://ns.dataone.org/service/types/v2.0",
    }
    return properties


@pytest.fixture(name="store")
def init_store(props):
    """Create FileHashStore instance for all tests."""
    store = FileHashStore(props)
    return store


@pytest.fixture(name="pids")
def init_pids():
    """Shared test harness data.
    - object_cid: hex digest of the pid
    - metadata_cid: hex digest of the pid + store_metadata_namespace
    """
    test_pids = {
        "doi:10.18739/A2901ZH2M": {
            "file_size_bytes": 39993,
            "metadata_cid": "323e0799524cec4c7e14d31289cefd884b563b5c052f154a066de5ec1e477da7",
            "md5": "db91c910a3202478c8def1071c54aae5",
            "sha1": "1fe86e3c8043afa4c70857ca983d740ad8501ccd",
            "sha224": "922b1e86f83d3ea3060fd0f7b2cf04476e8b3ddeaa3cf48c2c3cf502",
            "sha256": "4d198171eef969d553d4c9537b1811a7b078f9a3804fc978a761bc014c05972c",
            "sha384": "d5953bd802fa74edea72eb941ead7a27639e62792fedc065d6c81de6c613b5b8739ab1f90e7f24a7500d154a727ed7c2",
            "sha512": "e9bcd6b91b102ef5803d1bd60c7a5d2dbec1a2baf5f62f7da60de07607ad6797d6a9b740d97a257fd2774f2c26503d455d8f2a03a128773477dfa96ab96a2e54",
        },
        "jtao.1700.1": {
            "file_size_bytes": 8724,
            "metadata_cid": "ddf07952ef28efc099d10d8b682480f7d2da60015f5d8873b6e1ea75b4baf689",
            "md5": "f4ea2d07db950873462a064937197b0f",
            "sha1": "3d25436c4490b08a2646e283dada5c60e5c0539d",
            "sha224": "9b3a96f434f3c894359193a63437ef86fbd5a1a1a6cc37f1d5013ac1",
            "sha256": "94f9b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a",
            "sha384": "a204678330fcdc04980c9327d4e5daf01ab7541e8a351d49a7e9c5005439dce749ada39c4c35f573dd7d307cca11bea8",
            "sha512": "bf9e7f4d4e66bd082817d87659d1d57c2220c376cd032ed97cadd481cf40d78dd479cbed14d34d98bae8cebc603b40c633d088751f07155a94468aa59e2ad109",
        },
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a": {
            "file_size_bytes": 18699,
            "metadata_cid": "9a2e08c666b728e6cbd04d247b9e556df3de5b2ca49f7c5a24868eb27cddbff2",
            "md5": "e1932fc75ca94de8b64f1d73dc898079",
            "sha1": "c6d2a69a3f5adaf478ba796c114f57b990cf7ad1",
            "sha224": "f86491d23d25dbaf7620542f056aba8a092a70be625502a6afd1fde0",
            "sha256": "4473516a592209cbcd3a7ba4edeebbdb374ee8e4a49d19896fafb8f278dc25fa",
            "sha384": "b1023a9be5aa23a102be9bce66e71f1f1c7a6b6b03e3fc603e9cd36b4265671e94f9cc5ce3786879740536994489bc26",
            "sha512": "c7fac7e8aacde8546ddb44c640ad127df82830bba6794aea9952f737c13a81d69095865ab3018ed2a807bf9222f80657faf31cfde6c853d7b91e617e148fec76",
        },
    }
    return test_pids
