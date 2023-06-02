"""Pytest overall configuration file for fixtures"""


def pytest_addoption(parser):
    """Run slow tests only when a flag is set on pytest."""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests",
    )
