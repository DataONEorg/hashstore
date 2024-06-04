from setuptools import setup, find_packages

setup(
    name="hashstore",
    version="1.1",
    packages=find_packages(where="src"),
    entry_points={
        "console_scripts": [
            "hashstore=hashstore.command_line:main",
        ],
    },
)
