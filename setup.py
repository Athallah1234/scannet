from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ScanNet",
    version="0.1.0",
    author="NetScan Team",
    author_description="Network scanning library for internal audits, learning and monitoring",
    description="A safe, educational, authorized-only network scanning library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/user/netscan",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0.0",
        "rich>=12.0.0",
        "dnspython>=2.2.0",
        "requests>=2.27.0",
        "python-whois>=0.7.3",
        "tabulate>=0.8.9",
    ],
    entry_points={
        "console_scripts": [
            "scannet=scannet.cli:cli",
        ],
    },
)
