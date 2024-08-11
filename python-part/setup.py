#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='pgp-sig2dot',
    version='1.0',
    author="cryolitia",
    author_email="cryolitia@gmail.com",
    url="https://github.com/cryolitia/pgp-sig2dot",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Utilities",
        "Environment :: Console",
        "Topic :: Security :: Cryptography",
    ],
    install_requires=[
        "jaal",
        "matplotlib",
        "networkx",
        "pandas",
        "pydot",
    ],
    # Executables
    scripts=["main.py"],
)
