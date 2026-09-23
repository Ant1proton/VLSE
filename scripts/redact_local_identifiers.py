#!/usr/bin/env python3
"""Redact local paths and host identifiers from captured experiment text."""

import argparse
from pathlib import Path
import re
import socket
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--result-root", required=True)
    args = parser.parse_args()
    replacements = {}
    for value, label in (
        (str(Path.home()), "<home>"),
        (args.repo_root, "<repo>"),
        (args.result_root, "<results>"),
    ):
        for candidate in (str(Path(value).absolute()), str(Path(value).resolve())):
            if len(candidate) > 1:
                replacements[candidate] = label
    paths = sorted(replacements, key=len, reverse=True)
    path_pattern = re.compile("|".join(re.escape(path) for path in paths))
    hostname = socket.gethostname()
    host_pattern = re.compile(r"(?<![\w.-])" + re.escape(hostname) + r"(?![\w.-])") if hostname else None
    for line in sys.stdin:
        line = path_pattern.sub(lambda match: replacements[match.group()], line)
        if host_pattern is not None:
            line = host_pattern.sub("<host>", line)
        sys.stdout.write(line)


if __name__ == "__main__":
    main()
