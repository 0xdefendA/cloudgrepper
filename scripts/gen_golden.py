#!/usr/bin/env python3
"""Capture Python cloudgrep Search() output over fixtures -> tests/golden/.

Uses only the Python stdlib (search.py has no third-party imports).
Golden cases are restricted to scenarios where Python 1.0.5's any()
short-circuit cannot truncate output: single-line JSON files, or files
whose first matching line is the only interesting comparison.
"""
import io
import os
import sys
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "cloudgrep"))
from cloudgrep.search import Search  # noqa: E402

DATA = os.path.join(HERE, "..", "..", "cloudgrep", "tests", "data")
OUT = os.path.join(HERE, "..", "tests", "golden")
os.makedirs(OUT, exist_ok=True)

# (golden_name, fixture, queries, hide_filenames, log_format, log_properties, json_output)
CASES = [
    ("cloudtrail_sig_json.txt", "cloudtrail_singleline.json", ["SignatureVersion"], False, "json", ["Records"], True),
    ("cloudtrail_sig_line.txt", "cloudtrail_singleline.json", ["SignatureVersion"], False, "json", ["Records"], False),
    ("cloudtrail_sig_hidden.txt", "cloudtrail_singleline.json", ["SignatureVersion"], True, "json", ["Records"], True),
    ("azure_singleline_json.txt", "azure_singleline.json", ["listKeys"], False, "json", ["data"], True),
    ("gz_first_match.txt", "000000.gz", ["Running on machine"], False, None, [], False),
    ("gz_first_match_json.txt", "000000.gz", ["Running on machine"], False, None, [], True),
    ("zip_first_match.txt", "000000.zip", ["Running on machine"], False, None, [], False),
    ("utf8_torture.txt", "UTF-8-Test.txt", ["the"], False, None, [], False),
]

for name, fixture, queries, hide, fmt, props, jo in CASES:
    buf = io.StringIO()
    with redirect_stdout(buf):
        Search().search_file(os.path.join(DATA, fixture), fixture, queries, hide, None, fmt, props, jo)
    with open(os.path.join(OUT, name), "w") as f:
        f.write(buf.getvalue())
    print(f"wrote {name}")
