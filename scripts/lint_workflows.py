"""Check the workflow with the pinned actionlint image.

Same hardened container shape as the scanners. actionlint writes to stdout only;
any finding or crash is a non-zero exit and therefore a failed job.
"""

import subprocess
import sys

from scan import ROOT, Session, load_lock


def main():
    lock = load_lock(ROOT)
    session = Session(lock, ROOT)  # No report directory; there is nothing to archive.
    try:
        session.docker(lock["images"]["actionlint"], ["-color"],
                       ["--workdir", "/repo"] + session.mount(ROOT, "/repo", True), timeout=300)
    finally:
        session.cleanup()
    print("actionlint: no findings")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"WORKFLOW LINT FAILED: {error}", file=sys.stderr)
        sys.exit(1)
