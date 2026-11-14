"""Where things live.

dataset_tools/ sits at the root of the firewall repo. Tools read/write datasets next to themselves
(dataset_tools/<type>/data, git-ignored) and put trained artifacts where the runtime looks for
them (<repo>/ml/<type>/artifacts). Override the repo location with BIFROST_REPO.
"""
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.expanduser(os.getenv("BIFROST_REPO", os.path.dirname(_HERE))))


def artifacts_dir(kind: str) -> str:
    return os.path.join(REPO, "ml", kind, "artifacts")
