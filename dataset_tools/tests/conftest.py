"""Make both the firewall repo (ml.*) and this tools folder (dataset_tools.*) importable."""
import os, sys
from dataset_tools import paths
FYP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
for p in (FYP, paths.REPO):
    if p not in sys.path:
        sys.path.insert(0, p)
