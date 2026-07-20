import os
import sys
from importlib.metadata import version as _get_version, PackageNotFoundError

sys.path.insert(0, os.path.abspath(".."))

project = "memobj"
author = "StarrFox"
copyright = f"2024, {author}"

try:
    release = _get_version("memobj")
except PackageNotFoundError:
    release = "unknown"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "myst_parser",
]

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "furo"

autodoc_member_order = "bysource"
autoclass_content = "both"
napoleon_google_docstring = True
napoleon_numpy_docstring = False
