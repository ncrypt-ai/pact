"""Sphinx configuration for pact."""

import os
import sys
from importlib.metadata import version as distribution_version

sys.path.insert(0, os.path.abspath("../src"))

project = "Pact"
copyright = "2026, Rex Stockham"
author = "Rex Stockham"

release = distribution_version("pact")
version = release

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
    "sphinx_copybutton",
    "sphinx_remove_toctrees",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

autodoc_member_order = "bysource"
autodoc_typehints = "description"

html_theme = "furo"
html_title = "Pact Documentation"
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_theme_options = {
    "navigation_with_keys": True,
    "light_css_variables": {
        "color-brand-primary": "#1f6feb",
        "color-brand-content": "#1f6feb",
    },
    "dark_css_variables": {
        "color-brand-primary": "#58a6ff",
        "color-brand-content": "#58a6ff",
    },
}
