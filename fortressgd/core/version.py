"""Product version. Keep in sync with fortressgd/plugin/addons/fortressgd/plugin.cfg and pyproject.toml."""

__version__ = "0.1.0"

# Godot tags this CLI supports: exactly the tags with a patches/<tag>/ folder
# (DESIGN.md §4). "4.7" and "4.7.x" are aliases for 4.7.2.
SUPPORTED_GODOT = ("4.6.2", "4.7.2")
GODOT_TAG_ALIASES = {"4.7": "4.7.2", "4.7.x": "4.7.2"}


def concrete_godot_tag(version: str) -> str:
    """Map toml/CLI godot values to a patches/<tag> folder name."""
    return GODOT_TAG_ALIASES.get(version, version)
