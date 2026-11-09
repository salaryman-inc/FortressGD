@tool
extends RefCounted
## DESIGN.md §6.3 forced excludes. Patterns live in filters.json (shared with the CLI).

const FILTERS_JSON := "res://addons/fortressgd/filters.json"
const FEATURE_TAG := "fortressgd_production"
const TEXT_SCRIPT_PATTERN := "*.gd"


static func production_feature_tag() -> String:
	var data := _load_json()
	var tag: Variant = data.get("feature_tag", FEATURE_TAG)
	if typeof(tag) == TYPE_STRING and str(tag) != "":
		return str(tag)
	return FEATURE_TAG


static func forced_exclude_patterns() -> PackedStringArray:
	var out := PackedStringArray()
	var data := _load_json()
	var raw: Variant = data.get("forced_exclude", [])
	if typeof(raw) != TYPE_ARRAY:
		return out
	for item in raw:
		out.append(str(item))
	return out


## Forced §6.3 excludes plus [filters].exclude; [filters].include overrides both.
## Mirrors core/filters.py find_leaks.
static func should_skip_forced(path: String, include_patterns: PackedStringArray, exclude_patterns := PackedStringArray()) -> bool:
	for inc in include_patterns:
		if inc != "" and glob_match(path, inc):
			return false
	for pat in forced_exclude_patterns():
		if glob_match(path, pat):
			return true
	for pat in exclude_patterns:
		if pat != "" and glob_match(path, pat):
			return true
	return false


## For the export plugin that runs before Godot's GDScript plugin. Like
## should_skip_forced, except a script that only the "*.gd" rule excludes is kept,
## so the GDScript plugin can still pack it as bytecode. The "*.gd" rule is about
## text, not about the script; the late plugin drops any text that is left.
static func should_skip_before_bytecode(path: String, include_patterns: PackedStringArray, exclude_patterns := PackedStringArray()) -> bool:
	if not should_skip_forced(path, include_patterns, exclude_patterns):
		return false
	if _normalize(path).get_extension().to_lower() != "gd":
		return true
	for pat in forced_exclude_patterns():
		if pat != TEXT_SCRIPT_PATTERN and glob_match(path, pat):
			return true
	for pat in exclude_patterns:
		if pat != "" and glob_match(path, pat):
			return true
	return false


static func glob_match(path: String, pattern: String) -> bool:
	var npath := _normalize(path)
	var npat := _normalize(pattern).replace("**", "*")
	return npath.matchn(npat)


static func _normalize(path: String) -> String:
	var p := path.replace("\\", "/")
	if p.begins_with("res://"):
		p = p.substr(6)
	while p.begins_with("/"):
		p = p.substr(1)
	return p


static func _load_json() -> Dictionary:
	var raw := FileAccess.get_file_as_string(FILTERS_JSON)
	var parsed: Variant = JSON.parse_string(raw)
	if typeof(parsed) != TYPE_DICTIONARY:
		return {}
	return parsed
