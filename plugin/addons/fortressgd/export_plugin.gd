@tool
extends EditorExportPlugin
## Production export: skip DESIGN.md §6.3 excludes when feature tag fortressgd_production is set.

const FGDConfig := preload("res://addons/fortressgd/config.gd")
const FGDFilters := preload("res://addons/fortressgd/filters.gd")

var _include: PackedStringArray = PackedStringArray()


func _get_name() -> String:
	# Sorted after Godot's built-in "GDScript" plugin so binary-token .gdc remap
	# runs first. skip() on *.gd then only hits leftover text scripts.
	return "GDScript.FortressGD"


func _export_begin(features: PackedStringArray, is_debug: bool, path: String, flags: int) -> void:
	_include = PackedStringArray()
	var result: Dictionary = FGDConfig.load_project_toml()
	if not result.get("ok", false):
		return
	var data: Dictionary = result.get("data", {})
	var filters: Variant = data.get("filters", {})
	if typeof(filters) != TYPE_DICTIONARY:
		return
	var inc: Variant = filters.get("include", [])
	if typeof(inc) != TYPE_ARRAY:
		return
	for item in inc:
		_include.append(str(item))


func _export_file(path: String, type: String, features: PackedStringArray) -> void:
	if not features.has(FGDFilters.production_feature_tag()):
		return
	if FGDFilters.should_skip_forced(path, _include):
		skip()
