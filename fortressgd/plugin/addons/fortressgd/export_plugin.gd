@tool
extends EditorExportPlugin
## Production export: skip DESIGN.md §6.3 excludes when feature tag fortressgd_production is set.
## When [production].mangle_scripts is true, run the mangler (core/mangle.py on CLI export
## via FORTRESSGD_CLI_EXPORT; otherwise mangle.gd in the editor) before bytecode remap.

const FGDConfig := preload("res://addons/fortressgd/config.gd")
const FGDFilters := preload("res://addons/fortressgd/filters.gd")
const FGDMangle := preload("res://addons/fortressgd/mangle.gd")

var _include: PackedStringArray = PackedStringArray()
var _exclude: PackedStringArray = PackedStringArray()
var _mangle_enabled: bool = false
var _mangle_applied: bool = false
var _mangle_abort: bool = false
var _mangle_backups: Dictionary = {}
var _mangle_mapping: Dictionary = {}
var _mangle_export_path: String = ""
var _mangle_secret_hash: String = ""


func _get_name() -> String:
	# Sorted after Godot's built-in "GDScript" plugin so binary-token .gdc remap
	# runs first. skip() on *.gd then only hits leftover text scripts.
	# Mangling rewrites sources in _export_begin so that remap sees mangled text.
	return "GDScript.FortressGD"


func _export_begin(features: PackedStringArray, is_debug: bool, path: String, flags: int) -> void:
	_include = PackedStringArray()
	_exclude = PackedStringArray()
	_mangle_enabled = false
	_mangle_applied = false
	_mangle_abort = false
	_mangle_backups = {}
	_mangle_mapping = {}
	_mangle_export_path = path
	_mangle_secret_hash = ""
	var result: Dictionary = FGDConfig.load_project_toml()
	if not result.get("ok", false):
		# Fail closed on production presets: exporting without the config would skip
		# mangling and [filters] with no error. Other presets export as before.
		if features.has(FGDFilters.production_feature_tag()):
			push_error("FortressGD: %s. Run: %s" % [str(result.get("error", "cannot load .fortressgd.toml")), str(result.get("next_command", "fortressgd doctor"))])
			_mangle_abort = true
		return
	var data: Dictionary = result.get("data", {})
	var filters: Variant = data.get("filters", {})
	if typeof(filters) == TYPE_DICTIONARY:
		var inc: Variant = filters.get("include", [])
		if typeof(inc) == TYPE_ARRAY:
			for item in inc:
				_include.append(str(item))
		var exc: Variant = filters.get("exclude", [])
		if typeof(exc) == TYPE_ARRAY:
			for item in exc:
				_exclude.append(str(item))
	if not features.has(FGDFilters.production_feature_tag()):
		return
	var production: Variant = data.get("production", {})
	if typeof(production) != TYPE_DICTIONARY:
		return
	_mangle_enabled = bool(production.get("mangle_scripts", false))
	if not _mangle_enabled:
		return
	# CLI export already applied core/mangle.py; do not double-mangle.
	if OS.get_environment("FORTRESSGD_CLI_EXPORT") == "1":
		return
	var hex_secret := _load_secret_hex()
	if hex_secret == "":
		push_error("FortressGD: mangle_scripts is true but secret is missing. Run: fortressgd secret generate")
		_mangle_abort = true
		return
	_mangle_secret_hash = FGDMangle.secret_hash(hex_secret)
	# Keyed with a secret-derived key, never the public secret_hash (which only
	# labels the source map).
	var applied: Dictionary = FGDMangle.apply_project(FGDMangle.mangle_key(hex_secret))
	if not applied.get("ok", false):
		push_error("FortressGD: %s" % str(applied.get("error", "mangle failed")))
		_mangle_abort = true
		return
	_mangle_backups = applied.get("backups", {})
	_mangle_mapping = applied.get("mapping", {})
	_mangle_applied = true


func _export_file(path: String, type: String, features: PackedStringArray) -> void:
	if _mangle_abort:
		skip()
		return
	if not features.has(FGDFilters.production_feature_tag()):
		return
	if FGDFilters.should_skip_forced(path, _include, _exclude):
		skip()


func _export_end() -> void:
	if _mangle_abort:
		# skip() here is too late: GDScript.FortressGD runs after the built-in
		# GDScript plugin, which has already add_file'd bytecode. Refuse the
		# finished artifact (ExportNotifier destructor runs after save_pack).
		# Godot 4 has no way for a plugin to set the export's exit code, so
		# fortressgd export fails on the missing artifact instead.
		push_error("FortressGD: refusing export artifact after mangle abort")
		FGDMangle.refuse_export_artifact(_mangle_export_path)
		_mangle_abort = false
		_mangle_applied = false
		_mangle_backups = {}
		_mangle_mapping = {}
		return
	if _mangle_applied:
		FGDMangle.restore(_mangle_backups)
		if _mangle_export_path != "":
			# Source map under <project>/.fortressgd/maps/, never next to the export.
			FGDMangle.write_map(_mangle_export_path, _mangle_secret_hash, _mangle_mapping)
	_mangle_applied = false
	_mangle_backups = {}
	_mangle_mapping = {}


func _load_secret_hex() -> String:
	# Same order as core/secret.py load_secret_hex: the project's
	# .fortressgd.secret first, then FORTRESSGD_SECRET. Keep the two aligned, or a
	# CLI export and an editor export of the same project use different secrets.
	var root := ProjectSettings.globalize_path("res://")
	if not (root.ends_with("/") or root.ends_with("\\")):
		root += "/"
	var path := root + ".fortressgd.secret"
	if FileAccess.file_exists(path):
		var file := FileAccess.open(path, FileAccess.READ)
		if file != null:
			var text := file.get_as_text().strip_edges()
			file.close()
			if text != "":
				return text
	return OS.get_environment("FORTRESSGD_SECRET").strip_edges()
