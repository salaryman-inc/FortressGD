@tool
extends EditorPlugin

const FGDConfig := preload("res://addons/fortressgd/config.gd")
const FGDExportPlugin := preload("res://addons/fortressgd/export_plugin.gd")

var _export_plugin: EditorExportPlugin
var _late_export_plugin: EditorExportPlugin


func _enter_tree() -> void:
	# Two instances, sorted around Godot's GDScript plugin; see export_plugin.gd.
	_export_plugin = FGDExportPlugin.new()
	add_export_plugin(_export_plugin)
	_late_export_plugin = FGDExportPlugin.new(true)
	add_export_plugin(_late_export_plugin)
	var result: Dictionary = FGDConfig.load_project_toml()
	if not result.get("ok", false):
		var err := str(result.get("error", "failed to read .fortressgd.toml"))
		var nxt := str(result.get("next_command", "fortressgd doctor"))
		push_error("FortressGD: %s Run: %s" % [err, nxt])
	else:
		print("FortressGD: loaded .fortressgd.toml")


func _exit_tree() -> void:
	if _export_plugin:
		remove_export_plugin(_export_plugin)
		_export_plugin = null
	if _late_export_plugin:
		remove_export_plugin(_late_export_plugin)
		_late_export_plugin = null


func _get_plugin_name() -> String:
	return "FortressGD"
