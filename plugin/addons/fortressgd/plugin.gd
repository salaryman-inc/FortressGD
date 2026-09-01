@tool
extends EditorPlugin

const FGDConfig := preload("res://addons/fortressgd/config.gd")

func _enter_tree() -> void:
	var result: Dictionary = FGDConfig.load_project_toml()
	if not result.get("ok", false):
		var err := str(result.get("error", "failed to read .fortressgd.toml"))
		var nxt := str(result.get("next_command", "fortressgd doctor"))
		push_error("FortressGD: %s Run: %s" % [err, nxt])
	else:
		print("FortressGD: loaded .fortressgd.toml")


func _exit_tree() -> void:
	pass


func _get_plugin_name() -> String:
	return "FortressGD"
