extends Node

var score := 0
var lives := 3

func _on_button_pressed() -> void:
	score += lives
