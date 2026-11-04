extends Node2D

@export var speed: float = 100.0
@export_range(0, 10)
var level := 1
@export_group("G")
var x = 0
@export_enum("A", "B") var choice = 0
@onready
@export
var stacked = 1
var plain = 1

func _on_button_pressed() -> void:
	speed += 1.0
