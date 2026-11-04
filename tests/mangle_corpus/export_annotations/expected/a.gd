extends Node2D

@export var speed: float = 100.0
@export_range(0, 10)
var level := 1
@export_group("G")
var _fec81a1c4f5 = 0
@export_enum("A", "B") var choice = 0
@onready
@export
var stacked = 1
var _fde13e1f814 = 1

func _facb0d4e3dd() -> void:
	speed += 1.0
