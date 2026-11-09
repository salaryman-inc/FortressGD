extends Node2D

@export var speed: float = 100.0
@export_range(0, 10)
var level := 1
@export_group("G")
var _f4aacee948d = 0
@export_enum("A", "B") var choice = 0
@onready
@export
var stacked = 1
var _f56b5811786 = 1

func _fb7c3f57849() -> void:
	speed += 1.0
