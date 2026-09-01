extends Node2D


func _ready() -> void:
	print("FortressGD sample project")


func _draw() -> void:
	draw_rect(Rect2(-32, -32, 64, 64), Color(0.91, 0.27, 0.38))
