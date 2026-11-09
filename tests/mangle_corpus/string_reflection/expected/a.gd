extends Node

signal my_signal
var health = 3
var hp = 1
var speed = Vector2.ZERO
var _f03ce4a5673 = 1

func go():
	emit_signal("my_signal")
	connect("my_signal", Callable(self, "go"))
	var _fd4aa069748 = get("health")
	var _fa7de0c609d = &"go"
	var _ff9ee06a166 = ^".:hp"
	create_tween().tween_property(self, "speed:x", 1.0, 0.5)
	print("hello world", _f03ce4a5673)
