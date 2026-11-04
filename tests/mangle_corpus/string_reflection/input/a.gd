extends Node

signal my_signal
var health = 3
var hp = 1
var speed = Vector2.ZERO
var hello_world = 1

func go():
	emit_signal("my_signal")
	connect("my_signal", Callable(self, "go"))
	var h = get("health")
	var c = &"go"
	var p = ^".:hp"
	create_tween().tween_property(self, "speed:x", 1.0, 0.5)
	print("hello world", hello_world)
