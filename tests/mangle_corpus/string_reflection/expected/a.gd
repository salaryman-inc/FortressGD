extends Node

signal my_signal
var health = 3
var hp = 1
var speed = Vector2.ZERO
var _fb0646920bd = 1

func go():
	emit_signal("my_signal")
	connect("my_signal", Callable(self, "go"))
	var _faa8e6a17ad = get("health")
	var _fd0bee63cea = &"go"
	var _f79c7b4babc = ^".:hp"
	create_tween().tween_property(self, "speed:x", 1.0, 0.5)
	print("hello world", _fb0646920bd)
