extends Node

func _ready():
	if true:
		assert(1 == 1)
	print_debug("x")

func f():
	breakpoint

func g(a, b):
	if a: assert(b)
	var x = 1; assert(x);
	logger.print_debug("kept")
