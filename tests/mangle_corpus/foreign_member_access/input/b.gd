extends Node

enum State { IDLE, RUN }

var s = State.IDLE
var scale_x = 1.5

func f():
	return scale_x * 2.0
