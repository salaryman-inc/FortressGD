extends Node

var speed = 5
var hp = 3

func _ready():
	var other = get_node("Enemy")
	other.speed = 10
	self.hp -= 1
	hp -= 1
