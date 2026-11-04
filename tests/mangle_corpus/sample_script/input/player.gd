extends Node2D
class_name SampleHero

# strip this comment
func _ready() -> void:
	var health := 10
	assert(health > 0)
	print_debug("debug")
	breakpoint
	my_attack()
	public_mod_hook()

## fortressgd:keep
func public_mod_hook() -> void:
	pass

func my_attack() -> void:
	pass
