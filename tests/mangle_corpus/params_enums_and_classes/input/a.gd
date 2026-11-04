extends Node
class_name Hero

enum Mood { CALM = 1, ANGRY }
const MAX_HP := 10

class Inner:
	var depth = 0

func heal(amount: int, bonus := 0) -> int:
	var total := amount + bonus
	for step in range(total):
		pass
	return mini(total, MAX_HP)
# comment
"""doc string with heal inside"""
