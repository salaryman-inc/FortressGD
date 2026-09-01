@tool
extends RefCounted
## Reads and validates project-root `.fortressgd.toml`. Unknown keys are errors.

const CONFIG_NAME := ".fortressgd.toml"
const SCHEMA_PATH := "res://addons/fortressgd/schema.json"


static func load_project_toml() -> Dictionary:
	var out := {
		"ok": false,
		"error": "",
		"next_command": "fortressgd init",
		"data": {},
	}
	var root := ProjectSettings.globalize_path("res://")
	if root.ends_with("/") or root.ends_with("\\"):
		pass
	else:
		root += "/"
	var path := root + CONFIG_NAME
	if not FileAccess.file_exists(path):
		out["error"] = "missing %s" % CONFIG_NAME
		out["next_command"] = "fortressgd init"
		return out
	var file := FileAccess.open(path, FileAccess.READ)
	if file == null:
		out["error"] = "cannot read %s" % CONFIG_NAME
		out["next_command"] = "fortressgd doctor"
		return out
	var text := file.get_as_text()
	file.close()
	var parsed: Variant = _parse_toml(text)
	if typeof(parsed) == TYPE_DICTIONARY and parsed.has("_error"):
		out["error"] = str(parsed["_error"])
		out["next_command"] = "fortressgd doctor"
		return out
	if typeof(parsed) != TYPE_DICTIONARY:
		out["error"] = "failed to parse %s" % CONFIG_NAME
		out["next_command"] = "fortressgd doctor"
		return out
	var verr := _validate(parsed)
	if verr != "":
		out["error"] = verr
		out["next_command"] = "fortressgd doctor"
		return out
	out["ok"] = true
	out["error"] = ""
	out["next_command"] = ""
	out["data"] = parsed
	return out


static func _schema() -> Dictionary:
	var raw := FileAccess.get_file_as_string(SCHEMA_PATH)
	var parsed: Variant = JSON.parse_string(raw)
	if typeof(parsed) != TYPE_DICTIONARY:
		return {}
	return parsed


static func _validate(data: Dictionary) -> String:
	var schema := _schema()
	if schema.is_empty():
		return "missing plugin schema.json"
	var unknown: PackedStringArray = []
	var root_allowed: Array = schema.get("root", [])
	for key in data.keys():
		var val: Variant = data[key]
		if typeof(val) == TYPE_DICTIONARY:
			if not schema.has(key):
				unknown.append(str(key))
				continue
			var allowed: Array = schema[key]
			for sk in val.keys():
				if not allowed.has(sk):
					unknown.append("%s.%s" % [key, sk])
		else:
			if not root_allowed.has(key):
				unknown.append(str(key))
	if unknown.size() > 0:
		return "unknown key(s) in %s: %s" % [CONFIG_NAME, ", ".join(unknown)]
	if not data.has("schema") or not data.has("godot"):
		return "%s must set schema and godot" % CONFIG_NAME
	return ""


static func _parse_toml(text: String) -> Variant:
	var result := {}
	var current: Dictionary = result
	var lines := text.split("\n")
	var i := 0
	while i < lines.size():
		var stripped := _strip_comment(lines[i]).strip_edges()
		if stripped == "":
			i += 1
			continue
		if stripped.begins_with("[") and stripped.ends_with("]") and not stripped.contains("="):
			var name := stripped.substr(1, stripped.length() - 2).strip_edges()
			var section := {}
			result[name] = section
			current = section
			i += 1
			continue
		if not stripped.contains("="):
			return {"_error": "invalid line in %s: %s" % [CONFIG_NAME, stripped]}
		var eq := stripped.find("=")
		var key := stripped.substr(0, eq).strip_edges()
		var rest := stripped.substr(eq + 1).strip_edges()
		var assembled := rest
		while not _value_complete(assembled):
			i += 1
			if i >= lines.size():
				return {"_error": "unclosed array in %s" % CONFIG_NAME}
			assembled += " " + _strip_comment(lines[i]).strip_edges()
		var parsed_val: Variant = _parse_value(assembled.strip_edges())
		if typeof(parsed_val) == TYPE_DICTIONARY and parsed_val.has("_error"):
			return parsed_val
		current[key] = parsed_val
		i += 1
	return result


static func _value_complete(s: String) -> bool:
	var t := s.strip_edges()
	if not t.begins_with("["):
		return t != ""
	return _brackets_balanced(t)


static func _brackets_balanced(s: String) -> bool:
	var depth := 0
	var in_str := false
	var esc := false
	for idx in s.length():
		var ch := s[idx]
		if in_str:
			if esc:
				esc = false
			elif ch == "\\":
				esc = true
			elif ch == "\"":
				in_str = false
			continue
		if ch == "\"":
			in_str = true
			continue
		if ch == "[":
			depth += 1
		elif ch == "]":
			depth -= 1
	return depth == 0 and not in_str


static func _parse_value(s: String) -> Variant:
	if s == "true":
		return true
	if s == "false":
		return false
	if s.begins_with("\"") and s.ends_with("\"") and s.length() >= 2:
		return s.substr(1, s.length() - 2)
	if s.begins_with("[") and s.ends_with("]"):
		var inner := s.substr(1, s.length() - 2).strip_edges()
		var arr: Array = []
		if inner == "":
			return arr
		for item in _split_array_items(inner):
			var pv: Variant = _parse_value(item.strip_edges())
			if typeof(pv) == TYPE_DICTIONARY and pv.has("_error"):
				return pv
			arr.append(pv)
		return arr
	if s.is_valid_int():
		return int(s)
	return {"_error": "unsupported value in %s: %s" % [CONFIG_NAME, s]}


static func _split_array_items(inner: String) -> Array:
	var items: Array = []
	var buf := ""
	var in_str := false
	var esc := false
	for idx in inner.length():
		var ch := inner[idx]
		if in_str:
			buf += ch
			if esc:
				esc = false
			elif ch == "\\":
				esc = true
			elif ch == "\"":
				in_str = false
			continue
		if ch == "\"":
			in_str = true
			buf += ch
			continue
		if ch == ",":
			var item := buf.strip_edges()
			if item != "":
				items.append(item)
			buf = ""
			continue
		buf += ch
	var tail := buf.strip_edges()
	if tail != "":
		items.append(tail)
	return items


static func _strip_comment(line: String) -> String:
	var out := ""
	var in_str := false
	var esc := false
	for idx in line.length():
		var ch := line[idx]
		if in_str:
			out += ch
			if esc:
				esc = false
			elif ch == "\\":
				esc = true
			elif ch == "\"":
				in_str = false
			continue
		if ch == "\"":
			in_str = true
			out += ch
			continue
		if ch == "#":
			break
		out += ch
	return out
