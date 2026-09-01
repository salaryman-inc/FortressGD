@tool
extends RefCounted
## Identifier mangling + unsafe call/rpc/set scan (DESIGN.md §9).
## Algorithm matches core/mangle.py (secret_hash PRNG, keep annotation, reserved JSON).

const RESERVED_PATH := "res://addons/fortressgd/mangle_reserved.json"
const KEEP_PREFIX := "## fortressgd:keep"
const MANGLE_INFO := "fortressgd-mangle-v1"
const PLUGIN_ADDON := "addons/fortressgd"
const MAP_SUFFIX := ".fortressgd.map.json"

const KIND_IDENT := "ident"
const KIND_STRING := "string"
const KIND_COMMENT := "comment"
const KIND_PUNCT := "punct"
const KIND_SPACE := "space"
const KIND_NEWLINE := "newline"
const KIND_NUMBER := "number"
const KIND_ANNOTATION := "annotation"
const KIND_NODEPATH := "nodepath"

const UNSAFE := ["call", "rpc", "set"]
const DECL := ["func", "var", "const", "signal", "enum", "class", "for"]


static func reserved_names() -> Dictionary:
	var out := {}
	var raw := FileAccess.get_file_as_string(RESERVED_PATH)
	var parsed: Variant = JSON.parse_string(raw)
	if typeof(parsed) != TYPE_DICTIONARY:
		return out
	for key in ["keywords", "lifecycle", "engine"]:
		var arr: Variant = parsed.get(key, [])
		if typeof(arr) != TYPE_ARRAY:
			continue
		for item in arr:
			out[str(item)] = true
	return out


static func secret_hash(hex_secret: String) -> String:
	var clean := hex_secret.strip_edges().to_lower()
	var raw := PackedByteArray()
	var i := 0
	while i + 1 < clean.length():
		raw.append(clean.substr(i, 2).hex_to_int())
		i += 2
	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	ctx.update("fortressgd-v1|".to_utf8_buffer())
	ctx.update(raw)
	return ctx.finish().hex_encode().substr(0, 16)


static func mangled_identifier(original: String, secrethash: String, used: Dictionary, reserved: Dictionary) -> String:
	var attempt := 0
	while true:
		var msg := "%s|%s|%s|%d" % [MANGLE_INFO, secrethash, original, attempt]
		var ctx := HashingContext.new()
		ctx.start(HashingContext.HASH_SHA256)
		ctx.update(msg.to_utf8_buffer())
		var name := "_f" + ctx.finish().hex_encode().substr(0, 10)
		if not reserved.has(name) and not used.has(name):
			return name
		attempt += 1
	return "_fdeadbeef00"


static func is_keep_comment(value: String) -> bool:
	return value.strip_edges().begins_with(KEEP_PREFIX)


static func source_map_path(export_path: String) -> String:
	return str(export_path) + MAP_SUFFIX


static func source_map_text(secrethash: String, mapping: Dictionary) -> String:
	var identifiers := {}
	var keys: Array = mapping.keys()
	keys.sort()
	for k in keys:
		identifiers[str(k)] = str(mapping[k])
	var payload := {
		"version": 1,
		"secret_hash": secrethash,
		"identifiers": identifiers,
	}
	return JSON.stringify(payload, "\t") + "\n"


static func list_gdscript_files() -> PackedStringArray:
	var out := PackedStringArray()
	_walk("res://", out)
	return out


static func apply_project(secrethash: String) -> Dictionary:
	## Returns { ok, error, backups, mapping }. backups: path -> original text.
	var reserved := reserved_names()
	var files := {}
	var backups := {}
	for path in list_gdscript_files():
		var src := FileAccess.get_file_as_string(path)
		files[path] = src
	var hits: Array = []
	var paths: Array = files.keys()
	paths.sort()
	for path in paths:
		hits.append_array(find_unsafe_calls(str(files[path]), str(path)))
	if hits.size() > 0:
		return {"ok": false, "error": _format_unsafe(hits), "backups": {}, "mapping": {}}
	var user := {}
	for path in files.keys():
		for ident in collect_user_identifiers(str(files[path]), reserved):
			user[ident] = true
	var mapping := {}
	var used := reserved.duplicate()
	var originals: Array = user.keys()
	originals.sort()
	for original in originals:
		var name := mangled_identifier(str(original), secrethash, used, reserved)
		mapping[str(original)] = name
		used[name] = true
	for path in files.keys():
		var rewritten := rewrite_source(str(files[path]), mapping, true)
		var original: String = str(files[path])
		if rewritten != original:
			backups[path] = original
			var fh := FileAccess.open(path, FileAccess.WRITE)
			if fh == null:
				restore(backups)
				return {"ok": false, "error": "cannot write mangled %s" % path, "backups": {}, "mapping": {}}
			fh.store_string(rewritten)
			fh.close()
	return {"ok": true, "error": "", "backups": backups, "mapping": mapping}


static func restore(backups: Dictionary) -> void:
	for path in backups.keys():
		var fh := FileAccess.open(str(path), FileAccess.WRITE)
		if fh == null:
			continue
		fh.store_string(str(backups[path]))
		fh.close()


static func write_map(export_path: String, secrethash: String, mapping: Dictionary) -> String:
	var dest := source_map_path(export_path)
	var fh := FileAccess.open(dest, FileAccess.WRITE)
	if fh == null:
		# May be an absolute OS path outside res://.
		fh = FileAccess.open(dest, FileAccess.WRITE)
	if fh == null:
		return ""
	fh.store_string(source_map_text(secrethash, mapping))
	fh.close()
	return dest


static func find_unsafe_calls(source: String, filename: String) -> Array:
	var tokens: Array = tokenize(source)
	var maps := _keep_maps(tokens)
	var keep_same: Dictionary = maps[0]
	var keep_only: Dictionary = maps[1]
	var nonempty: Dictionary = maps[2]
	var hits: Array = []
	var i := 0
	while i < tokens.size():
		var tok: Dictionary = tokens[i]
		if str(tok["kind"]) == KIND_IDENT and str(tok["value"]) in UNSAFE:
			var j := _skip_ws_comments(tokens, i + 1)
			if j < tokens.size() and str(tokens[j]["kind"]) == KIND_PUNCT and str(tokens[j]["value"]) == "(":
				var k := _skip_ws_comments(tokens, j + 1)
				if k < tokens.size() and str(tokens[k]["kind"]) == KIND_STRING:
					if not _line_is_kept(int(tok["line"]), keep_same, keep_only, nonempty):
						hits.append({"path": filename, "line": int(tok["line"]), "kind": str(tok["value"])})
		i += 1
	return hits


static func collect_user_identifiers(source: String, reserved: Dictionary) -> PackedStringArray:
	var tokens: Array = tokenize(source)
	var maps := _keep_maps(tokens)
	var keep_same: Dictionary = maps[0]
	var keep_only: Dictionary = maps[1]
	var nonempty: Dictionary = maps[2]
	var user := {}
	var class_names := {}
	var i := 0
	while i < tokens.size():
		var tok: Dictionary = tokens[i]
		if str(tok["kind"]) != KIND_IDENT:
			i += 1
			continue
		var kept := _line_is_kept(int(tok["line"]), keep_same, keep_only, nonempty)
		if str(tok["value"]) == "class_name":
			var j := _skip_ws_comments(tokens, i + 1)
			if j < tokens.size() and str(tokens[j]["kind"]) == KIND_IDENT:
				class_names[str(tokens[j]["value"])] = true
				i = j + 1
				continue
		if str(tok["value"]) in DECL:
			var j2 := _skip_ws_comments(tokens, i + 1)
			if str(tok["value"]) == "enum":
				i = _collect_enum(tokens, i, j2, user, reserved, kept, class_names)
				continue
			if j2 < tokens.size() and str(tokens[j2]["kind"]) == KIND_IDENT:
				var name := str(tokens[j2]["value"])
				var name_kept := kept or _line_is_kept(int(tokens[j2]["line"]), keep_same, keep_only, nonempty)
				if not reserved.has(name) and not class_names.has(name) and not name_kept:
					user[name] = true
				if str(tok["value"]) == "func":
					var k := _skip_ws_comments(tokens, j2 + 1)
					if k < tokens.size() and str(tokens[k]["kind"]) == KIND_PUNCT and str(tokens[k]["value"]) == "(":
						_collect_params(tokens, k + 1, user, reserved, class_names)
				i = j2 + 1
				continue
			i += 1
			continue
		i += 1
	var out := PackedStringArray()
	for ident in user.keys():
		if reserved.has(ident) or class_names.has(ident):
			continue
		out.append(str(ident))
	return out


static func rewrite_source(source: String, mapping: Dictionary, strip: bool) -> String:
	var tokens: Array = tokenize(source)
	if strip:
		tokens = _strip_tokens(tokens)
	var out := ""
	for tok in tokens:
		var t: Dictionary = tok
		if str(t["kind"]) == KIND_IDENT and mapping.has(str(t["value"])):
			out += str(mapping[str(t["value"])])
		else:
			out += str(t["value"])
	return out


static func tokenize(source: String) -> Array:
	var tokens: Array = []
	var i := 0
	var n := source.length()
	var line := 1
	var col := 1
	while i < n:
		var ch := source[i]
		var sl := line
		var sc := col
		if ch == "\r":
			if i + 1 < n and source[i + 1] == "\n":
				tokens.append(_tok(KIND_NEWLINE, "\r\n", sl, sc))
				i += 2
			else:
				tokens.append(_tok(KIND_NEWLINE, "\r", sl, sc))
				i += 1
			line += 1
			col = 1
			continue
		if ch == "\n":
			tokens.append(_tok(KIND_NEWLINE, "\n", sl, sc))
			i += 1
			line += 1
			col = 1
			continue
		if ch == " " or ch == "\t":
			var j := i
			while j < n and (source[j] == " " or source[j] == "\t"):
				j += 1
			tokens.append(_tok(KIND_SPACE, source.substr(i, j - i), sl, sc))
			col += j - i
			i = j
			continue
		if ch == "#":
			var c := i
			while c < n and source[c] != "\r" and source[c] != "\n":
				c += 1
			tokens.append(_tok(KIND_COMMENT, source.substr(i, c - i), sl, sc))
			col += c - i
			i = c
			continue
		if ch == "\"" or ch == "'":
			var sres := _read_string(source, i, line, col)
			tokens.append(_tok(KIND_STRING, str(sres[0]), sl, sc))
			i = int(sres[1])
			line = int(sres[2])
			col = int(sres[3])
			continue
		if ch == "@" and i + 1 < n and _is_ident_start(source[i + 1]):
			var a := i + 2
			while a < n and _is_ident_cont(source[a]):
				a += 1
			tokens.append(_tok(KIND_ANNOTATION, source.substr(i, a - i), sl, sc))
			col += a - i
			i = a
			continue
		if ch == "$" or ch == "%":
			var nres := _read_nodepath(source, i, line, col)
			tokens.append(_tok(KIND_NODEPATH, str(nres[0]), sl, sc))
			i = int(nres[1])
			line = int(nres[2])
			col = int(nres[3])
			continue
		if (ch == "&" or ch == "^") and i + 1 < n and (source[i + 1] == "\"" or source[i + 1] == "'"):
			col += 1
			i += 1
			var sres2 := _read_string(source, i, line, col)
			tokens.append(_tok(KIND_STRING, ch + str(sres2[0]), sl, sc))
			i = int(sres2[1])
			line = int(sres2[2])
			col = int(sres2[3])
			continue
		if _is_ident_start(ch):
			var id := i + 1
			while id < n and _is_ident_cont(source[id]):
				id += 1
			tokens.append(_tok(KIND_IDENT, source.substr(i, id - i), sl, sc))
			col += id - i
			i = id
			continue
		if _is_digit(ch):
			var num := i + 1
			while num < n and (_is_ident_cont(source[num]) or source[num] == "."):
				num += 1
			tokens.append(_tok(KIND_NUMBER, source.substr(i, num - i), sl, sc))
			col += num - i
			i = num
			continue
		tokens.append(_tok(KIND_PUNCT, ch, sl, sc))
		col += 1
		i += 1
	return tokens


static func _tok(kind: String, value: String, line: int, col: int) -> Dictionary:
	return {"kind": kind, "value": value, "line": line, "col": col}


static func _is_ident_start(ch: String) -> bool:
	var c := ch.unicode_at(0)
	return (c >= 65 and c <= 90) or (c >= 97 and c <= 122) or c == 95


static func _is_ident_cont(ch: String) -> bool:
	var c := ch.unicode_at(0)
	return _is_ident_start(ch) or (c >= 48 and c <= 57)


static func _is_digit(ch: String) -> bool:
	var c := ch.unicode_at(0)
	return c >= 48 and c <= 57


static func _read_string(source: String, i: int, line: int, col: int) -> Array:
	var n := source.length()
	var quote := source[i]
	var triple := i + 2 < n and source.substr(i, 3) == quote + quote + quote
	var start := i
	if triple:
		i += 3
		col += 3
		while i < n:
			if source[i] == "\n":
				line += 1
				col = 1
				i += 1
				continue
			if source[i] == "\r":
				line += 1
				col = 1
				i += 1
				if i < n and source[i] == "\n":
					i += 1
				continue
			if source.substr(i, 3) == quote + quote + quote:
				i += 3
				col += 3
				break
			if source[i] == "\\" and i + 1 < n:
				i += 2
				col += 2
				continue
			i += 1
			col += 1
	else:
		i += 1
		col += 1
		while i < n:
			var ch := source[i]
			if ch == "\n":
				line += 1
				col = 1
				i += 1
				continue
			if ch == "\\":
				i += 2 if i + 1 < n else 1
				col += 2
				continue
			i += 1
			col += 1
			if ch == quote:
				break
	return [source.substr(start, i - start), i, line, col]


static func _read_nodepath(source: String, i: int, line: int, col: int) -> Array:
	var start := i
	i += 1
	col += 1
	var n := source.length()
	if i < n and (source[i] == "\"" or source[i] == "'"):
		var sres := _read_string(source, i, line, col)
		i = int(sres[1])
		line = int(sres[2])
		col = int(sres[3])
		return [source.substr(start, i - start), i, line, col]
	if i < n and _is_ident_start(source[i]):
		while i < n:
			if _is_ident_cont(source[i]):
				i += 1
				col += 1
				continue
			if source[i] == "/" and i + 1 < n and _is_ident_start(source[i + 1]):
				i += 1
				col += 1
				continue
			break
	return [source.substr(start, i - start), i, line, col]


static func _skip_ws_comments(tokens: Array, i: int) -> int:
	while i < tokens.size() and str(tokens[i]["kind"]) in [KIND_SPACE, KIND_NEWLINE, KIND_COMMENT]:
		i += 1
	return i


static func _keep_maps(tokens: Array) -> Array:
	var by_line := {}
	for tok in tokens:
		var t: Dictionary = tok
		var ln := int(t["line"])
		if not by_line.has(ln):
			by_line[ln] = []
		by_line[ln].append(t)
	var keep_same := {}
	var keep_only := {}
	var nonempty := {}
	for line in by_line.keys():
		var saw_keep := false
		var saw_code := false
		for tok in by_line[line]:
			var t2: Dictionary = tok
			var kind := str(t2["kind"])
			if kind == KIND_SPACE or kind == KIND_NEWLINE:
				continue
			if kind == KIND_COMMENT:
				if is_keep_comment(str(t2["value"])):
					saw_keep = true
				continue
			saw_code = true
		if saw_keep or saw_code:
			nonempty[line] = true
		if saw_keep:
			keep_same[line] = true
			if not saw_code:
				keep_only[line] = true
	return [keep_same, keep_only, nonempty]


static func _line_is_kept(line: int, keep_same: Dictionary, keep_only: Dictionary, nonempty: Dictionary) -> bool:
	if keep_same.has(line):
		return true
	var prev := line - 1
	while prev >= 1:
		if nonempty.has(prev):
			return keep_only.has(prev)
		prev -= 1
	return false


static func _prev_code(tokens: Array, i: int) -> Variant:
	var j := i - 1
	while j >= 0 and str(tokens[j]["kind"]) in [KIND_SPACE, KIND_NEWLINE, KIND_COMMENT]:
		j -= 1
	if j < 0:
		return null
	return tokens[j]


static func _collect_params(tokens: Array, start: int, user: Dictionary, reserved: Dictionary, class_names: Dictionary) -> void:
	var i := start
	var depth := 1
	var arg_start := true
	while i < tokens.size() and depth > 0:
		var tok: Dictionary = tokens[i]
		var kind := str(tok["kind"])
		var val := str(tok["value"])
		if kind == KIND_PUNCT:
			if val in ["(", "[", "{"]:
				depth += 1
			elif val in [")", "]", "}"]:
				depth -= 1
				if depth <= 0:
					break
			elif val == "," and depth == 1:
				arg_start = true
		elif kind == KIND_IDENT and depth == 1 and arg_start:
			if not reserved.has(val) and not class_names.has(val):
				user[val] = true
			arg_start = false
		i += 1


static func _collect_enum(tokens: Array, keyword_index: int, after_kw: int, user: Dictionary, reserved: Dictionary, kept: bool, class_names: Dictionary) -> int:
	var i := after_kw
	if i < tokens.size() and str(tokens[i]["kind"]) == KIND_IDENT:
		var name := str(tokens[i]["value"])
		if not reserved.has(name) and not class_names.has(name) and not kept:
			user[name] = true
		i += 1
		i = _skip_ws_comments(tokens, i)
	if i < tokens.size() and str(tokens[i]["kind"]) == KIND_PUNCT and str(tokens[i]["value"]) == "{":
		i += 1
		var depth := 1
		var member_start := true
		while i < tokens.size() and depth > 0:
			var tok: Dictionary = tokens[i]
			var kind := str(tok["kind"])
			var val := str(tok["value"])
			if kind == KIND_PUNCT:
				if val == "{":
					depth += 1
				elif val == "}":
					depth -= 1
				elif val == "," and depth == 1:
					member_start = true
				elif val == "=" and depth == 1:
					member_start = false
			elif kind == KIND_IDENT and depth == 1 and member_start:
				if not reserved.has(val) and not class_names.has(val) and not kept:
					user[val] = true
				member_start = false
			i += 1
		return i
	return maxi(keyword_index + 1, i)


static func _strip_tokens(tokens: Array) -> Array:
	var out: Array = []
	var i := 0
	while i < tokens.size():
		var tok: Dictionary = tokens[i]
		var kind := str(tok["kind"])
		var val := str(tok["value"])
		if kind == KIND_COMMENT:
			i += 1
			continue
		if kind == KIND_IDENT and val in ["assert", "print_debug"]:
			var prev: Variant = _prev_code(tokens, i)
			var dotted := typeof(prev) == TYPE_DICTIONARY and str(prev["kind"]) == KIND_PUNCT and str(prev["value"]) == "."
			var j := _skip_ws_comments(tokens, i + 1)
			if not dotted and j < tokens.size() and str(tokens[j]["kind"]) == KIND_PUNCT and str(tokens[j]["value"]) == "(":
				var k := _consume_paren_group(tokens, j)
				i = _skip_trailing_semi(tokens, k)
				continue
		if kind == KIND_IDENT and val == "breakpoint":
			var prev2: Variant = _prev_code(tokens, i)
			var dotted2 := typeof(prev2) == TYPE_DICTIONARY and str(prev2["kind"]) == KIND_PUNCT and str(prev2["value"]) == "."
			if not dotted2:
				i = _skip_trailing_semi(tokens, i + 1)
				continue
		out.append(tok)
		i += 1
	return out


static func _consume_paren_group(tokens: Array, open_index: int) -> int:
	var i := open_index
	var depth := 0
	while i < tokens.size():
		var tok: Dictionary = tokens[i]
		if str(tok["kind"]) == KIND_PUNCT:
			if str(tok["value"]) == "(":
				depth += 1
			elif str(tok["value"]) == ")":
				depth -= 1
				i += 1
				if depth <= 0:
					return i
				continue
		i += 1
	return i


static func _skip_trailing_semi(tokens: Array, i: int) -> int:
	var j := i
	while j < tokens.size() and str(tokens[j]["kind"]) == KIND_SPACE:
		j += 1
	if j < tokens.size() and str(tokens[j]["kind"]) == KIND_PUNCT and str(tokens[j]["value"]) == ";":
		return j + 1
	return i


static func _format_unsafe(hits: Array) -> String:
	var parts: PackedStringArray = PackedStringArray()
	var kinds := {}
	for hit in hits:
		var h: Dictionary = hit
		parts.append("%s:%d" % [str(h["path"]), int(h["line"])])
		kinds[str(h["kind"])] = true
	var kind_list: Array = kinds.keys()
	kind_list.sort()
	return "unsafe %s(\"…\") at %s (use a Callable, or mark with ## fortressgd:keep)" % [
		", ".join(PackedStringArray(kind_list)).replace(", ", "/"),
		", ".join(parts),
	]


static func join_dir(dir_path: String, name: String) -> String:
	# String.path_join keeps a trailing slash, so "res://" + file stays "res://file".
	# rstrip("/") would collapse res:// to res: and yield the invalid res:/file.
	return dir_path.path_join(name)


static func refuse_export_artifact(export_path: String) -> PackedStringArray:
	## Delete the finished export so an aborted run cannot ship original scripts.
	## Called from EditorExportPlugin._export_end (after save_pack closes the file).
	var removed := PackedStringArray()
	if export_path == "":
		return removed
	var paths := PackedStringArray()
	paths.append(export_path)
	var lower := export_path.to_lower()
	if not (lower.ends_with(".pck") or lower.ends_with(".zip")):
		paths.append(export_path.get_basename() + ".pck")
	for p in paths:
		if p != "" and FileAccess.file_exists(p):
			var err := DirAccess.remove_absolute(p)
			if err == OK:
				removed.append(p)
	return removed


static func _walk(dir_path: String, out: PackedStringArray) -> void:
	var d := DirAccess.open(dir_path)
	if d == null:
		return
	d.list_dir_begin()
	var name := d.get_next()
	while name != "":
		if name.begins_with("."):
			name = d.get_next()
			continue
		var child := join_dir(dir_path, name)
		var rel := child
		if rel.begins_with("res://"):
			rel = rel.substr(6)
		if rel == PLUGIN_ADDON or rel.begins_with(PLUGIN_ADDON + "/"):
			name = d.get_next()
			continue
		if d.current_is_dir():
			if name == ".godot":
				name = d.get_next()
				continue
			_walk(child, out)
		elif name.ends_with(".gd"):
			out.append(child)
		name = d.get_next()
	d.list_dir_end()
