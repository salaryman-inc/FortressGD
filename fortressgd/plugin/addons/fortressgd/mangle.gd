@tool
extends RefCounted
## Identifier mangling + unsafe call/rpc/set scan (DESIGN.md §9).
## Algorithm matches core/mangle.py (HMAC under the mangler key, keep annotation, reserved JSON).

const RESERVED_PATH := "res://addons/fortressgd/mangle_reserved.json"
const KEEP_PREFIX := "## fortressgd:keep"
# v2: names are an HMAC under a key derived from the project secret, not a hash
# of the public secret_hash. Must match core/mangle.py.
const MANGLE_INFO := "fortressgd-mangle-v2"
const MANGLE_KEY_INFO := "fortressgd.mangle.key.v1"
const PLUGIN_ADDON := "addons/fortressgd"
const ADDONS_DIR := "addons"
const MAP_SUFFIX := ".fortressgd.map.json"
# Source maps go here, never next to the artifact. Matches core/mangle.py MAP_DIR.
const MAP_DIR := ".fortressgd/maps"

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
# Text files that refer to script members by name (scenes, resources, autoloads).
const TEXT_RESOURCE_SUFFIXES := [".tscn", ".tres"]
const TEXT_RESOURCE_NAMES := ["project.godot"]
# Binary resources can hold the same references but cannot be scanned as text.
const BINARY_RESOURCE_SUFFIXES := [".scn", ".res"]
# @export_* annotations that group inspector entries and declare no var.
const EXPORT_NON_DECL := ["@export_group", "@export_subgroup", "@export_category"]
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


static func _secret_bytes(hex_secret: String) -> PackedByteArray:
	var clean := hex_secret.strip_edges().to_lower()
	var raw := PackedByteArray()
	var i := 0
	while i + 1 < clean.length():
		raw.append(clean.substr(i, 2).hex_to_int())
		i += 2
	return raw


static func secret_hash(hex_secret: String) -> String:
	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	ctx.update("fortressgd-v1|".to_utf8_buffer())
	ctx.update(_secret_bytes(hex_secret))
	return ctx.finish().hex_encode().substr(0, 16)


## The mangler's key: hex HMAC-SHA256(secret, MANGLE_KEY_INFO). Mirrors
## core/mangle.py derive_mangle_key. Secret material: never print or store it.
static func mangle_key(hex_secret: String) -> String:
	var crypto := Crypto.new()
	return crypto.hmac_digest(HashingContext.HASH_SHA256, _secret_bytes(hex_secret), MANGLE_KEY_INFO.to_utf8_buffer()).hex_encode()


static func mangled_identifier(original: String, key: String, used: Dictionary, reserved: Dictionary) -> String:
	var crypto := Crypto.new()
	var key_bytes := key.to_utf8_buffer()
	var attempt := 0
	while true:
		var msg := "%s|%s|%d" % [MANGLE_INFO, original, attempt]
		var digest := crypto.hmac_digest(HashingContext.HASH_SHA256, key_bytes, msg.to_utf8_buffer())
		var name := "_f" + digest.hex_encode().substr(0, 10)
		if not reserved.has(name) and not used.has(name):
			return name
		attempt += 1
	return "_fdeadbeef00"


static func is_keep_comment(value: String) -> bool:
	return value.strip_edges().begins_with(KEEP_PREFIX)


## Mirrors core/mangle.py source_map_path: <project>/.fortressgd/maps/ plus the
## export path's place in the project, or _external/<file>-<hash> outside it.
static func source_map_path(project_root: String, export_path: String) -> String:
	var root := project_root.replace("\\", "/").simplify_path()
	if root.ends_with("/"):
		root = root.substr(0, root.length() - 1)
	var target := export_path.replace("\\", "/")
	if target.begins_with("res://"):
		target = target.substr(6)
	if target.is_relative_path():
		target = root + "/" + target
	target = target.simplify_path()
	var name := ""
	if target.begins_with(root + "/"):
		name = target.substr(root.length() + 1)
	else:
		var ctx := HashingContext.new()
		ctx.start(HashingContext.HASH_SHA256)
		ctx.update(target.to_utf8_buffer())
		name = "_external/%s-%s" % [target.get_file(), ctx.finish().hex_encode().substr(0, 8)]
	return root + "/" + MAP_DIR + "/" + name + MAP_SUFFIX


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


## Game scripts to mangle. Never anything under addons/ (third-party plugin code).
static func list_gdscript_files() -> PackedStringArray:
	var out := PackedStringArray()
	_walk("res://", out)
	return out


## Addon scripts: never rewritten, only scanned so the names they mention stay
## unmangled in game scripts. The FortressGD addon is never packed and is skipped.
static func list_scan_only_gdscript_files() -> PackedStringArray:
	var out := PackedStringArray()
	var all_files := PackedStringArray()
	_walk_all("res://" + ADDONS_DIR, all_files)
	for path in all_files:
		var res_path: String = path
		var rel := res_path.substr(6) if res_path.begins_with("res://") else res_path
		if not res_path.ends_with(".gd"):
			continue
		if rel == PLUGIN_ADDON or rel.begins_with(PLUGIN_ADDON + "/"):
			continue
		out.append(res_path)
	return out


## Every identifier token and identifier-shaped string piece in addon scripts.
## Dictionary used as a set. Mirrors core/mangle.py collect_scan_only_names.
static func collect_scan_only_names(sources: Array) -> Dictionary:
	var names := {}
	for src in sources:
		var source: String = src
		for tok in tokenize(source):
			var t: Dictionary = tok
			if str(t["kind"]) == KIND_IDENT:
				names[str(t["value"])] = true
		names.merge(collect_string_identifier_names(source))
	return names


static func apply_project(key: String) -> Dictionary:
	## Returns { ok, error, backups, mapping }. backups: path -> original text.
	var files := {}
	var backups := {}
	for path in list_gdscript_files():
		var src := FileAccess.get_file_as_string(path)
		files[path] = src
	# Project-wide names that scenes, resources, project.godot and addon scripts
	# mention: never renamed. Mirrors core/export.py.
	var exclude := {}
	exclude.merge(collect_resource_reference_names())
	var addon_sources: Array = []
	for addon_path in list_scan_only_gdscript_files():
		addon_sources.append(FileAccess.get_file_as_string(addon_path))
	exclude.merge(collect_scan_only_names(addon_sources))
	for res_path in binary_resource_paths():
		push_warning("FortressGD: cannot scan binary resource %s for mangled names" % res_path)
	var result := mangle_sources(files, key, exclude)
	if not result.get("ok", false):
		return {"ok": false, "error": str(result.get("error", "mangle failed")), "backups": {}, "mapping": {}}
	var sources: Dictionary = result["sources"]
	for path in files.keys():
		var rewritten: String = sources[path]
		var original: String = str(files[path])
		if rewritten != original:
			backups[path] = original
			var fh := FileAccess.open(path, FileAccess.WRITE)
			if fh == null:
				restore(backups)
				return {"ok": false, "error": "cannot write mangled %s" % path, "backups": {}, "mapping": {}}
			fh.store_string(rewritten)
			fh.close()
	return {"ok": true, "error": "", "backups": backups, "mapping": result["mapping"]}


## Pure transform: no file I/O. files maps path -> source text; exclude is a
## Dictionary set of names never to rename. Returns
## { ok, error, sources: path -> mangled text, mapping: original -> mangled }.
## Mirrors core/mangle.py mangle_scripts; tests/mangle_corpus checks both.
static func mangle_sources(files: Dictionary, key: String, exclude: Dictionary = {}) -> Dictionary:
	var reserved := reserved_names()
	var hits: Array = []
	var paths: Array = files.keys()
	paths.sort()
	for path in paths:
		hits.append_array(find_unsafe_calls(str(files[path]), str(path)))
	if hits.size() > 0:
		return {"ok": false, "error": _format_unsafe(hits), "sources": {}, "mapping": {}}
	var user := {}
	for path in files.keys():
		for ident in collect_user_identifiers(str(files[path]), reserved):
			user[ident] = true
	# A name is renamed everywhere or nowhere. Drop every name that something
	# may reference in a way the rewrite cannot follow.
	var excluded := exclude.duplicate()
	for path in files.keys():
		excluded.merge(collect_foreign_member_names(str(files[path])))
		excluded.merge(collect_string_identifier_names(str(files[path])))
	for name in excluded.keys():
		user.erase(name)
	var mapping := {}
	var used := reserved.duplicate()
	var originals: Array = user.keys()
	originals.sort()
	for original in originals:
		var name := mangled_identifier(str(original), key, used, reserved)
		mapping[str(original)] = name
		used[name] = true
	var sources := {}
	for path in files.keys():
		sources[path] = rewrite_source(str(files[path]), mapping, true)
	return {"ok": true, "error": "", "sources": sources, "mapping": mapping}


static func restore(backups: Dictionary) -> void:
	for path in backups.keys():
		var fh := FileAccess.open(str(path), FileAccess.WRITE)
		if fh == null:
			continue
		fh.store_string(str(backups[path]))
		fh.close()


static func write_map(export_path: String, secrethash: String, mapping: Dictionary) -> String:
	var root := ProjectSettings.globalize_path("res://")
	var dest := source_map_path(root, export_path)
	if DirAccess.make_dir_recursive_absolute(dest.get_base_dir()) != OK:
		return ""
	# Keep Godot from importing or packing the maps.
	var gdignore := root.path_join(".fortressgd/.gdignore")
	if not FileAccess.file_exists(gdignore):
		var marker := FileAccess.open(gdignore, FileAccess.WRITE)
		if marker != null:
			marker.close()
	var fh := FileAccess.open(dest, FileAccess.WRITE)
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
				# Scenes store @export values under the property's original name.
				var exported := str(tok["value"]) == "var" and _has_export_annotation(tokens, i)
				if not reserved.has(name) and not class_names.has(name) and not name_kept and not exported:
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


## Names accessed as `receiver.name` through a receiver other than self/super.
## Returns a Dictionary used as a set. Mirrors core/mangle.py.
static func collect_foreign_member_names(source: String) -> Dictionary:
	var tokens: Array = tokenize(source)
	var names := {}
	for i in range(tokens.size()):
		var tok: Dictionary = tokens[i]
		if str(tok["kind"]) != KIND_IDENT:
			continue
		var dot := _prev_code_index(tokens, i)
		if dot < 0 or str(tokens[dot]["kind"]) != KIND_PUNCT or str(tokens[dot]["value"]) != ".":
			continue
		var recv := _prev_code_index(tokens, dot)
		if recv >= 0 and str(tokens[recv]["kind"]) == KIND_IDENT and str(tokens[recv]["value"]) in ["self", "super"]:
			continue
		names[str(tok["value"])] = true
	return names


## Identifier-shaped pieces of every string literal (split on `:`, `/`, `.`), so
## string-based reflection keeps working. Dictionary used as a set. Mirrors core/mangle.py.
static func collect_string_identifier_names(source: String) -> Dictionary:
	var names := {}
	for tok in tokenize(source):
		var t: Dictionary = tok
		if str(t["kind"]) != KIND_STRING:
			continue
		var text := str(t["value"])
		if text.begins_with("&") or text.begins_with("^"):
			text = text.substr(1)
		for q in ["\"\"\"", "'''", "\"", "'"]:
			var quote: String = q
			if text.begins_with(quote):
				text = text.substr(quote.length())
				if text.ends_with(quote):
					text = text.substr(0, text.length() - quote.length())
				break
		for piece in text.replace(":", "/").replace(".", "/").split("/"):
			if _is_identifier(piece):
				names[piece] = true
	return names


static func _is_identifier(text: String) -> bool:
	if text == "" or not _is_ident_start(text[0]):
		return false
	for c in range(1, text.length()):
		if not _is_ident_cont(text[c]):
			return false
	return true


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


## True when the `var` at var_index carries an @export* annotation, on the same
## line or the lines right above. @export_group / _subgroup / _category do not count.
static func _has_export_annotation(tokens: Array, var_index: int) -> bool:
	var j := _prev_code_index(tokens, var_index)
	while j >= 0:
		var kind := str(tokens[j]["kind"])
		var val := str(tokens[j]["value"])
		if kind == KIND_PUNCT and val == ")":
			var depth := 0
			while j >= 0:
				if str(tokens[j]["kind"]) == KIND_PUNCT and str(tokens[j]["value"]) == ")":
					depth += 1
				elif str(tokens[j]["kind"]) == KIND_PUNCT and str(tokens[j]["value"]) == "(":
					depth -= 1
					if depth == 0:
						break
				j -= 1
			j = _prev_code_index(tokens, j)
			if j < 0 or str(tokens[j]["kind"]) != KIND_ANNOTATION:
				return false
			continue
		if kind != KIND_ANNOTATION:
			return false
		if val.begins_with("@export") and not (val in EXPORT_NON_DECL):
			return true
		j = _prev_code_index(tokens, j)
	return false


static func _prev_code_index(tokens: Array, i: int) -> int:
	var j := i - 1
	while j >= 0 and str(tokens[j]["kind"]) in [KIND_SPACE, KIND_NEWLINE, KIND_COMMENT]:
		j -= 1
	return j


static func _prev_code(tokens: Array, i: int) -> Variant:
	var j := _prev_code_index(tokens, i)
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


# Drop comments; replace assert / print_debug / breakpoint statements with `pass`
# so a block whose only statement was stripped still parses. Mirrors core/mangle.py.
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
				out.append(_tok(KIND_IDENT, "pass", int(tok["line"]), int(tok["col"])))
				i = _skip_trailing_semi(tokens, k)
				continue
		if kind == KIND_IDENT and val == "breakpoint":
			var prev2: Variant = _prev_code(tokens, i)
			var dotted2 := typeof(prev2) == TYPE_DICTIONARY and str(prev2["kind"]) == KIND_PUNCT and str(prev2["value"]) == "."
			if not dotted2:
				out.append(_tok(KIND_IDENT, "pass", int(tok["line"]), int(tok["col"])))
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


## Every identifier in the project's .tscn / .tres files and project.godot. Scenes
## and resources name @export values, connected methods, animation tracks and
## autoloads by their original text. Dictionary used as a set. Mirrors core/mangle.py.
static func collect_resource_reference_names() -> Dictionary:
	var names := {}
	var re := RegEx.new()
	re.compile("[A-Za-z_][A-Za-z0-9_]*")
	var all_files := PackedStringArray()
	_walk_all("res://", all_files)
	for path in all_files:
		var res_path: String = path
		var wanted: bool = res_path.get_file() in TEXT_RESOURCE_NAMES
		for suffix in TEXT_RESOURCE_SUFFIXES:
			if res_path.ends_with(str(suffix)):
				wanted = true
		if not wanted:
			continue
		var text: String = FileAccess.get_file_as_string(res_path)
		for m in re.search_all(text):
			var found: RegExMatch = m
			names[found.get_string()] = true
	return names


## res:// paths of *.scn / *.res files, which reference scanning cannot read.
static func binary_resource_paths() -> PackedStringArray:
	var out := PackedStringArray()
	var all_files := PackedStringArray()
	_walk_all("res://", all_files)
	for path in all_files:
		var res_path: String = path
		for suffix in BINARY_RESOURCE_SUFFIXES:
			if res_path.ends_with(str(suffix)):
				out.append(res_path)
	return out


## Every file under dir_path, skipping dot entries (.godot, .git, ...) like _walk.
static func _walk_all(dir_path: String, out: PackedStringArray) -> void:
	var d := DirAccess.open(dir_path)
	if d == null:
		return
	d.list_dir_begin()
	var name := d.get_next()
	while name != "":
		if name.begins_with(".") or name == "__pycache__":
			name = d.get_next()
			continue
		var child := join_dir(dir_path, name)
		if d.current_is_dir():
			_walk_all(child, out)
		else:
			out.append(child)
		name = d.get_next()
	d.list_dir_end()


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
		# Nothing under addons/ is rewritten (this includes addons/fortressgd).
		if rel == ADDONS_DIR or rel.begins_with(ADDONS_DIR + "/"):
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
