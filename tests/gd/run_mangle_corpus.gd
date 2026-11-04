extends SceneTree
## Runs plugin/addons/fortressgd/mangle.gd on tests/mangle_corpus and prints one
## result line per case: "FGD_CORPUS " + JSON {case, ok, error, sources, mapping}.
## Usage (from tests/test_mangle_corpus.py):
##   godot --headless --path <project> --script res://run_mangle_corpus.gd -- <corpus_dir> <secret_hash>

const FGDMangle := preload("res://addons/fortressgd/mangle.gd")


func _init() -> void:
	var args := OS.get_cmdline_user_args()
	if args.size() < 2:
		push_error("usage: -- <corpus_dir> <secret_hash>")
		quit(2)
		return
	var corpus: String = args[0]
	var secrethash: String = args[1]
	var cases := PackedStringArray()
	var d := DirAccess.open(corpus)
	if d == null:
		push_error("cannot open corpus %s" % corpus)
		quit(2)
		return
	for entry in d.get_directories():
		if DirAccess.dir_exists_absolute(corpus.path_join(entry).path_join("input")):
			cases.append(entry)
	cases.sort()
	for case_name in cases:
		var case_dir := corpus.path_join(case_name)
		var files := {}
		_read_tree(case_dir.path_join("input"), "", files)
		var exclude := {}
		var exclude_path := case_dir.path_join("exclude.txt")
		if FileAccess.file_exists(exclude_path):
			for line in FileAccess.get_file_as_string(exclude_path).split("\n"):
				var excluded_name := line.strip_edges()
				if excluded_name != "":
					exclude[excluded_name] = true
		var result: Dictionary = FGDMangle.mangle_sources(files, secrethash, exclude)
		result["case"] = case_name
		print("FGD_CORPUS " + JSON.stringify(result))
	quit(0)


func _read_tree(base: String, rel: String, out: Dictionary) -> void:
	var here := base if rel == "" else base.path_join(rel)
	var d := DirAccess.open(here)
	if d == null:
		return
	for file_name in d.get_files():
		if file_name.ends_with(".gd"):
			var key := file_name if rel == "" else rel.path_join(file_name)
			out[key] = FileAccess.get_file_as_string(here.path_join(file_name))
	for dir_name in d.get_directories():
		_read_tree(base, dir_name if rel == "" else rel.path_join(dir_name), out)
