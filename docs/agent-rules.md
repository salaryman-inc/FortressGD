# Agent rules for FortressGD projects

Rules for AI coding agents (and humans) working in a Godot project that ships through FortressGD. Production exports may mangle GDScript identifiers when `[production].mangle_scripts` is true.

## Use Callables, not string `call` / `rpc`

Do not write `call("name")`, `rpc("name")`, or other string-dispatched method names. After mangling, those strings still name the old identifier and the packed game breaks.

Use a `Callable` instead:

```gdscript
my_attack()
my_attack.call()
do_thing.bind(arg)
rpc_id.rpc()  # typed rpc via Callable, not rpc("do_thing")
```

If a third-party API truly requires a string method name, mark that usage:

```gdscript
## fortressgd:keep
call("public_mod_hook")
```

Unmarked `call("…")` / `rpc("…")` / `set("…")` **fail the export** with file:line.

## No secrets under `res://`

Never put the project secret, `aes_key`, API tokens, or other credentials in anything Godot packs (`res://`, scenes, scripts, `export_presets.cfg`). The 32-byte FortressGD secret lives in `.fortressgd.secret` (gitignored) or `FORTRESSGD_SECRET`. Source maps (`*.fortressgd.map.json`) are written to `.fortressgd/maps/` in the project, never packed and never next to the export. Do not copy them into a build folder or commit them: a map reverses all mangling.

## Prefer direct access over string `set` / `get`

Prefer assigning the property, or a setter method as a Callable, over `set("prop", value)` / `get("prop")`. Unmarked `set("…")` still fails the export.

Member names written as **string literals** anywhere in the project's scripts are left unmangled automatically, so `emit_signal("hit")`, `get("hp")`, `has_method("go")`, `Callable(self, "go")`, `&"go"`, `^".:hp"` and `"speed:x"` keep working. The mangler keeps every identifier-shaped piece of a string (split on `:`, `/` and `.`) out of the rename map.

Names **built at runtime** cannot be seen: `call("on_" + event)` or `get(prefix + "_hp")` still break after mangling. Mark the declaration of each such member with `## fortressgd:keep` so it is not renamed:

```gdscript
## fortressgd:keep
func on_jump() -> void:
	pass
```

## Names scenes and autoloads use are kept

Names that scenes and resources refer to are left unmangled automatically: `@export` vars, methods connected in the editor, AnimationPlayer method and property tracks, and autoload names. The mangler keeps every identifier that appears in a `.tscn`, `.tres` or `project.godot` out of the rename map. Binary `.scn` / `.res` files cannot be scanned: export prints a warning for each. Save scenes and resources as text (`.tscn` / `.tres`) when mangling is on.
