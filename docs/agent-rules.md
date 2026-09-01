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

Never put the project secret, `aes_key`, API tokens, or other credentials in anything Godot packs (`res://`, scenes, scripts, `export_presets.cfg`). The 32-byte FortressGD secret lives in `.fortressgd.secret` (gitignored) or `FORTRESSGD_SECRET`. Source maps (`*.fortressgd.map.json`) stay next to the export artifact and are not packed.

## No string `set` / `get` for user properties

Do not write `set("prop", value)` or `get("prop")` for properties you declared. Those strings are not renamed. Assign the property, use a setter method as a Callable, or mark a required string usage with `## fortressgd:keep`.
