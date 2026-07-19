# CLI JSON output contract

Lvau 0.5.0 introduces JSON schema version 1 for automation-facing commands.

Successful output has this top-level shape:

```json
{
  "schema_version": 1,
  "command": "inspect",
  "status": "ok",
  "data": {}
}
```

Error documents use `status: "error"` and an `error` object containing stable `code` and human-readable `message` fields. Existing process exit codes remain authoritative for success or failure.

The generic schema is stored at `schemas/lvau-cli-output-v1.schema.json`. Fields inside `data` are command-specific. New fields may be added compatibly within schema version 1, while removal or semantic reinterpretation requires a new schema version.
