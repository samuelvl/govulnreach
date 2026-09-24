# Analyzer behavior fixtures

The fixtures show supported analyzer behavior. Each behavior has one directory
under `cases/`.

## Directory categories

- `reachable/` contains findings that the analyzer can reach.
- `unreachable/` contains findings that the analyzer can disprove.
- `unknown/` contains findings that need investigation.
- `advisory-level/` contains module and package findings without symbol paths.
- `module-graph/` contains version and dependency graph behavior.

Each case directory must contain:

- `advisory.json`, a small synthetic OSV advisory.
- `case.json`, the expected analyzer result.
- Go source files and, when needed, a `go.mod` file.

The manifest uses these fields:

```json
{
  "description": "A short description",
  "source": ".",
  "package": ".",
  "expected": {
    "status": "affected",
    "reachability": "reachable",
    "justification": "",
    "finding_level": "symbol",
    "finding_outcome": "reachable",
    "call_path_contains": ["example.com/vulnerable/parser.WriteJSON"]
  }
}
```

`source` defaults to the case directory. `package` defaults to `.`.
`justification`, `finding_level`, `finding_outcome`, and
`call_path_contains` default to empty values.

Use identifiers such as `GO-TEST-DIRECT-CALL` for synthetic advisories.
Use paths under `example.com` for synthetic modules and packages.

Normal cases use the shared module in `cases/go.mod`. Put reusable fake
dependencies under `modules/`. Use an isolated `app/go.mod` when a case needs
a different module version, a replacement, or a missing dependency.

The test discovers every `case.json` under `cases/` and uses its relative
directory as the subtest name. The test sorts cases and runs them serially.

## Add a case

1. Create a directory under the category that matches the behavior.
2. Add a synthetic `advisory.json`.
3. Add a `case.json` with the expected status and reachability.
4. Add the source files and module files that the case needs.
5. Run `go test ./internal/vex`.

