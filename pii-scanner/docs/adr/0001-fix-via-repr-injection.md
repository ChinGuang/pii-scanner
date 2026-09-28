# Fix strategy: inject `__repr__` on the model class, not patch call sites

The scanner detects PII Leaks at individual logger call sites, but fixing each call site independently is fragile — new call sites can be added at any time. We chose instead to inject a single safe `__repr__` method on the affected model class. This is harder to reverse (it changes the class contract) and surprising without context (a reader might wonder why `__repr__` is explicitly defined), but it was the deliberate choice because it is defensive by construction: every future log call is safe automatically.

## Considered Options

- **Patch each logger call site** — targeted but incomplete; misses indirect logging paths (exception messages, third-party libraries).
- **Inject `__repr__` on the model class** — chosen; one fix protects all current and future call sites.

## Consequences

The `__repr__` of patched model classes will no longer show raw field values in a REPL or debugger. Developers who rely on `repr(customer)` for debugging will see masked output. This is intentional.
