# C++ Code Conventions

## Language

All C++ source files (`.cpp`, `.hpp`) must be written in English only.
- No Chinese characters are allowed anywhere in C++ code, including comments, string literals, and identifiers.
- This applies to all files under `src/` and `include/`.
- Unit test files under `tests/` are exempt from this rule for now.

---

## Standard

- Use **C++17** as the baseline; C++11/14 features are also acceptable.
- Do not use compiler-specific extensions unless absolutely necessary.

---

## Style: Google C++ Style Guide

Follow the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) with the additions below.

### Naming

| Entity | Convention | Example |
|---|---|---|
| Files | `snake_case` | `rule_engine.cpp` |
| Classes / Structs | `PascalCase` | `RuleEngine` |
| Functions / Methods | `PascalCase` | `AppendRule()` |
| Variables (local) | `snake_case` | `rule_count` |
| Member variables | `snake_case_` (trailing `_`) | `store_` |
| Constants / `constexpr` | `kPascalCase` | `kMaxRules` |
| Enums | `PascalCase` members | `Kind::kAccept` |
| Macros | `ALL_CAPS` | `WIN32_LEAN_AND_MEAN` |
| Namespaces | `snake_case` | `winiptables` |

### Formatting

- Indent: 4 spaces (no tabs).
- Line length: 100 characters max.
- Opening brace on the same line for functions, classes, control flow.
- Always use braces for `if`/`for`/`while` bodies, even single-line.

### Headers

- Use `#pragma once` instead of include guards.
- Use `""` for all non-system headers: project headers and third-party headers (e.g. `"gtest/gtest.h"`, `"WinDivert.h"`).
- Use `<>` only for standard library headers (`<string>`, `<vector>`, …) and Windows SDK headers (`<windows.h>`).
- Order of includes (separated by blank lines):
  1. Corresponding `.hpp` for a `.cpp` file
  2. Other project headers (`"winiptables/..."`)
  3. Third-party headers (`"gtest/gtest.h"`, `"WinDivert.h"`, …)
  4. Standard library headers (`<string>`, `<vector>`, …)
  5. Windows / platform headers last (`<windows.h>`)
- Never use `using namespace` in header files.

---

## Memory Management

- **Prefer smart pointers over raw pointers** for ownership:
  - `std::unique_ptr<T>` for exclusive ownership.
  - `std::shared_ptr<T>` only when shared ownership is genuinely needed.
- Use raw pointers (`T*`) only for **non-owning references** (observer pattern, callbacks, out-params).
- Use references (`T&` / `const T&`) instead of pointers when the value cannot be null.
- Never use `new` / `delete` directly; use `std::make_unique` / `std::make_shared`.
- Prefer stack allocation for small, short-lived objects.

---

## Modern C++ Idioms

- Use `auto` when the type is obvious from context or verbose (iterators, lambdas).
- Use range-based `for` loops instead of index loops where possible.
- Use `[[nodiscard]]` on functions whose return value must not be ignored.
- Use `override` and `final` on virtual method overrides.
- Use `= delete` to explicitly disable copy/move when not needed.
- Use `constexpr` for compile-time constants instead of `#define`.
- Use `std::string_view` for read-only string parameters instead of `const std::string&`.
- Use structured bindings (`auto [a, b] = ...`) for pairs/tuples.
- Use `std::optional<T>` for values that may be absent instead of sentinel values or null pointers.
- Use `enum class` instead of plain `enum`.

---

## Error Handling

- Do not use exceptions in performance-critical paths (packet processing).
- Return result types (`StoreResult`, `std::optional`, `bool`) for recoverable errors.
- Use `assert()` only for programmer errors (invariants), not runtime errors.
- Log errors to `stderr` with a `[winiptables]` prefix.

---

## Concurrency

- Protect shared state with `std::shared_mutex` (read/write lock).
- Use `std::atomic<T>` for simple counters; avoid locks for them.
- Prefer `std::memory_order_relaxed` for statistics counters,
  `std::memory_order_acquire`/`release` for synchronization.
- Never hold a lock while doing I/O or calling external APIs.

---

## Comments

- Every public class and non-trivial function must have a brief comment explaining its purpose.
- Use `//` for all comments; avoid `/* */` except for file-level license headers.
- Do not comment obvious code; comment the *why*, not the *what*.
- Section dividers use the form:
  ```cpp
  // -----------------------------------------------------------------------
  // Section name
  // -----------------------------------------------------------------------
  ```

---

## Miscellaneous

- Every `.cpp` file must start with a one-line comment: `// filename.cpp — brief description`.
- Every `.hpp` file must start with `#pragma once` followed by a one-line description comment.
- Avoid `static` global mutable state; prefer singletons with explicit lifetime management.
- Prefer `nullptr` over `NULL` or `0` for pointers.
- Prefer `static_cast<T>` over C-style casts.
- Keep functions short; if a function exceeds ~60 lines, consider splitting it.
