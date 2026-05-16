# IDA Pro Triton & Miasm MCP

An enhanced fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) that adds
**Triton symbolic execution** and **Miasm IR analysis** as native built-in tools — no separate
MCP servers required.

> Upstream demo video (core IDA Pro MCP features):

https://github.com/user-attachments/assets/6ebeaa92-a9db-43fa-b756-eececce2aca0

The binaries and prompt for the video are available in the [mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset) repository.

## What's new in this fork

| Engine | What you get |
|--------|-------------|
| **Triton** (`triton-library`) | Symbolic execution, SMT constraint solving, taint analysis, path constraint exploration, snapshots |
| **Miasm** (`miasm`) | IR lifting, SSA transformation, CFG analysis, dead-code elimination, cross-arch assembly/patching, symbolic emulation, dependency graphs |

Both engines are **optional** — install them only when you need them. The plugin loads and runs
without them; every Triton/Miasm tool reports a clear install hint when the dependency is absent.

### API design: AI-agent-first

Every tool in this fork returns a **structured `dict`** with a consistent `"ok"` field, never raw strings or untyped lists. This makes outputs predictable for LLM parsing and downstream tool chaining:

```python
# Triton status
{"ok": True, "available": True, "architecture": "x86_64", ...}

# Miasm CFG summary
{"ok": True, "block_count": 12, "edges": 18, "cyclomatic_complexity": 7, ...}

# Error shape (always the same)
{"ok": False, "error": "Triton is not installed. Run: ida-pro-mcp --install-deps triton"}
```

All address parameters accept a **`str`** (hex `"0x401000"` or a symbol name `"main"`) and are normalized automatically via `parse_address()`. You never need to convert names to integers yourself.

### Installing the analysis engines

After installing the plugin, add the engines through the MCP server's own installer:

```sh
# Install both engines at once (default when --install-deps is used without a value)
ida-pro-mcp --install-deps
# or explicitly
ida-pro-mcp --install-deps all

# Or individually
ida-pro-mcp --install-deps triton
ida-pro-mcp --install-deps miasm

# Comma-separated also works
ida-pro-mcp --install-deps triton,miasm

# Specify IDA's Python explicitly if auto-detection fails
ida-pro-mcp --install-deps all --python "C:\Program Files\IDA Professional 9.3\python3\python.exe"
```

Or install manually into IDA's Python environment:

```sh
# Triton symbolic execution engine
pip install triton-library

# Miasm IR analysis framework
pip install "miasm>=0.1.5" future

# Both at once via package extras
pip install "ida-pro-triton-miasm-mcp[all]"
```

**Verify everything is working:**

After connecting your MCP client, call the probe tools:

```
triton_status   # → {"ok": true, "available": true, ...}
miasm_status    # → {"ok": true, "available": true, ...}
```

If a dependency is missing, the probe reports `"available": false` and the engine-specific tools are hidden. The rest of the IDA MCP tools work normally.

> **Forked from** [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) — upstream core IDA tools, zeromcp transport, and idalib support are from that project.

### Triton tools (36 tools)

All tools require `pip install triton-library`. Architecture is auto-detected from the loaded binary.

| Tool | Description |
|------|-------------|
| `triton_status` | Report availability and context state (always available) |
| `triton_init` | Initialize context; auto-detects arch from IDA |
| `triton_reset` | Clear symbolic state, keep architecture |
| `triton_get_context_info` | Dump context detail |
| `triton_symbolize_register` | Mark a register as symbolic |
| `triton_symbolize_memory` | Mark a memory region as symbolic |
| `triton_batch_symbolize_registers` | Symbolize several registers at once |
| `triton_set_concrete_register_value` | Seed a concrete register value |
| `triton_get_concrete_register_value` | Read a concrete register value |
| `triton_set_concrete_memory_value` | Seed concrete bytes |
| `triton_get_concrete_memory_value` | Read concrete bytes |
| `triton_process_instruction` | Process one instruction at a given address |
| `triton_process_function` | Process all instructions in a function |
| `triton_get_symbolic_variables` | List all symbolic variables |
| `triton_get_symbolic_expressions` | List all symbolic expressions |
| `triton_get_path_constraints` | List accumulated path constraints |
| `triton_taint_register` / `triton_untaint_register` | Tag/untag register taint |
| `triton_taint_memory` / `triton_untaint_memory` | Tag/untag memory taint |
| `triton_is_register_tainted` / `triton_is_memory_tainted` | Query taint status |
| `triton_get_taint_summary` | Summarize all tainted regs and memory |
| `triton_solve_path_constraints` | SMT-solve the current path predicate |
| `triton_get_ast_expression` | Get the AST for a symbolic variable |
| `triton_simplify_expression` | Algebraically simplify an expression |
| `triton_lift_to_smt` | Export an expression as SMT-LIB2 |
| `triton_snapshot_save` / `_restore` / `_list` / `_delete` | Context snapshots for branch exploration |
| `triton_analyze_function` | **Compound:** init → symbolize args → process function → Z3 solve, all in one call |
| `triton_find_input_for_branch` | **Compound:** CFG-guided Z3 search — find inputs that drive execution to a specific address |
| `triton_annotate_function` | Write IDA comments at branch points with path conditions |
| `triton_highlight_tainted_instructions` | Color instructions that operate on tainted data |

### Miasm tools (21 tools)

All tools require `pip install miasm future`. Architecture is auto-detected from the loaded binary.

| Tool | Description |
|------|-------------|
| `miasm_status` | Report availability and architecture state (always available) |
| `miasm_sync` | Re-sync architecture with IDA |
| `miasm_init` | Explicit (re-)initialization, optional architecture override |
| `miasm_get_context_info` | Detailed session info: arch, bitness, endianness, procname |
| `miasm_reset` | Rebuild Machine from current IDA state (clean slate) |
| `miasm_search_instruction_pattern` | Find consecutive mnemonic sequences inside a function |
| `miasm_lift_to_ir` | Lift an address range to Miasm IR |
| `miasm_lift_function` | Lift a whole function to IR + return CFG |
| `miasm_get_ssa` | Apply SSA transformation to a function |
| `miasm_get_cfg_dot` | Export function CFG as Graphviz DOT |
| `miasm_find_paths` | Find all paths between two addresses |
| `miasm_deobfuscate_cfg` | Apply dead-code elimination to simplify CFG |
| `miasm_simplify_block` | Symbolically execute a block, return simplified regs |
| `miasm_emulate_symbolic` | Emulate a block with optional initial register state |
| `miasm_get_function_side_effects` | Report which regs/memory a function reads/writes |
| `miasm_trace_data_flow` | Trace data-flow origins of a register at an address |
| `miasm_assemble` | Assemble an instruction, return all encodings |
| `miasm_patch_instruction` | Assemble + patch bytes directly into the IDA database |
| `miasm_get_cfg_summary` | CFG structural summary: blocks, edges, cyclomatic complexity, loops, topological order |
| `miasm_solve_path_constraints` | Enumerate paths to a target and solve for concrete inputs with Z3 |
| `miasm_annotate_data_flow` | Write IDA comments showing data-flow origins of a register |

### Phase 3.5 refinements (v1.0.0)

- **Uniform address parameters** — all 59 Triton/Miasm tools now accept `str` addresses (hex or symbol name), matching upstream conventions.
- **Structured returns everywhere** — all status and context tools return `dict` instead of raw strings.
- **Bug fixes** — `triton_solve_path_constraints(negate_last=True)` no longer corrupts the context; `miasm_patch_instruction` is now properly `@unsafe`; nested `@idasync` deadlock eliminated in `miasm_annotate_data_flow`; Triton snapshot restore no longer crashes on GC'd AST nodes.
- **Relaxed Miasm constraint** — `miasm>=0.1.5` (was `>=0.1.17`, which was unsatisfiable in many environments).

### Phase 3.6 — Async Tasks + Skills (v1.0.0)

- **Async task system** — `task_submit`, `task_poll`, `task_list`, `task_cancel` for long-running operations
- **7 workflow skills** — `binary-survey`, `stripped-binary-recovery`, `function-deep-dive`, `triton-symbolic-exec`, `miasm-ir-analysis`, `hybrid-deobfuscate`, `vuln-hunter-static`

### Hybrid tools (2 tools)

| Tool | Description |
|------|-------------|
| `hybrid_analyze_function` | **Cross-engine:** Miasm deobfuscation → Triton symbolic execution → Z3 solving, unified report |
| `hybrid_deobfuscate_and_patch` | **Cross-engine:** Miasm dead-code elimination → identify empty blocks → optionally NOP them out in IDA |

### Async Task System (4 tools)

Submit heavy operations as background tasks to avoid MCP client timeouts. The worker thread replays the submitter's extension/unsafe context so gating behaves identically to synchronous calls.

| Tool | Description |
|------|-------------|
| `task_submit` | Submit any tool as a background task → returns `task_id` immediately |
| `task_poll` | Poll a task every 2-3 s → returns `status` (`pending`/`running`/`done`/`error`/`cancelled`) + result when done |
| `task_list` | List all active/recent tasks with auto-detected category (`triton` / `miasm` / `hybrid` / `core`) |
| `task_cancel` | Cancel a pending task; flag running tasks (IDA main thread ops are not interruptible) |

Tasks are especially useful for:
- `triton_process_function` on large functions
- `miasm_lift_function` / `miasm_get_ssa` on complex CFGs
- `callgraph` with deep recursion
- `analyze_funcs` batch operations

### MCP Resources

In addition to `ida://` resources, the fork exposes Triton and Miasm session state as browsable resources:

**Triton session resources:**
- `triton://session/context` — Full context dump (architecture, modes, symbolic vars, taint state)
- `triton://session/constraints` — Accumulated path predicate in SMT-LIB 2 format
- `triton://session/symbolic-vars` — All symbolic variables with origins

**Miasm function resources:**
- `miasm://function/{address}/ir` — IRCFG as JSON blocks and edges
- `miasm://function/{address}/ssa` — SSA-transformed IRCFG as JSON
- `miasm://function/{address}/cfg-dot` — Graphviz DOT string for the assembly CFG

## Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - Use `idapyswitch` to switch to the newest Python version
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9 recommended), **IDA Free is not supported**
- Supported MCP Client (pick one you like)
  - [Amazon Q Developer CLI](https://aws.amazon.com/q/developer/)
  - [Augment Code](https://www.augmentcode.com/)
  - [Claude](https://claude.ai/download)
  - [Claude Code](https://www.anthropic.com/code)
  - [Cline](https://cline.bot)
  - [Codex](https://github.com/openai/codex)
  - [Copilot CLI](https://docs.github.com/en/copilot)
  - [Crush](https://github.com/charmbracelet/crush)
  - [Cursor](https://cursor.com)
  - [Gemini CLI](https://google-gemini.github.io/gemini-cli/)
  - [Kilo Code](https://www.kilocode.com/)
  - [Kiro](https://kiro.dev/)
  - [LM Studio](https://lmstudio.ai/)
  - [Opencode](https://opencode.ai/)
  - [Qodo Gen](https://www.qodo.ai/)
  - [Qwen Coder](https://qwenlm.github.io/qwen-code-docs/)
  - [Roo Code](https://roocode.com)
  - [Trae](https://trae.ai/)
  - [VS Code](https://code.visualstudio.com/)
  - [VS Code Insiders](https://code.visualstudio.com/insiders)
  - [Warp](https://www.warp.dev/)
  - [Windsurf](https://windsurf.com)
  - [Zed](https://zed.dev/)
  - [Other MCP Clients](https://modelcontextprotocol.io/clients#example-clients): Run `ida-pro-mcp --config` to get the JSON config for your client.

## Installation

### Via MCP Client (Claude Code)

The upstream plugin is available in the Claude Code marketplace:

```bash
claude plugin marketplace add mrexodia/claude-marketplace
claude plugin install ida-pro-mcp@mrexodia
```

To use **this fork** instead, install from source into your project:

```bash
# Clone or download this repository, then
pip install .
# or directly from GitHub
pip install "https://github.com/your-org/ida-pro-triton-miasm-mcp/archive/refs/heads/main.zip"
```

Then install the IDA plugin:

```bash
ida-pro-mcp --install
```

**Note**: Headless `idalib-mcp` requires having idalib activated globally and [uv](https://astral.sh/uv) installed:

```bash
# windows
uv run "C:\Program Files\IDA Professional 9.3\idalib\python\py-activate-idalib.py"
# macos
uv run "/Applications/IDA Professional 9.3.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
```

### Manual MCP Configuration

If your MCP client does not support plugins, add the server manually to your client's MCP config:

```json
{
  "mcpServers": {
    "ida-pro-triton-miasm": {
      "command": "uv",
      "args": ["run", "ida-pro-mcp", "--transport", "http://127.0.0.1:8744/sse"]
    }
  }
}
```

For stdio transport (most clients):

```json
{
  "mcpServers": {
    "ida-pro-triton-miasm": {
      "command": "uv",
      "args": ["run", "ida-pro-mcp"]
    }
  }
}
```

### Installing from the IDA GUI

**Note**: the MCP plugin approach is no longer recommended and will eventually be deprecated. Use `idalib-mcp` instead.

If you want to configure the MCP server manually from the IDA GUI:

```sh
pip uninstall ida-pro-mcp
pip install https://github.com/your-org/ida-pro-triton-miasm-mcp/archive/refs/heads/main.zip
```

Configure the MCP servers and install the IDA Plugin:

```
ida-pro-mcp --install
```

**Important**: Make sure you completely restart IDA and your MCP client for the installation to take effect. Some clients (like Claude) run in the background and need to be quit from the tray icon.

## Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. For reverse engineering the conversion between integers and bytes are especially problematic. Below is a minimal example prompt, feel free to start a discussion or open an issue if you have good results with a different prompt:

```md
Your task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:

- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive
- If more details are necessary, disassemble the function and add comments with your findings
- NEVER convert number bases yourself. Use the `int_convert` MCP tool if needed!
- Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
- Create a report.md with your findings and steps taken at the end
- When you find a solution, prompt to user for feedback with the password you found
```

This prompt was just the first experiment, please share if you found ways to improve the output!

Another prompt by [@can1357](https://github.com/can1357):

```md
Your task is to create a complete and comprehensive reverse engineering analysis. Reference AGENTS.md to understand the project goals and ensure the analysis serves our purposes.

Use the following systematic methodology:

1. **Decompilation Analysis**
   - Thoroughly inspect the decompiler output
   - Add detailed comments documenting your findings
   - Focus on understanding the actual functionality and purpose of each component (do not rely on old, incorrect comments)

2. **Improve Readability in the Database**
   - Rename variables to sensible, descriptive names
   - Correct variable and argument types where necessary (especially pointers and array types)
   - Update function names to be descriptive of their actual purpose

3. **Deep Dive When Needed**
   - If more details are necessary, examine the disassembly and add comments with findings
   - Document any low-level behaviors that aren't clear from the decompilation alone
   - Use sub-agents to perform detailed analysis

4. **Important Constraints**
   - NEVER convert number bases yourself - use the int_convert MCP tool if needed
   - Use MCP tools to retrieve information as necessary
   - Derive all conclusions from actual analysis, not assumptions

5. **Documentation**
   - Produce comprehensive RE/*.md files with your findings
   - Document the steps taken and methodology used
   - When asked by the user, ensure accuracy over previous analysis file
   - Organize findings in a way that serves the project goals outlined in AGENTS.md or CLAUDE.md
```

Live stream discussing prompting and showing some real-world malware analysis:

[![](https://img.youtube.com/vi/iFxNuk3kxhk/0.jpg)](https://www.youtube.com/watch?v=iFxNuk3kxhk)

## Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they can sometimes struggle with complex mathematical calculations or exhibit "hallucinations" (making up facts). Make sure to tell the LLM to use the `int_convert` MCP tool and you might also need [math-mcp](https://github.com/EthanHenrickson/math-mcp) for certain operations.

Another thing to keep in mind is that LLMs will not perform well on obfuscated code. Before trying to use an LLM to solve the problem, take a look around the binary and spend some time (automatically) removing the following things:

- String encryption
- Import hashing
- Control flow flattening
- Code encryption
- Anti-decompilation tricks

**For obfuscated binaries, use the hybrid workflow:**
1. Run `hybrid_analyze_function` to let Miasm fold constants and eliminate dead code before Triton symbolically executes the simplified path.
2. Use `miasm_solve_path_constraints` to find concrete inputs that reach a specific block.
3. Apply `hybrid_deobfuscate_and_patch` (dry_run first) to NOP out dead blocks verified by Miasm.

You should also use a tool like Lumina or FLIRT to try and resolve all the open source library code and the C++ STL, this will further improve the accuracy.

## Transports & Headless MCP

You can run an SSE server to connect to the user interface like this:

```sh
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

After installing [`idalib`](https://docs.hex-rays.com/core/idalib/getting-started) you can also run a headless MCP server. You can start with an initial binary:

```sh
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/executable
```

Or start without a binary and open/close arbitrary files later with `idalib_open(...)` / `idalib_close(...)`:

```sh
uv run idalib-mcp --host 127.0.0.1 --port 8745
```

For stdio-based clients, use:

```sh
uv run idalib-mcp --stdio
```

_Note_: The `idalib` feature was contributed by [Willi Ballenthin](https://github.com/williballenthin).

## Headless idalib Session Model

`idalib-mcp` is a supervisor that keeps each open database in its own idalib worker process. Starting without an `input_path` is supported; use `idalib_open(input_path, ...)` to open databases dynamically and `idalib_close(session_id)` to close them. This allows one headless MCP server to work with arbitrary files over its lifetime.

If the requested IDB is already open in a GUI IDA instance running the plugin, `idalib-mcp` will use that GUI instance instead of spawning a duplicate headless worker. If the GUI instance later disappears, the next routed request reopens the database in a headless worker when possible. Unsaved GUI-only changes must be saved first if they should be visible after fallback.

Tools target either the database bound to the current MCP context or an explicit `database` argument.

```sh
uv run idalib-mcp --stdio --max-workers 4
```

Typical flow:

```python
idalib_open("/path/to/binary_a.exe", session_id="binary_a")
idalib_open("/path/to/library.dll", session_id="library")

decompile("main", database="binary_a")
xrefs_to("ImportantExport", database="library")
```

`database` accepts a session ID, filename, or input path. If omitted, tools use the database bound to the active context.

Use `--isolated-contexts` to enable strict per-transport isolation:

```sh
uv run idalib-mcp --isolated-contexts --host 127.0.0.1 --port 8745 path/to/executable
```

### Why use `--isolated-contexts`?

Use it when multiple agents connect to the same `idalib-mcp` server and you want deterministic context isolation:

- Prevent one agent from changing another agent's active database accidentally.
- Keep each transport context's default database explicit.
- Still allow intentional collaboration by passing `database=...` or binding multiple agents to the same session ID.

When `--isolated-contexts` is enabled:

- Each transport context has its own binding (`Mcp-Session-Id` for `/mcp`, `session` for `/sse`, `stdio:default` for stdio).
- Unbound contexts fail fast for IDB-dependent tools/resources unless `database` is provided.
- `idalib_switch(session_id)` and `idalib_open(...)` bind the caller context only.

### Streamable HTTP behavior

With `--isolated-contexts`, strict Streamable HTTP session semantics are enabled, including `Mcp-Session-Id` validation.

### Context tools

- `idalib_open(input_path, ...)`: Open binary in a worker and bind it to the active context policy.
- `idalib_switch(session_id)`: Rebind the active context policy to an existing session.
- `idalib_current()`: Return the session bound to the active context policy.
- `idalib_unbind()`: Remove the active context binding.
- `idalib_list()`: Includes `is_active`, `is_current_context`, `bound_contexts`, backend (`worker` or `gui`), and process IDs.

Worker controls:

- `--max-workers N`: maximum simultaneous database workers (`0` = unlimited, default `4`).
- `IDA_MCP_MAX_WORKERS`: environment default for `--max-workers`.


## MCP Resources

**Resources** represent browsable state (read-only data) following MCP's philosophy.

**Core IDB State:**
- `ida://idb/metadata` - IDB file info (path, arch, base, size, hashes)
- `ida://idb/segments` - Memory segments with permissions
- `ida://idb/entrypoints` - Entry points (main, TLS callbacks, etc.)

**UI State:**
- `ida://cursor` - Current cursor position and function
- `ida://selection` - Current selection range

**Type Information:**
- `ida://types` - All local types
- `ida://structs` - All structures/unions
- `ida://struct/{name}` - Structure definition with fields

**Lookups:**
- `ida://import/{name}` - Import details by name
- `ida://export/{name}` - Export details by name
- `ida://xrefs/from/{addr}` - Cross-references from address

## Core Functions

- `lookup_funcs(queries)`: Get function(s) by address or name (auto-detects, accepts list or comma-separated string).
- `int_convert(inputs)`: Convert numbers to different formats (decimal, hex, bytes, ASCII, binary).
- `list_funcs(queries)`: List functions (paginated, filtered).
- `list_globals(queries)`: List global variables (paginated, filtered).
- `imports(offset, count)`: List all imported symbols with module names (paginated).
- `decompile(addr)`: Decompile function at the given address.
- `disasm(addr)`: Disassemble function with full details (arguments, stack frame, etc).
- `xrefs_to(addrs)`: Get all cross-references to address(es).
- `xrefs_to_field(queries)`: Get cross-references to specific struct field(s).
- `callees(addrs)`: Get functions called by function(s) at address(es).

## Modification Operations

- `set_comments(items)`: Set comments at address(es) in both disassembly and decompiler views.
- `patch_asm(items)`: Patch assembly instructions at address(es).
- `declare_type(decls)`: Declare C type(s) in the local type library.
- `define_func(items)`: Define function(s) at address(es). Optionally specify `end` for explicit bounds.
- `define_code(items)`: Convert bytes to code instruction(s) at address(es).
- `undefine(items)`: Undefine item(s) at address(es), converting back to raw bytes. Optionally specify `end` or `size`.

## Memory Reading Operations

- `get_bytes(addrs)`: Read raw bytes at address(es).
- `get_int(queries)`: Read integer values using ty (i8/u64/i16le/i16be/etc).
- `get_string(addrs)`: Read null-terminated string(s).
- `get_global_value(queries)`: Read global variable value(s) by address or name (auto-detects, compile-time values).

## Stack Frame Operations

- `stack_frame(addrs)`: Get stack frame variables for function(s).
- `declare_stack(items)`: Create stack variable(s) at specified offset(s).
- `delete_stack(items)`: Delete stack variable(s) by name.

## Structure Operations

- `read_struct(queries)`: Read structure field values at specific address(es).
- `search_structs(filter)`: Search structures by name pattern.

## Debugger Operations (Extension)

Debugger tools are hidden by default. Enable with `?ext=dbg` query parameter:

```
http://127.0.0.1:13337/mcp?ext=dbg
```

**Control:**
- `dbg_start()`: Start debugger process.
- `dbg_exit()`: Exit debugger process.
- `dbg_continue()`: Continue execution.
- `dbg_run_to(addr)`: Run to address.
- `dbg_step_into()`: Step into instruction.
- `dbg_step_over()`: Step over instruction.

**Breakpoints:**
- `dbg_bps()`: List all breakpoints.
- `dbg_add_bp(addrs)`: Add breakpoint(s).
- `dbg_delete_bp(addrs)`: Delete breakpoint(s).
- `dbg_toggle_bp(items)`: Enable/disable breakpoint(s).

**Registers:**
- `dbg_regs()`: All registers, current thread.
- `dbg_regs_all()`: All registers, all threads.
- `dbg_regs_remote(tids)`: All registers, specific thread(s).
- `dbg_gpregs()`: GP registers, current thread.
- `dbg_gpregs_remote(tids)`: GP registers, specific thread(s).
- `dbg_regs_named(names)`: Named registers, current thread.
- `dbg_regs_named_remote(tid, names)`: Named registers, specific thread.

**Stack & Memory:**
- `dbg_stacktrace()`: Call stack with module/symbol info.
- `dbg_read(regions)`: Read memory from debugged process.
- `dbg_write(regions)`: Write memory to debugged process.

## Advanced Analysis Operations

- `py_eval(code)`: Execute arbitrary Python code in IDA context (returns dict with result/stdout/stderr, supports Jupyter-style evaluation).
- `analyze_funcs(addrs)`: Comprehensive function analysis (decompilation, assembly, xrefs, callees, callers, strings, constants, basic blocks).

## Pattern Matching & Search

- `find_regex(queries)`: Search strings with case-insensitive regex (paginated).
- `find_bytes(patterns, limit=1000, offset=0)`: Find byte pattern(s) in binary (e.g., "48 8B ?? ??"). Max limit: 10000.
- `find_insns(sequences, limit=1000, offset=0)`: Find instruction sequence(s) in code. Max limit: 10000.
- `find(type, targets, limit=1000, offset=0)`: Advanced search (immediate values, strings, data/code references). Max limit: 10000.

## Control Flow Analysis

- `basic_blocks(addrs)`: Get basic blocks with successors and predecessors.

## Type Operations

- `set_type(edits)`: Apply type(s) to functions, globals, locals, or stack variables.
- `infer_types(addrs)`: Infer types at address(es) using Hex-Rays or heuristics.

## Export Operations

- `export_funcs(addrs, format)`: Export function(s) in specified format (json, c_header, or prototypes).

## Graph Operations

- `callgraph(roots, max_depth)`: Build call graph from root function(s) with configurable depth.

## Batch Operations

- `rename(batch)`: Unified batch rename operation for functions, globals, locals, and stack variables (accepts dict with optional `func`, `data`, `local`, `stack` keys).
- `patch(patches)`: Patch multiple byte sequences at once.
- `put_int(items)`: Write integer values using ty (i8/u64/i16le/i16be/etc).

**Key Features:**

- **Type-safe API**: All functions use strongly-typed parameters with TypedDict schemas for better IDE support and LLM structured outputs
- **Batch-first design**: Most operations accept both single items and lists
- **Consistent error handling**: All batch operations return `[{..., error: null|string}, ...]`
- **Cursor-based pagination**: Search functions return `cursor: {next: offset}` or `{done: true}` (default limit: 1000, enforced max: 10000 to prevent token overflow)
- **Performance**: Strings are cached with MD5-based invalidation to avoid repeated `build_strlist` calls in large projects

## Development

Adding new features is a super easy and streamlined process. All you have to do is add a new `@tool` function to the modular API files in `src/ida_pro_mcp/ida_mcp/api_*.py` and your function will be available in the MCP server without any additional boilerplate! Below is a video where I add the `get_metadata` function in less than 2 minutes (including testing):

https://github.com/user-attachments/assets/951de823-88ea-4235-adcb-9257e316ae64

To test the MCP server itself:

```sh
npx -y @modelcontextprotocol/inspector
```

This will open a web interface at http://localhost:5173 and allow you to interact with the MCP tools for testing.

For testing I create a symbolic link to the IDA plugin and then POST a JSON-RPC request directly to `http://localhost:13337/mcp`. After [enabling symbolic links](https://learn.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development) you can run the following command:

```sh
uv run ida-pro-mcp --install
```

Generate the changelog of direct commits to `main`:

```sh
git log --first-parent --no-merges 1.2.0..main "--pretty=- %s"
```
