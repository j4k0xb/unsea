# unsea

Extracts the javascript source code and assets of Node [Single Executable Applications](https://nodejs.org/api/single-executable-applications.html).

Compatible with ELF (Linux), PE (Windows), and Mach-O (MacOS) executables.

## Installation

```bash
pip install unsea
```

## Usage

```bash
unsea <path-to-executable> [-o <output-directory>] [--force]
```

Output files:

- `index.js`: source code
- `index.jsc`: [code cache / bytecode](https://nodejs.org/api/single-executable-applications.html#v8-code-cache-support)
- `config.json`: configuration that was used to create the executable
- `assets/`: extracted assets

## Development

1. Clone the repo
2. Create/sync the environment:

   ```bash
   uv sync
   ```

3. Run the CLI:

   ```bash
   uv run unsea <path-to-executable>
   ```
