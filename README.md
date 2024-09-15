# unsea

Unpack the javascript source code and assets of Node [Single Executable Applications](https://nodejs.org/api/single-executable-applications.html).

Compatible with ELF, PE (.exe), and Mach-O executables.

## Usage

1. Clone the repo
2. Run `pip install -r requirements.txt`
3. Run `python unsea.py <path-to-executable>`

Output files:

- `sea.js`: source code
- `sea.jsc`: optional cached data (what [bytenode](https://github.com/bytenode/bytenode) creates).
- `sea_assets/`: optional extracted assets
