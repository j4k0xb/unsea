# unsea

Unpack the javascript source code and assets of Node [Single Executable Applications](https://nodejs.org/api/single-executable-applications.html).

Compatible with ELF, PE (.exe), and Mach-O executables.

## Usage

1. Clone the repo
2. Run `pip install -r requirements.txt`
3. Run `python unsea.py <path-to-executable>`

The source code will be extracted to `sea.js` and the assets will be extracted to a folder named `sea_assets`.
