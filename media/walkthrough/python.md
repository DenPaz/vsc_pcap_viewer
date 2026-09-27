# Python 3.14

PCAP Viewer runs a small backend written in Python (standard library only:
nothing to `pip install`). It needs **Python 3.14 or newer** and looks for
`python3.14`, then `python3` and `python` (on Windows: `py -3.14`, `py -3`,
`python`).

## Windows

- Install it from [python.org](https://www.python.org/downloads/) (the
  installer adds the `py` launcher), or run
  `winget install Python.Python.3.14`.

## macOS

- `brew install python@3.14`, or the installer from
  [python.org](https://www.python.org/downloads/).

## Linux

- Fedora: `sudo dnf install python3.14`
- Ubuntu: `sudo apt install python3.14` where your release has it (or the
  deadsnakes PPA).
- Any distribution: `uv python install 3.14` with
  [uv](https://docs.astral.sh/uv/), which puts `python3.14` in
  `~/.local/bin`.

## In a remote window

In WSL, over SSH, in a Dev Container or a Codespace, PCAP Viewer runs on the
remote machine: install Python **there** (the instructions above for its
system), not on your own computer. Set the path in **Remote** settings
(_Preferences: Open Remote Settings_): local user settings don't apply there.

## Installed somewhere else?

Set **PCAP Viewer › Python Path** (`pcapViewer.pythonPath`) to the
interpreter, for example `C:\Python314\python.exe` or
`/opt/python3.14/bin/python3`. Then click **Check Again**.
