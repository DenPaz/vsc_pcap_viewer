# TShark

TShark is Wireshark's command-line dissector: PCAP Viewer uses it to read
captures, so every protocol Wireshark knows works here too. It also uses
`capinfos`, `editcap`, `mergecap` and `dumpcap` from the same install for
some features.

## Windows

- Install [Wireshark](https://www.wireshark.org/download.html) and keep
  **TShark** selected in the installer (it is by default), or run
  `winget install WiresharkFoundation.Wireshark`.
- The viewer looks in `C:\Program Files\Wireshark` and on `PATH`.
- Live capture also needs **Npcap**, which the Wireshark installer offers.

## macOS

- `brew install --formula wireshark` (the command-line tools), or the
  Wireshark app from [wireshark.org](https://www.wireshark.org/download.html):
  the viewer finds `/Applications/Wireshark.app/Contents/MacOS/tshark`.
- Live capture needs the app's **ChmodBPF** package.

## Linux

- Debian and Ubuntu: `sudo apt install tshark`
- Fedora: `sudo dnf install wireshark-cli`
- Arch: `sudo pacman -S wireshark-cli`
- Prefer your distribution's package to the Snap: a Snap's tshark can't read
  most of your files.
- Ubuntu confines tshark with AppArmor. If a capture in your home folder
  can't be read, the error message says which local rule to add.
- Live capture: `sudo usermod -aG wireshark $USER`, then log in again.

## Installed somewhere else?

Set **PCAP Viewer › Tshark Path** (`pcapViewer.tsharkPath`) to the `tshark`
executable. Then click **Check Again**.
