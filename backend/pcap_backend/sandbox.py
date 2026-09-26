"""Explaining what a sandboxed tshark isn't allowed to do.

Ubuntu's apparmor package ships ``/etc/apparmor.d/tshark``, which confines
``/usr/bin/tshark`` to /tmp and Wireshark's own folders and only lets it
receive signals from itself. So tshark can fail to read the user's capture
("You don't have permission to read the file"), and the backend's ``kill()``
of a cancelled tshark fails with ``PermissionError`` (the kernel logs
``apparmor="DENIED" operation="signal" … peer="vscode"`` when VS Code runs
under its own ``vscode`` profile, ``peer="unconfined"`` otherwise).
"""

import sys
from pathlib import Path

_PERMISSION_ERRORS = ("don't have permission", "Permission denied")
APPARMOR_PROFILES = Path("/sys/kernel/security/apparmor/profiles")
APPARMOR_TSHARK = Path("/etc/apparmor.d/tshark")
CONFINED_TSHARK = Path("/usr/bin/tshark")  # the path the profile attaches to

# Local rules: read/write the user's files, and receive signals from the backend
# (unconfined, or under VS Code's own AppArmor profile named "vscode").
APPARMOR_RULES = (
    "owner @{HOME}/** rw,",
    "signal (receive) peer=unconfined,",
    "signal (receive) peer=vscode,",
)
APPARMOR_HINT = (
    "tshark is confined by AppArmor (profile /etc/apparmor.d/tshark, shipped with Ubuntu's "
    "apparmor package). It only lets tshark read and write files in /tmp and Wireshark's own "
    "folders, and doesn't let the extension stop a cancelled tshark. Allow both with local "
    "rules, then reload the profile:\n"
    f"  printf '%s\\n' {' '.join(repr(r) for r in APPARMOR_RULES)} "
    "| sudo tee -a /etc/apparmor.d/local/tshark\n"
    "  sudo apparmor_parser -r /etc/apparmor.d/tshark\n"
    "Add a similar line for captures elsewhere (e.g. 'owner /media/** rw,')."
)
SNAP_HINT = (
    "This tshark is a Snap package, which is sandboxed and has its own /tmp. Install tshark "
    "from your distribution's packages instead (e.g. 'sudo apt install tshark') and set "
    "'pcapViewer.tsharkPath' to it."
)
GENERIC_HINT = (
    "tshark was not allowed to access a file that the extension can read. It may be "
    "sandboxed (AppArmor, SELinux, Snap or Flatpak) or running as another user."
)
GENERIC_KILL_HINT = (
    "The operating system refused to signal it. It may be sandboxed (AppArmor, SELinux, "
    "Snap or Flatpak) or running as another user."
)


def apparmor_confines_tshark(
    profiles: Path = APPARMOR_PROFILES, profile_file: Path = APPARMOR_TSHARK
) -> bool:
    """Whether AppArmor's ``tshark`` profile is loaded in enforce mode."""
    try:
        loaded = profiles.read_text(encoding="utf-8", errors="replace")
    except OSError:
        # securityfs isn't readable for everyone everywhere: fall back to the profile file.
        return profile_file.is_file()
    return any(line.startswith("tshark (enforce)") for line in loaded.split("\n"))


def _apparmor_applies(tshark: Path, profiles: Path) -> bool:
    return (
        sys.platform.startswith("linux")
        and tshark.resolve() == CONFINED_TSHARK
        and apparmor_confines_tshark(profiles)
    )


def permission_hint(tshark: Path, stderr: str, profiles: Path = APPARMOR_PROFILES) -> str | None:
    """Explain a tshark "permission" failure on a file the backend itself could access."""
    if not any(p in stderr for p in _PERMISSION_ERRORS):
        return None
    if sys.platform.startswith("linux") and (
        "/snap/" in str(tshark) or tshark.resolve().name == "snap"
    ):
        return SNAP_HINT
    return APPARMOR_HINT if _apparmor_applies(tshark, profiles) else GENERIC_HINT


def kill_denied_hint(program: Path, profiles: Path = APPARMOR_PROFILES) -> str:
    """Explain why killing ``program`` raised PermissionError."""
    return APPARMOR_HINT if _apparmor_applies(program, profiles) else GENERIC_KILL_HINT
