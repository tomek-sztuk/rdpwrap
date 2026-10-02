# RDP Wrapper maintenance after Windows Update

`RDPWMaint.exe` is a standalone Windows 10/11 maintenance installer built from
`src-maintenance`. It replaces the maintenance logic of the legacy installer:
no external PowerShell repair scripts or Delphi installation are needed at run
time. It uses the project's original x86/x64 wrapper DLL resources, unchanged.
Windows' .NET Framework 4.8 is required. No additional .NET SDK is needed to run it.

## Commands

Run checks from an administrator terminal to inspect the actual modules loaded by
TermService. A non-elevated check can confirm observed concurrent sessions but may
be unable to enumerate the service's modules; the report records that limitation.

```powershell
.\RDPWMaint.exe --check
.\RDPWMaint.exe --auto
.\RDPWMaint.exe --auto --source C:\verified\rdpwrap.ini
```

`--auto` is unattended: no prompts, UAC dialogs, forced logoffs, pauses or Windows
reboots. An elevated administrator or SYSTEM task is required for changes.
Windows Remote Desktop must already be enabled. The program preserves firewall,
authentication, account, graphics and access settings. It can install the Wrapper
on an already configured RDP host without invoking the old installer.

## Failure cases handled

| State after an update | Action |
| --- | --- |
| Correct DLL, exact INI support, loaded/responding service | Exit without fetching updates or restarting |
| Windows replaced `termsrv.dll` with a new build | Import only exact-build INI sections and required missing PatchCodes |
| Wrapper registration reverted to `termsrv.dll` | Register the original bundled Wrapper and reload |
| `rdpwrap.dll` missing or modified, including a still-valid PE file | Restore the original bundled DLL by SHA-256 fingerprint |
| `rdpwrap.ini` missing | Reconstruct from embedded configuration and exact-build support |
| Registered correct library not loaded, stopped service or failed listener | One controlled SCM reload/start and verification |
| No validated entry for the precise new Windows build | Stop without guessing offsets or replacing the Windows DLL |
| Active/disconnected remote session, pending remote logon, unreadable sessions | Hold/fail before writes or service actions |
| Malformed/duplicate INI data or conflicting shared patch definition | Stop rather than silently replace unrelated configuration |

The original `termsrv.dll` is never replaced or patched on disk. Catalog/embedded
signature verification, fixed numeric version extraction, PE architecture/RVA
checks and DLL fingerprints are performed before changes. INI validation checks
structure and bounds, not the semantics of community-provided machine code.

If TermService is confirmed stopped and WTS session enumeration is unavailable,
the independent Windows LSA logon table is checked instead. Remote interactive,
cached remote and ambiguous non-console logons block repair. Failure to read both
tables stops the operation. WTS failures while the service runs are never ignored.

Source order: embedded fork INI, the fork's own `res/rdpwrap.ini`,
`sebaxakerhtc/rdpwrap.ini`, `asmtron/rdpwrap`, then the original `stascorp/rdpwrap`.
`--source` uses only the specified local file when an update is necessary. An
already supported working configuration does not read or download an update.
Downloaded content is INI text only; executable/DLL downloads are not performed.

## Scheduling

The program does not create a scheduled task merely by running `--auto`.
`--task-plan` previews the actual Windows Task Scheduler XML without registering it.
To opt in, run once **as administrator**:

```powershell
.\RDPWMaint.exe --register-task
```

This copies the single executable to the administrator-controlled
`C:\Program Files\RDP Wrapper Maintenance` directory and registers **RDP Wrapper
Maintenance** under SYSTEM. It runs two minutes after boot and every hour,
including when nobody is logged in. Skipped remote-session runs can retry on the
next hourly run. No account password is saved. Overlapping instances are ignored.
The program uses a global mutex shared with the earlier repair scripts.

If the program was rebuilt, run `--register-task` from the new binary to update
the protected copy. If another instance is using the file, wait for it to finish.

To remove the job without uninstalling Wrapper:

```powershell
.\RDPWMaint.exe --unregister-task
```

Alternatively, an existing scheduler can invoke the protected EXE with `--auto`
under administrator/SYSTEM privileges. A logged-in remote user blocks changes,
even when the task itself runs in session 0. Session checks occur immediately
before operations; they are not a lock that prevents new logons. A session that
appears mid-operation holds further actions, and the report records pending work.

## Reports, backups and verification

Administrator/SYSTEM reports and backups are in
`C:\ProgramData\RDPWrapperMaintenance`; non-elevated reports use
`%LOCALAPPDATA%\RDPWrapperMaintenance`. `--log-dir` can override the report directory.
The report includes before/after state, numeric build, hashes, source provenance,
sessions, changed sections, backup path and rollback outcome.

Before actual changes, original files and the service registration are saved.
Writes are atomic on the target volume. A failed apply/start/verification attempts
to restore only this operation's changes, preserving later external edits.
Rollback also observes the remote-session guard. A held operation may leave a
pending reload for the next eligible run. A new service process after a reboot
does not unnecessarily replay a stale reload marker.

The local test is TCP/X.224 negotiation without authentication. It does not prove
LAN reachability, successful user login, graphics quality or correct concurrency
when nobody is connected. Test two real users after the first successful repair.

| Exit | Meaning |
| --- | --- |
| 0 | Healthy, or successful verified repair/install |
| 1 | Check needs attention, or runtime cannot be inspected confidently |
| 2 | Operation failed; inspect the JSON report |
| 3 | Held by a remote session or concurrent maintenance |
| 4 | Administrator privileges required |

## Building and testing

```powershell
.\src-maintenance\build.ps1 -Test
```

The build uses Windows' .NET Framework C# compiler, project resource bundle and
fork INI. Output is `bin/RDPWMaint.exe`. No Delphi compiler, NuGet packages or
network downloads are needed. The original installer sources remain available
for legacy uninstallation; this program does not silently uninstall/reinstall.

`--self-test` uses temporary fixtures and a fake platform for service/registry
actions. Tests also read the live Windows version/catalog signature without
changing Windows. GitHub Actions builds the executable, runs the tests and saves
the EXE as an artifact; it does not register a task or install Wrapper on the runner.

The fork INI includes the exact `10.0.26100.9444` definitions imported from
`sebaxakerhtc/rdpwrap.ini` downloaded on 2026-10-02 (source SHA-256
`12FAEF5BA19E153362017B9849A9CAD2CF6E2DE1DE4EF5C9C183E2DF7971967D`).
Other build sections and existing global values were preserved.
