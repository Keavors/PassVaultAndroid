English · [Русский](README.md)

# PassVault for Android

An offline password vault, the companion of the desktop
[PassVault](https://github.com/Keavors/PassVault). The `vault.pmv` file format is shared;
synchronisation is transferring the file and merging with conflict review on either side.

Current version: 3.1. Version history is in [README_ANDROID.txt](README_ANDROID.txt) (in Russian).

## Features

Parity with the desktop: trash, password history, snapshot archive with grandfather-father-son
rotation, merge with conflict review, generator, CSV/JSON export and import (understands
Bitwarden and KeePass), encrypted copy export, opening another file, auto-lock, clipboard
clearing after 30 seconds, growing delay after wrong passwords.

What the app does to protect the data:

- `FLAG_SECURE` — no screenshots and no preview in "recents".
- No `INTERNET` permission — the system will not let it open a socket.
- `allowBackup="false"` — the file never goes to Google cloud backup.
- The password in the clipboard is marked sensitive (Android 13+).
- Writes with `fsync`, snapshots too: a sudden power-off cannot leave an empty file.
- Unknown fields from a newer desktop version survive being rewritten by the phone.

## Formats

Only `PMVAULT2` is written (Argon2id: 3 passes, 256 MiB, 4 lanes), computed in pure Java
(BouncyCastle). `PMVAULT1` (PBKDF2, files of versions 1.x and 2.x) is always read; an old file
migrates to Argon2id on first open after a copy in the old format is placed in the archive.
The master password does not change.

Argon2id asks for 256 MiB per attempt, so the manifest sets `largeHeap="true"`, and decryption
runs in a background thread with a "please wait" dialog.

## Where the data lives

The app's internal storage (`files/`), unreachable by other apps:

| File | What it is |
|---|---|
| `vault.pmv` | the vault |
| `vault.pmv.prev` | previous version for rollback |
| `vault.pmv.bak` | copy from version 1.x, read during recovery |
| `vault_backups/` | snapshot archive |
| `attempts.json` | wrong-password counter |

Uninstalling the app removes the data — keep a copy on the PC.

## Synchronisation

- Phone → PC: "⋮" → Export copy → file to the PC → File → Merge with another file…
- PC → phone: File → Save copy as… → file to the phone → "⋮" → Import and merge.

If the file is encrypted with the same password as the current vault, the password is not asked again.
To make both sides identical: merge on device A, export the result and merge on B.

## Build and tests

Needs JDK 17+ (the JBR from Android Studio works) and the Android SDK.

```bash
gradlew :app:testDebugUnitTest    # core unit tests, no emulator
gradlew :app:assembleDebug        # app/build/outputs/apk/debug/app-debug.apk
```

The release build is signed with the debug key on purpose: the app is not published, and an
unsigned APK cannot be installed.

The core (`Core.kt`) never touches `android.*`, so cryptography, the model, merging, disk writes,
snapshot rotation and the attempt delay are checked by ordinary JVM tests.

## Compatibility with the PC

Checked on real files in both directions:

- PC → Android: `python tools\make_android_fixture.py` in the PC project puts two reference
  files (`pc_vault_argon2.pmv`, `pc_vault.pmv`) into `app/src/test/resources`; `PcCompatibilityTest` reads them.
- Android → PC: the test `PcCompatibilityTest.writesFileForPcToRead` writes
  `app/build/interop/android_vault.pmv`, which the PC tests read.

## Layout

```
app/src/main/java/com/example/passvault/
├── Core.kt            core: file format, KDF, encryption, model, merge, snapshots
├── MainActivity.kt    unlock, entry list, menu
├── EntryActivity.kt   entry card
└── Dialogs.kt         dialogs: generator, merge, settings
app/src/test/          core unit tests and PC compatibility tests
```
