# Gunbound (Thor's Hammer) Launcher

This is a replacement for the game launcher that was used in GunBound Thor's Hammer (2006).

![Launcher Screenshot](https://raw.github.com/jglim/gunbound-launcher/master/Other/banner.gif)

### Quick Start

- Clone this repository and unarchive it somewhere safe
- In the `TestClient` folder, edit the server address and credentials in `Launcher.ini`
- Run `Launcher.exe` to start GunBound

### Features

- Skip the GunBound installer. The registry keys are automatically set up if they are absent.
- No emulation of GunBound "Fetch" system required 
- Essential settings can be provisioned via `Launcher.ini` (Server address, version)
- Minimal requirements: standalone binary `Launcher.exe` + configuration `Launcher.ini`, Requires _.NET 4.0_ which should be present on most modern systems
- Decent base to build your own launcher - credentials can be passed via command line
- Development features such as automatic DLL injection and the ability to launch GunBound with correct parameters while suspended (for debugging/removing GameGuard)

### Why

The main `GunBound.gme` client is launched via the `GunBound.exe` launcher. However it is possible (and desirable) to skip the launcher as:
- GunBound's proprietary updating/patching "Fetch" system has to be emulated
- Existing fetch emulation does not validate the user's credentials anyway
- Credential checking is done again when the client connects to the world

As a side feature, removing the installer requirement also allows for quick "LAN party" style setups.

### Usage
- Place `Launcher.exe` in the same folder as `GunBound.gme`
- Create a `Launcher.ini` file containing basic configuration
- _Optional but recommended:_ Set up [DxWnd](https://sourceforge.net/projects/dxwnd/) to launch GunBound in windowed mode
- Run `Launcher.exe` to start GunBound. Credentials can be supplied via command line.

`Launcher.ini` is a text-based configuration file, where options are delimited with newlines `\n`. Windows line endings (`\r\n`) are automatically normalized. Keys and values are separated with `=`. These are the possible options:
- `SERVER` configures the registry so that the client connects to this address
- `VERSION` configures the registry so that the client runs normally. This value must match the XFS file version
- `USERNAME` and `PASSWORD` optionally provided here if setting it in the command line is inconvenient. The command line values take precedence, if available.
- `CREATE_SUSPENDED` if _TRUE_, the `GunBound.gme` process will be launched in a suspended state until the console window receives a keypress. Useful for attaching debuggers.
- `INJECT_DLL` if set, the DLL at the relative path will be injected via `CreateRemoteThread`
- `EXIT_IMMEDIATELY` if _TRUE_, the console does not close upon completion.

Here is an example configuration file for typical use cases:
```
USERNAME=testusername
PASSWORD=testpassword
SERVER=127.0.0.1
VERSION=280
EXIT_IMMEDIATELY=TRUE
CREATE_SUSPENDED=FALSE
```

### How

The launcher sets up the registry to reflect a full GunBound installation. Key values such as `IP`, `BuddyIP`, `Location` and `Version` are also set based on the configuration file.

The game client is then launched directly:
- A 48-byte array is created, containing 
    - ASCII-encoded username (bytes 0-15). Padded with `0`s
    - ASCII-encoded password (bytes 16-31) Padded with `0`s
    - The last set of 16 bytes remains safely as `0`s. They appear to used be for a "invite-to-game" feature 
- Data is then encrypted with AES-128 in ECB mode. The key is fixed in the client as `FAEE85F24073D9161390197F6E562A67`
- The output bytes are converted to an uppercase hex string. The result should be a 96-character credentials string
- `GunBound.gme` is started with the above value as its **only** command line parameter. 
    - Conventionally when a process is started with arguments, its own path is also prepended e.g. `"C:\Windows\system32\NOTEPAD.EXE" C:\some_file.txt`. 
    - Most implementations (batch files, `subprocess.run`, `System.Diagnostics.Process.Start` etc. do this by default)
    - The client exits if the executing path is included with the credentials string
    - Calling `CreateProcess` with the credentials string for the `lpCommandLine` parameter solves this issue

# License
MIT
Game client and artwork assets belong to Softnyx