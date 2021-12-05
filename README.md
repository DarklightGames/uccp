# uccp
`uccp` is a custom build tool for [Darkest Hour: Europe '44-'45](https://github.com/DarklightGames/DarkestHour) written in Rust.

It seeks to improve upon the bare-bones build tools offered by the Unreal Engine 2.5 build tool `ucc` by automating common build tasks.

Though `uccp` was designed with a particular mod in mind, it can also be used with any mod for the Unreal 2 engine.

In contrast to `ucc`, `uccp` will automatically:

* Detect changes in your mod's code files and mark those packages (and downstream packages) for compilation.
* Run `dumpint` on successfully compiled packages (optional).
* Move compiled packages and localization files to the specified mod's `System` folder.
* Warn about ambiguous asset files (e.g., having identically named files in both the `./Animations` folder and the `./<ModName>/Animations` folder)

This tool also integrates the [UnrealScriptPlus](https://github.com/DarklightGames/UnrealScriptPlus) library. This means that it will scan any changed files for syntax errors and emit warnings about potential problems before the `ucc` process gets to it. This results in saved time since UnrealScriptPlus can detect syntax errors virtually instantly while it can take `ucc` a number of seconds or even minutes to detect a syntax error.
## Usage

```
USAGE:
    uccp.exe [FLAGS] [OPTIONS] <mod>

FLAGS:
    -c, --clean         Compile all packages
    -d, --debug         Compile debug packages (for use with UDebugger)
    -i, --dumpint       Dump localization files
    -h, --help          Prints help information
        --no-cascade    Ignore package dependencies
        --no-ucc        Do not run UCC
        --no-usp        Do not run UnrealScriptPlus
    -q, --quiet         Minimal output during UCC compile
    -V, --version       Prints version information

OPTIONS:
        --directory <dir>    Root directory (default: ".")

ARGS:
    <mod>    Mod folder name

Process finished with exit code 0

```

For example, if you wanted to run a build of the mod `MyMod` in the root directory `C:/Root/Directory`, you would invoke the following:

```shell
uccp.exe --directory C:/Root/Directory MyMod 
```

