# Debian packaging for VRA

Builds a self-contained `.deb` that installs VRA under `/usr/lib/vra` with a
`vra` command on `PATH`.

## Build

```sh
packaging/build_deb.sh            # -> dist/vra_<version>_all.deb
```

Works on any system with `dpkg-deb` (Debian/Ubuntu, Termux, GitHub Actions).
The GitHub workflow `.github/workflows/build-deb.yml` builds it automatically on
every push and attaches it to releases tagged `v*`.

## Package contents

| Path               | What                                                        |
|--------------------|-------------------------------------------------------------|
| `/usr/bin/vra`     | entry-point shim (adds `/usr/lib/vra` to `sys.path`)        |
| `/usr/lib/vra/`    | `pyproject.toml` + full `vra/` package sources              |
| `/usr/share/doc/vra/` | license, README, docs, examples                            |

## Install

```sh
sudo apt install ./dist/vra_0.1.0_all.deb
```

Dependencies are pulled automatically (`python3-typer`, `python3-pydantic`,
`python3-rich`, ...). Static analyzers (`clang`, `cppcheck`, `semgrep`) are
recommended but optional.

### Native accelerator

`postinst` compiles the optional C accelerator (`vra._native`) in place when a
C compiler is present:

```sh
cc -O2 -fPIC -shared -I$(python3 -c 'import sysconfig;print(sysconfig.get_paths()["include"])') \
   /usr/lib/vra/vra/_native.c -o /usr/lib/vra/vra/_native$(python3-config --extension-suffix)
```

If no compiler is available VRA simply runs on the pure-Python fallback
(slower, same results).

## Layout

```
packaging/
  build_deb.sh     # dpkg-deb --build orchestrator
  deb/control      # package metadata + dependency list
  deb/postinst     # bytecode precompile + optional native build
  vra-bin          # /usr/bin/vra shim source
```