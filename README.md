# Routing Plugin
The Routing Plugin - `routing` - is a plugin for the Multipath 
TCP Daemon - [`mptcpd`](https://intel.github.io/mptcpd/) - that automatizes
the routing configuration needed for [mptcp](https://www.rfc-editor.org/rfc/rfc8684.html) 
to work correctly.

## Building
To build `routing` the following dependencies are required:

- Build dependencies
  - C compiler (C99 compliant)
  - [GNU Autoconf](https://www.gnu.org/software/autoconf/)
  - [GNU Automake](https://www.gnu.org/software/automake/)
  - [GNU Libtool](https://www.gnu.org/software/libtool/)
  - [GNU Autoconf Archive](https://www.gnu.org/software/autoconf-archive/)
  - [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)
  - [Pandoc](https://pandoc.org/) >= 2.2.1 (needed to convert 
  `README.md` contents from the GitHub markdown format content to 
  plain text)
  <!--- [Doxygen](http://www.doxygen.nl/) (only needed to build-->
- Run and build dependencies
  - [Patched mptcpd](https://github.com/dulive/mptcpd/tree/patched_version)
  - Linux kernel NetLink user API headers
  - [Embedded Linux Library](https://git.kernel.org/pub/scm/libs/ell/ell.git) >= v0.30
  - [Library Minimalistic NetLink](https://netfilter.org/projects/libmnl/)

### Bootstrapping
Assuming all build dependencies listed above are installed, bootstrapping
`routing` simply requires to run the [`bootstrap`](bootstrap) script 
in the top-level source directory, _e.g._:

```sh
$ ./bootstrap
```

### Build Steps
These build steps are the same as the ones found in all Autotool enabled 
software packages, _i.e._ running the `configure` followed by the command 
`make`.

```sh
./configure
make
```

If `configure` returns an error about `mptcpd` not being found set the 
environment variable `PKG_CONFIG_PATH` to `/usr/local/lib/pkgconfig`
and run it again, _e.g._:

```sh
$ PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure
```

### Instalation

__NOTE__: Installing `routing` requires to be run with `sudo` if the 
`mptcpd` plugin directory is owned by `root`.

Installing `routing` on any Linux system just requires to run:

```sh
make install
```

## Running

For the plugin to work properly it is necessary that the `existing` 
`notify-flags` is active (in the case of using the patched version of 
`mptcpd`, both `existing_ifs` and `existing_addrs` `notify-flags` are 
necessary), _e.g._:

```sh
# original mptcpd
$ mptcpd --notify-flags=existing

# mptcpd patched version
$ mptcpd --notify-flags=existing_ifs,existing_addrs
```
