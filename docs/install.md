# Installing liminal

The README's Quickstart is the development install. This page covers a clean machine, the `memory` extra and its pinned techne, and building the image.

## Development

You need git and Python 3.12 or newer. On Debian and Ubuntu, also run
`sudo apt update && sudo apt install python3-venv`; without it `python3 -m venv`
fails. The techne steps below install from `tenishai/techne`, a separate
repository; if it is not public where you are, they need access to it.

```bash
git clone https://github.com/tenishai/liminal.git && cd liminal
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Everything above, including the test suite, runs without techne. Only the
`memory` handler needs it:

```bash
pip install -r requirements-sources.txt   # techne at its pinned git tag, no sibling checkout
pip install -e ".[dev,memory]"
```

## Non-dev / clean machine

The `memory` handler needs `techne`, which is not on a public index. To install
without a sibling checkout (agents, other hosts, containers), work from a clone of
this repo (see Development above, including its Debian/Ubuntu `python3-venv`
step), with access to `tenishai/techne`, and pin the git source alongside the extra
inside a virtual environment:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-sources.txt ".[memory]"
```

If you work on techne and liminal together, install your techne checkout instead:
`pip install -e ../techne`.

The pinned techne is `v0.20.0` (distribution `tenish-techne`), stated in `requirements-sources.txt`, in the `memory`
extra's floor, and as the Dockerfile's `TECHNE_VERSION`; `tests/test_techne_pin.py`
keeps the three in step. To build the image from a sibling checkout, clone techne at
that tag and check it before building:

```bash
git clone --branch v0.20.0 https://github.com/tenishai/techne.git ../techne
bash scripts/check-techne-sibling.sh
docker build --build-context techne=../techne -t liminal .
```

The image build itself only compares techne's version string, which cannot tell
techne's main from the tag; the script compares commits. `TECHNE_ANY=1` skips the
script and `--build-arg TECHNE_ANY_VERSION=1` skips the build's check, for building
against whatever `../techne` has checked out.

The distribution is named `tenish-liminal` (not yet published to PyPI); the
import package and the CLI command are still `liminal`. To install a tagged release
straight from git:

```bash
pip install "tenish-liminal @ git+https://github.com/tenishai/liminal.git@<tag>"
```

`v0.4.0` is the first tag that builds `tenish-liminal`; `v0.3.0` builds the old
`tenishai-liminal` distribution, `v0.2.0` builds `liminal` and `v0.1.0` builds `limenal`.

## Alongside cabal

liminal is standalone — any MCP-speaking agent can use it. Cabal
(`github.com/tenishai/cabal`) is the primary downstream consumer; Cabal personas
connect to liminal for their tool surface and liminal asks Cabal Core for
credentials per `(persona, handler)`.

Sibling-checkout convention: clone `tenishai/liminal` as a sibling of `cabal`
and `techne`, install with `pip install -e ../liminal`.
