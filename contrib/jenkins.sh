#!/usr/bin/env bash
# jenkins build helper script for openbsc.  This is how we build on jenkins.osmocom.org

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi


set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

mkdir "$deps" || true
rm -rf "$inst"

osmo-build-dep.sh libosmocore "" ac_cv_path_DOXYGEN=false

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"

osmo-build-dep.sh libosmo-abis
osmo-build-dep.sh libosmo-netif

set +x
echo
echo
echo
echo " =============================== osmo-mgw ==============================="
echo
set -x

cd "$base"
autoreconf --install --force
./configure $MGCP --enable-vty-tests --enable-external-tests
$MAKE $PARALLEL_MAKE
LD_LIBRARY_PATH="$inst/lib" $MAKE check \
  || cat-testlogs.sh
LD_LIBRARY_PATH="$inst/lib" \
  DISTCHECK_CONFIGURE_FLAGS="$MGCP --enable-vty-tests --enable-external-tests" \
  $MAKE distcheck \
  || cat-testlogs.sh
