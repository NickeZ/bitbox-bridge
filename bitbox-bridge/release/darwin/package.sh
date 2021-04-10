#!/bin/sh

# Script for packaging on Mac OSX. Run after you have run "release.sh" in the docker container.
# Must be executed from the top folder

set -e

NAME=BitBoxBridge
VERSION=$(toml-echo bitbox-bridge/Cargo.toml package.version)

(
	cd bitbox-bridge/release/darwin
	codesign -s "${IDENTITY}" tmp/opt/shiftcrypto/bitbox-bridge/bin/bitbox-bridge
	pkgbuild --root tmp --scripts scripts --identifier ch.shiftcrypto.bitboxbridge --version "${VERSION}" --ownership recommended bridge.pkg
	codesign -s "${IDENTITY}" bridge.pkg
	productbuild --distribution distribution.xml --resources resources --package-path . --version "${VERSION}" "${NAME}-${VERSION}-macOS-installer.pkg"
	codesign -s "${IDENTITY}" "${NAME}-${VERSION}-macOS-installer.pkg"
)
