 #!/bin/sh -e

basedir=$(dirname $0)

pushd "$basedir" > /dev/null
mkdir -p ./{,emulator,libtee,liboptee_pkcs11,tests,TAs}/m4
autoreconf --install --symlink
popd > /dev/null

"$basedir"/configure --prefix="/opt/OpenTee" $@
# "$basedir"/configure --prefix="/opt/OpenTee" $@