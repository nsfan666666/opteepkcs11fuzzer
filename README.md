# Usage Guide for Debian GNU/Linux 10 (buster)

## Build Instructions

### Prepare for Build

Install Prerequisites:

```bash
sudo apt update -y
sudo apt-get install autoconf automake libtool cmake uuid-dev libglu1-mesa-dev libelf-dev mesa-common-dev build-essential wget git pkg-config libfuse-dev libssl1.0-dev
```

If libssl1.0-dev package is not found, add the repository ```deb [trusted=yes] http://security.ubuntu.com/ubuntu bionic-security main``` to ```/etc/apt/sources.list``` and run:

```bash
sudo apt update && apt-cache policy libssl1.0-dev
sudo apt-get install libssl1.0-dev
```

Then remove the added repository and run ```sudo apt update && apt-cache policy``` again. 

Install MbedTLS 3.1.0 (the mbedTLS in Debian apt repository is not compatible with Open-Tee)

```bash
cd /tmp && \
	wget https://github.com/ARMmbed/mbedtls/archive/refs/tags/v3.1.0.tar.gz && \
    tar xf v3.1.0.tar.gz && \
    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On ./mbedtls-3.1.0 && \
    make -j && sudo make install && \
    rm -rf ./mbedtls && sudo ldconfig
```

Install AFL++ prerequisites:

```bash
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# try to install llvm 12 and install the distro default if that fails
sudo apt-get install -y lld-12 llvm-12 llvm-12-dev clang-12 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo apt-get install -y ninja-build # optionally installed for QEMU mode
```

### Build Projects

Clone the Git repository `https://github.com/nsfan666666/opteepkcs11fuzzer`. Navigate to the cloned repository root directory.

Install AFL++:

```bash
cd <AFLplusplus>
make -j12 source-only NO_NYX=1 && sudo make install
```

Install Open-TEE with PKCS#11 TA:

```bash
sudo sh -c 'echo "[PATHS]\nta_dir_path = /opt/OpenTee/lib/TAs\ncore_lib_path = /opt/OpenTee/lib\nopentee_bin = /opt/OpenTee/bin/opentee-engine\nsubprocess_manager = libManagerApi.so\nsubprocess_launcher = libLauncherApi.so" > /etc/opentee.conf'

cd <opentee>/build
bash -c ../autogen.sh && make -j12 && sudo make install 
```

If inconsisten libtool is used, cd to opentee root directory and run ```autoreconf --force --install```, clean the build directory and repeat the above steps.

## Run & Fuzz Instructions

### Test run PKCS#11 TA

In order to test run the PKCS#11 TA with a specific input (corpus_entry), use the following commands: 

```bash
LD_PRELOAD=$(gcc -print-file-name=libasan.so) /opt/OpenTee/bin/opentee-engine -f 

cat <corpus_entries>/<corpus_entry> | /opt/OpenTee/bin/pkcs11_test 
```

### Fuzz PKCS#11 TA using AFL

Use the following command to initiate a fuzzing session with AFL:

```bash
cd <opentee>/build # uses cwd atm to find engine
AFL=1 afl-fuzz -T PKCS11 -D -t <timeout_ms> -i <corpus_entries> -o <opentee>/out -- /opt/OpenTee/bin/pkcs11_test
```

Stop the fuzzing session with <CTRL>+<C> and continue an old session using by replacing the `<corpus_entries>` with `-` in the above command.

To test if ASAN is functioning, run the above fuzzing command with the flag ```BUG=1```. If AFL catches the crash and ASAN crash log files are generated in ```/tmp/log/asan``` then it's working. This flag is only used for testing purpose.

**Note:** If a message stating "cannot find PID file", then run the engine standalone one time before fuzzing it. Follow the instructions in "Test run PKCS#11 TA" section.


### View Generated Coverage Information

After running an fuzzing session, run the following commands to generate an overview of the coverage information:

```bash
LD_PRELOAD=$(gcc -print-file-name=libasan.so) /opt/OpenTee/bin/opentee-engine -f

afl-cov --afl-fuzzing-dir <output_dir> --coverage-cmd  "cat AFL_FILE | LD_PRELOAD=$(gcc -print-file-name=libasan.so) /opt/OpenTee/bin/pkcs11_test" --code-dir <opentee> --overwrite
```

This will generate an index.html file which can be viewed on a browser. 

**Note:** The engine MUST be running before the afl-cov command is executed!

**Note:** Cannot run afl-cov command with --live since the code there assumes AFL=1 is unset, contradicting the real fuzzing process in run.



## Debug

### Utilities

```bash
# View where the gcov files will be produced
strings /opt/OpenTee/lib/TAs/liboptee_pkcs11_ta.so | grep gcda 

# View if any process related to the project is running
pstree -hp | egrep "tee_launcher|tee_manager|opentee-engine|pkcs11_test" 

# Kill all processes started by afl
sudo killall -s KILL tee_manager tee_launcher pkcs11_test engine afl-fuzz opentee-engine

# View TA output in syslog (enable rsyslog or similar services)
sudo tail -f /var/log/syslog # pipe into "bat --paging=never -l log" for prettier output 

# Disable log service when performing long fuzzing sessions to avoid using up the disk
service rsyslog stop

# Debug the TA using GDB
sudo -E gdb -ex "set follow-fork-mode child" opentee-engine $(pidof tee_launcher)
```

