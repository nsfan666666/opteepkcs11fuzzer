# Usage Guide

## Build Instructions

### Prepare for Build

Install Prerequisites:

```bash
sudo apt update -y
sudo apt-get install autoconf automake libtool uuid-dev libssl1.0-dev libglu1-mesa-dev libelf-dev mesa-common-dev build-essential git curl python htop pkg-config qbs gdb libfuse-dev
```



### Build 

Clone the Git repository `https://github.com/nsfan666666/opteepkcs11fuzzer`.

## Run & Fuzz Instructions

### Test run PKCS#11 TA

In order to test run the PKCS#11 TA with a specific input (corpus_entry), use the following commands: 

```bash
LD_PRELOAD=$(gcc -print-file-name=libasan.so) /opt/OpenTee/bin/opentee-engine -f 

cat <corpus_entry> | /opt/OpenTee/bin/pkcs11_test 
```

### Fuzz PKCS#11 TA using AFL

Use the following command to initiate a fuzzing session with AFL:

```bash
AFL=1 afl-fuzz -T PKCS11 -t <timeout_ms> -i <corpus_dir> -o <opentee_dir>/out -- /opt/OpenTee/bin/pkcs11_test
```

Stop the fuzzing session with <CTRL>+<C> and continue an old session using by replacing the `<corpus_dir>` with `-` in the above command.

### View Generated Coverage Information

After running an fuzzing session, run the following commands to generate an overview of the coverage information:

```bash
LD_PRELOAD=$(gcc -print-file-name=libasan.so) /opt/OpenTee/bin/opentee-engine -f

afl-cov --afl-fuzzing-dir <output_dir> --coverage-cmd  "cat AFL_FILE | LD_PRELOAD=$(gcc -print-file-name=libasan.so) /opt/OpenTee/bin/pkcs11_test" --code-dir <opentee_dir> --overwrite
```

This will generate an index.html file which can be viewed on a browser. 

**Note:** The engine MUST be running before the afl-cov command is executed!

**Note:** Cannot run afl-cov command with --live since the code there assumes AFL=1 is unset, contradicting the real fuzzing process in run.


## Debug

### Utilities

```bash
strings /opt/OpenTee/lib/TAs/liboptee_pkcs11_ta.so | grep gcda 

bash -c ../autogen.sh && make -j12 && sudo make install

sudo -E gdb -ex "set follow-fork-mode child" opentee-engine $(pidof tee_launcher)
```

