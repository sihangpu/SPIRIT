# SPIRIT
Toy implementation of SPIRIT

## Usage

Please make sure you have installed `openssl`, `cmake` and `ninja`, otherwise run the following command to install.
```bash
brew install cmake ninja openssl
```

Build the project:
```bash
 git clone -b master https://github.com/sihangpu/SPIRIT.git
 cd SPIRIT
 mkdir build && cd build
 cmake -GNinja ..
 ninja
```

By default, the exectuable file in `build/src/test_spirit_ref` simply tests the functionality of SPIRIT_{w/o} (after transfermation) 1000 times to calulate its running time.
