# SPIRIT
Toy implementation of SPIRIT

## Usage
> Since _Anonymous Github_ doesn't support downloading/cloning the repo, please directly download the `spirit.zip` to compile.

Please make sure you have installed `cmake` and `ninja`, otherwise run the following command to install.
```bash
brew install cmake ninja
```

Build the project:
```bash
 cd SPIRIT
 mkdir build && cd build
 cmake -GNinja ..
 ninja
```

By default, the exectuable file in `build/src/test_spirit_ref` simply tests the functionality of $\mathsf{SPIRIT}_{w/o}$ (after transformation) 1000 times to calulate its average running time.
