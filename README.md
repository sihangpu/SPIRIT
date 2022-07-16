# SPIRIT
Toy implementation of SPIRIT

## Usage
> Since _Anonymous Github_ doesn't support downloading/cloning the repo, please directly download the `spirit.zip` to compile.

Please make sure you have installed `cmake`, `ninja` and `gls`, otherwise run the following command to install.
```bash
brew install cmake ninja gls
```
Note that `gls` is only required in `pqFMD` and you probably need to set `gls` compiling and linking flags properly as follows. Edit `/src/pqFMD/CMakeLists.txt` to set proper path as follows.
```bash
  add_compile_options(-I/opt/homebrew/Cellar/gsl/2.7.1/include)
  add_link_options(-L/opt/homebrew/Cellar/gsl/2.7.1/lib)
```


Build the project:
```bash
 cd SPIRIT
 mkdir build && cd build
 cmake -GNinja ..
 ninja
```

By default, the exectuable file in `build/src/test_spirit_ref` simply tests the functionality of $\mathsf{SPIRIT}_{w/o}$ (after transformation) 1000 times to calulate its average running time.
