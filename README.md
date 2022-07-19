# SPIRIT
Toy implementation of SPIRIT

## Usage
> Since _Anonymous Github_ doesn't support downloading/cloning the repo, please directly download the `spirit.zip` to compile.

Please make sure you have installed `cmake` and `ninja` , otherwise run the following command to install.
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

By default, the exectuable files in `SPIRIT/build/src/` will run $\mathsf{SPIRIT}$ w/ and w/o KEY_EXPOSURE_SECURITY for security levels 128, 192, and 256. Additionally, there's also the version with Falcon integrated for more compact signature size. Fuzzy trackings, i.e., Post-quantum FMD and ScalableFuzzyTracking can also be tested in the folder `SPIRIT/build/src/pqFMD/` and `/SPIRIT/build/src/scalableFuzzy`, respectively.
