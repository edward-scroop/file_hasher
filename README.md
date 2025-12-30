# Hashsum
This is a personal project to learn about hashing algorithms by implementing them in rust. I intend to model the
behaviour of the GNU coreutils cksum program but as it is not a full rewrite i might not implement all behaviours.


## Getting Started
This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.


### Prerequisites

This is an example of how to list things you need to use the software and how to install them.
* rust >= 1.91
Install a compatible version either using your distro packages or rust's own tool rustup.

### Installation
For now there is no automated install script but a manual process can be followed below.

1. Run cargo install with release profile in the project directory.
   ```sh
   RUSTFLAGS=-Awarnings cargo build --release
   ```
3. Then copy the executable from the /project/release dir to where you wish and run the executable.


## Usage
The program can be run with filepaths to files you wish to get the hash of.


## License
Distributed under the GNU GPLv3 or later. See `LICENSE.md` for more information.


## Contact
Edward Scroop - <edward.scroop@gmail.com>
