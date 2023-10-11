# Sakizuke

Sakizuke is a utility for parsing Portable Executables, written in C.

It is built for conducting static analysis - cataloging structural information and empowering analytic capabilities.


## Installation

To get started, simply clone the repository and build the utility via _make_.

`git clone https://github.com/DeveshChande/Sakizuke.git`

`sudo apt install git make gcc libssl-dev libcurl4-openssl-dev libcmocka-dev`

`make`

`pulse [options] [file]`

## Options

`--path` : Specify the file path of the Portable Executable to be parsed.

`--computeHash`: Display MD5, SHA-1, and SHA256 hashes of the specified file.

`--vtLookup`: Display VirusTotal results.
              To use this switch, be sure to append the VirusTotal API Key into the virusTotalResults32() / virusTotalResults64() function.
