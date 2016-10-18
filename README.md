# lwe-frodo

**lwe-frodo** is a C cryptographic library for post-quantum key exchange based on the learning with errors (LWE) problem.  It is based on the following research paper:

- Joppe Bos, Craig Costello, Léo Ducas, Ilya Mironov, Michael Naehrig, Valeria Nikolaenko, Ananth Raghunathan, Douglas Stebila.  **Frodo: Take off the ring!  Practical, quantum-secure key exchange from LWE**.  In *ACM Conference on Computer and Communications Security (CCS) 2016*, ACM, October, 2016.  DOI:[10.1145/2976749.2978425](http://dx.doi.org/10.1145/2976749.2978425), Eprint [http://eprint.iacr.org/2016/659](http://eprint.iacr.org/2016/659).

You can [download the PDF](https://github.com/lwe-frodo/lwe-frodo/blob/master/LWE-Frodo-full-version.pdf) of the paper from the GitHub repository.

Python scripts for selecting parameters are available in the [lwe-frodo/parameter-selection](https://github.com/lwe-frodo/parameter-selection) repository.

## Building

The software is plain C.  Compilation has been tested using gcc on Ubuntu 16.04.1 and clang on Mac OS X 10.11.6.  The software uses some routines from OpenSSL's libcrypto, so you will need to have OpenSSL installed.

### To compile on Ubuntu:

	sudo apt-get install make gcc libssl-dev
	make

### To compile on Mac OS X using brew:

You will need to have installed the Xcode developer tools, including the command-line programs and the [brew](http://brew.sh) package manager.

	brew install openssl
	make OPENSSL_DIR=/usr/local/opt/openssl
	
(You can also uncomment the appropriate line in the `Makefile` and then you only need to type `make`.)

You can also download and compile OpenSSL yourself following the instructions on the [OpenSSL website](https://www.openssl.org/).  You will need to edit the `Makefile` to point to your copy of OpenSSL.

## Running

To run the basic test harness, type:

	./test
	
This will test various aspects of the library, including:

- correctness of routines for packing / unpacking vectors in bit arrays
- correctness and distribution of random sampling
- correctness of key exchange

You can run the test harness in continuous mode by typing:

	./test cont
	
This will run the test harness indefinitely (hit `Ctrl-C` to stop).  Given that the probability of failure for the default parameters is 2<sup>-38.9</sup>, you should not see any failures unless you run it for several billion iterations.

You can get runtime benchmarking results by typing:

	./test bench

In order to obtain accurate benchmarking results, you should disable hyperthreading (a.k.a. hardware multithreading) and TurboBoost.  `./test bench` will output instructions on how to do so.

## Parameters

The software includes 4 parameters sets, as described in the paper:

- **challenge** — smaller parameters that should be reasonably accessible within the current cryptanalytic state-of-the-art
- **classical** — provides 128-bit security against best-known classical attacks, but not against quantum attackers
- **recommended** — provides ≥128 bits of security against best-known quantum attacks
- **paranoid** — provides 128 bits of security against an algorithm reaching the complexity lower bound for sieving algorithms (see [paper](https://github.com/lwe-frodo/lwe-frodo/blob/master/LWE-Frodo-CCS-BCDMNNRS16.pdf) for details)

By default, the recommended parameters are used.  This can be configured by editing `lwe.h`.

## License

This software is licensed under the MIT License.  For details, see [LICENSE.txt](https://github.com/lwe-frodo/lwe-frodo/blob/master/LICENSE.txt).

## Acknowledgements

JB and LD were supported in part by the Commission of the European Communities through the Horizon 2020 program under project number 645622 (PQCRYPTO).  DS was supported in part by Australian Research Council (ARC) Discovery Project grant DP130104304 and a Natural Sciences and Engineering Research Council of Canada (NSERC) Discovery Grant.  The authors would like to thank Adam Langley, Eric Grosse, and Úlfar Erlingsson for their inputs. A large part of this work was done when VN was an intern with the Google Security and Privacy Research team.
