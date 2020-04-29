# bls12-381-comparison
This is a quick benchmark between [Apache Milagro](https://github.com/apache/incubator-milagro-crypto) and
ZCash's [Pairing](https://crates.io/crates/pairing) library for the BLS signature scheme

The BLS signature scheme is useful for creating aggregated signatures. I wanted to find out which pairing library would be faster.
Any comments or suggestions to my quick and dirty test here are welcome. I'm not sure if I implemented according to each
libraries intended use but this is how I was able to get it to work.

To run the tests run the following command
```rust
cargo run --release -- --iterations {integer}
```

On average as of April 9 2019, ZCash's pairing tends to run 2-4X slower.


-----

UPDATE: Apr 29 2020
Using [pairing_plus](https://crates.io/crates/pairing-plus), ZCash's implementation runs about
100X faster that milagro

================================================================================
BLS Apache Milagro
------------------
Generating - 100 signatures...3.27s
Verifying - 100 signatures...3.87s
Verifying - multisignature...0.30s
Verifying - aggregated signature...3.31s
================================================================================


================================================================================
BLS ZCash pairing
-----------------
Generating - 100 signatures...0.30s
Verifying - 100 signatures...0.25s
Verifying - multisignature...0.00s
Verifying - aggregated signature...0.14s
================================================================================

