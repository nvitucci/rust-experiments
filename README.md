# Rust experiments

This repository collects my experiments with Rust. 
Each directory is a standalone project and can be built and run independently.

## `crypto`

In this project I implemented some popular encryption and digital signature algorithms. 
Here I explored many aspects of Rust, including:

- the basics of the Cargo system;
- importing and using external crates;
- splitting the code into modules and submodules;
- the basics of `struct`s and `enum`s with pattern matching;
- the meaning and usage of `trait`s;
- the difference between mutable and immutable variables;
- the basics of ownership and references;
- applying code style with `cargo fmt`;
- writing unit tests;
- how to turn comments into documentation, and how to build documentation with `cargo doc`.

The reference I used for the implementation of the algorithms is the evergreen [Handbook of Applied Cryptography](https://cacr.uwaterloo.ca/hac/).
The large numbers used in the `main` and in the tests are from another (as of now unpublished) project of mine.

**NOTE:** This project is not intended for any production use.