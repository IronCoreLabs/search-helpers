# Search Helpers

[![Crates](https://img.shields.io/crates/v/ironcore-search-helpers.svg)](https://crates.io/crates/ironcore-search-helpers) [![Docs](https://docs.rs/ironcore-search-helpers/badge.svg)](https://docs.rs/ironcore-search-helpers)![Rust](https://github.com/IronCoreLabs/search-helpers/workflows/Rust/badge.svg)

A Rust library for encrypted search helpers which can be used to create blind indexes.

For now this supports creating an index on strings using tri-grams. The tri-grams are hashed
using a salt as well as an optional partition_id.
