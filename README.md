# Search Helpers

![Rust](https://github.com/IronCoreLabs/search-helpers/workflows/Rust/badge.svg)

This is a crate of some generic encrypted search helpers which can be used to create blind indexes.

For now this supports is being able to create an index on strings using tri-grams. The tri-grams are hashed
using a salt as well as an optional partition_id.

## Publishing

Due to the generic nature of what this crate is, we don't publish it to crates.io. We do tag the repository to allow
depending on stable versions of this repository.
