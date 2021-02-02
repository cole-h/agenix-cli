# agenix-rs

This project provides a binary, `agenix`, intended for use with
https://github.com/ryantm/agenix and aims to provide a more sophisticated
replacement for the shell script version of `agenix`.

## Configuration

For an example configuration, check out the
[.agenix.toml.example](./.agenix.toml.example) file.

The basic layout is one `[identities]` TOML table and one or many `[[paths]]`
TOML array-of-tables. The `[identities]` table is essentially an association of
identity names (which can be anything that TOML itself supports as a key) to its
public key.

> **__NOTE__**: The given name is only so that you can use multiple keys for
multiple globs (mentioned below) without having to copy-paste the key everywhere
-- it holds no other meaning.

The `[[paths]]` array-of-tables contains two keys: `glob` and `identities`.
`glob` is a a path glob `agenix` uses to match against, and `identities` is an
array of identities (either specified by a name that is then looked up in the
`[identities]` table, or the public key itself).

## Usage

Using `agenix` is as simple [setting up a configuration](#configuration) and
then running `agenix [file]`.

> **__NOTE__**: If the specified file exists and was previously encrypted to an
`age` identity, you must use the `-i`/`--identity` flag to specify the private
key associated with that identity; otherwise, `agenix` will be unable to decrypt
the contents.
