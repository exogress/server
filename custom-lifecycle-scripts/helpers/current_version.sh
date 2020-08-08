#!/usr/bin/env bash
toml get ./crates/common/Cargo.toml package.version|jq -r .
