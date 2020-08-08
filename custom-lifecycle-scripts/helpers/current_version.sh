#!/usr/bin/env bash
toml get ./Cargo.toml package.version|jq -r .
