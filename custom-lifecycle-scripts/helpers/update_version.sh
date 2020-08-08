#!/usr/bin/env bash

NEW_VERSION=$1

NEW_CARGO_TOML=`toml set ./Cargo.toml package.version ${NEW_VERSION}`

echo "${NEW_CARGO_TOML}" > ./Cargo.toml

git add ./Cargo.*
