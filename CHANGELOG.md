# Change Log
All notable changes to this project will be documented in this file.

The format is partially based on [Keep a Changelog](http://keepachangelog.com/)

## Versions
### [Unreleased]
- Control `discover_replies` option in config

### [0.1.1] - 2025-07-02
- make `rand` dependency optional (generate discovery id from time if disabled)
- switch from `sha2` to `sha2_const_stable`
- do not check packet integrity using sha256 (only for pseudo-random packet ID)
- work with local ipv4 interface addresses only

### [0.1.0] - 2025-06-29

Baseline version of the project.

Features:
- interface configuration changes detection
- backup ports support (extended announcement)
- custom advertisement data