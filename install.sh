#!/bin/sh
pkg install rust -y
pkg install git -y
rm -rf ~/RustyScanner
cd ~
git clone https://github.com/adfastltda/RustyScanner.git
cd ~/RustyScanner/Scan/
cargo build --release
cp ~/RustyScanner/Scan/target/release/scanner $PREFIX/bin/scan
rm -rf ~/RustyScanner
scan -h
