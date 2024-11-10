#!bin/bash/sh
pkg update 
pkg upgrade -y
apt update
apt upgrade -y
apt list --upgradable
apt --fix-broken install
pkg install rust git
rm -rf ~/RustyScanner
cd ~
git clone https://github.com/adfastltda/RustyScanner.git
cd ~/RustyScanner/Scan/
cargo build --release
cp ~/RustyScanner/Scan/target/release/scanner $PREFIX/bin/scan
rm -rf ~/RustyScanner
scan -h