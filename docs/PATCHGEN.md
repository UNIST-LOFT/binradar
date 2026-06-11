```sh
# Install Guix
cd /tmp
wget https://guix.gnu.org/guix-install.sh
chmod +x guix-install.sh
./guix-install.sh
# Pull the latest guix
cp ./utils/channels.scm ~/.config/guix/channels.scm
guix pull
# Install taosc
guix build taosc
# Build buggy binary
guix build binutils@2.29
cd benchmarks/loftix/binutils/CVE-2017-14940
# Use just (https://github.com/casey/just)
just taosc
# Or run directly
guix shell taosc -- taosc-fix 1 workdir poc "$(guix build binutils@2.29)/bin/nm" -l @@
```
