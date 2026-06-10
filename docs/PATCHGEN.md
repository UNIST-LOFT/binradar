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
mkdir -p out/binutils/cve-2017-14940
guix shell taosc
taosc-fix 1 out ./benchmarks/loftix/bugs/cve/2017/14940  /gnu/store/s2ga20pj4jiiya53nr2rbiqsdh778k3b-binutils-2.29/bin/nm -l @@

```
