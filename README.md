I've also provided a [Lima](https://github.com/lima-vm/lima) config file with
the packages you need for building the code pre-installed.

If you have a Linux machine or VM to hand, feel free to use that instead of
Lima, using the `learning-ebpf.yaml` file as a guide for the packages you'll 
need to install. The minimum kernel version required varies from chapter to chapter. All
these examples have been tested on an Ubuntu distribution using a 5.15 kernel. 

### Install this repo

```sh
git clone --recurse-submodules https://github.com/lizrice/learning-ebpf
cd learning-ebpf
>>>>>>> 311b1d5 (Additions to README.md)
```
git clone https://github.com/lizrice/learning-ebpf

cd learning-ebpf
limactl start ubuntu-ebpf.yaml
limactl shell ubuntu-ebpf

cd learning-ebpf
git submodule init
git submodule add https://github.com/libbpf/libbpf

sudo -s
```

## Building bpftool

To get libbfd support you might need to build bpftool from source

```
