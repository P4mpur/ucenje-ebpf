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
<<<<<<< HEAD
=======

### Building bpftool

There are several examples using `bpftool` throughout the book. To get a version
with libbfd support (which you'll need if you want to see the jited code in the 
Chapter 3 examples) you might need to build it from source:

```sh
cd ..
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src 
make install 
```

`bpftool` binaries are now also available from https://github.com/libbpf/bpftool/releases these days.

## Examples

You won't be surprised to learn that the directories correspond to chapters in
the book. Here are the different examples that accompany each chapter.

* Chapter 1: What Is eBPF and Why Is It Important?
* [Chapter 2: eBPF's "Hello World"](chapter2/README.md) - Basic examples using the BCC framework.
* [Chapter 3: Anatomy of an eBPF Program](chapter3/README.md) - C-based XDP
  examples, used in the book to explore how the source code gets transformed to eBPF bytecode and
  machine code. There's also an example of BPF to BPF function calls.
* [Chapter 4: The bpf() System Call](chapter4/README.md) - More BCC-based examples, used in the book to
  illustrate what's happening at the syscall level when you use eBPF.
* [Chapter 5: CO-RE, BTF and Libbpf](chapter5/README.md) - Libbpf-based C
  example code.
* [Chapter 6: The eBPF Verifier](chapter6/README.md) - Make small edits to the
  example code to cause a variety of verifier errors!
* [Chapter 7: eBPF Program and Attachment Types](chapter7/README.md) - Examples
  of different eBPF program types.
* [Chapter 8: eBPF for Networking](chapter8/README.md) - Example code that
  attaches to various points in the network stack to interfere with ping and
  curl requests. *Coming soon, load balancer example*
* Chapter 9: eBPF for Security - *coming soon*
* [Chapter 10: eBPF Programming](chapter10/README.md) - The book explores examples from various eBPF
  libraries.
* Chapter 11: The Future Evolution of eBPF

There are no code examples for Chapters 1 and 11.

### Privileges

You'll need root privileges (well, strictly CAP_BPF and [additional
privileges](https://mdaverde.com/posts/cap-bpf/)) to be able to load BPF
programs into the kernel. `sudo -s` is your friend.

### View eBPF trace output

A couple of ways to see the output from the kernel's trace pipe where eBPF
tracing gets written:

* `cat /sys/kernel/debug/tracing/trace_pipe`
* `bpftool prog tracelog`

## Corrections

I'd love to hear if you find corrections and improvements for
these examples. Issues and PRs are welcome!
