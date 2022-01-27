# LKM-hook syscall

Hook `execve` system call. Test in Ubuntu16.04,18.04,20.04.

It's only a demo for hook `execve`, you can add your code in hook.c to change the `execve` logic.

## Build&Install

First install build tools

```sh
sudo apt-get install build-essential kmod  linux-headers-`uname -r`
```

```sh
make all       # build
make install   # install module, need root
make uninstall # uninstall module, need root
```
