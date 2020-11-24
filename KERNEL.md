# Running a debuggable Linux kernel with QEMU

## Setting up the kernel
 
1. Make the following directory structure:

   ```
   kernel-module
   │   ├── build
   │   │   ├── busybox-1.32.0
   │   │   ├── linux-5.9.1
   │   │   └── musl-1.2.1
   │   ├── src
   │   │   ├── busybox-1.32.0
   │   │   ├── linux-5.9.1
   │   │   └── musl-1.2.1
   ```
   
2. Download sources:
   
   - Linux kernel 5.9.1: https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.9.1.tar.xz. Extract it to `kernel-module/src/linux-5.9.1`
   - BusyBox 1.32.0: https://busybox.net/downloads/busybox-1.32.0.tar.bz2. Extract it to `kernel-module/src/busybox-1.32.0`
   - musl libc: https://musl.libc.org/releases/musl-1.2.1.tar.gz. Extract it to `kernel-module/src/musl-1.2.1`
   
3. Assuming current directory is `kernel-module/src/linux-5.9.1`, run the following commands:

   ```bash
   $ make O=../../build/linux-5.9.1 x86_64_defconfig
   $ make O=../../build/linux-5.9.1 kvmconfig
   $ make O=../../build/linux-5.9.1 menuconfig
   ```
   
   A menu will pop up. Find and enable the following options in it:
   
   - DEBUG_KERNEL (Kernel hacking -> Kernel debugging)
   - DEBUG_INFO (Kernel hacking -> Compile-time checks and compiler options -> Compile the kernel with debug info)
   - CONFIG_GDB_SCRIPTS (Kernel hacking -> Compile-time checks and compiler options -> Compile the kernel with debug info -> Provide GDB scripts for kernel debugging)
   - CONFIG_KGDB (Kernel hacking -> Generic Kernel Debugging Instruments -> KGDB: kernel debugger)
   - CONFIG_KGDB_SERIAL_CONSOLE (Kernel hacking -> Generic Kernel Debugging Instruments -> KGDB: kernel debugger -> KGDB: use kgdb over the serial console)
   - UBSAN (Kernel hacking -> Generic Kernel Debugging Instruments -> Undefined behaviour sanity checker)
   - KASAN (Kernel hacking -> Memory debugging -> KASAN: runtime memory debugger)
   - CONFIG_KALLSYMS (General setup -> Load all symbols for debugging/ksymoops)
   - CONFIG_KALLSYMS_ALL (General setup -> Load all symbols for debugging/ksymoops -> Include all symbols in kallsyms)
   - CONFIG_IKCONFIG (General setup -> Kernel .config support)
   - CONFIG_IKCONFIG_PROC (General setup -> Kernel .config support -> Enable access to .config through /proc/config.gz)
   
   Press `/` and find the following options. Make sure that they are enbaled. If you see that there are options that need to be enabled as preconditions for them, enable them too.
   
   - DEBUG_BUGVERBOSE
   - CONFIG_FRAME_POINTER
   
   Close the menu with saving configuration.

4. Build the kernel: `make O=../../build/linux-5.9.1/ -j4`. Parameter `j` stands for thread count. 

5. BusyBox provides a lot of standard Unix utilities (like `ls`, `pwd`, `cp`, etc.) as a single executable. We need to build it as a static binary. Some linux distributions (e.g. Arch Linux) do not provide static version of libc, that's why wee need to build musl-libc first (musl is a light-weight implementation of libc). Assuming current directory is `kernel-module/build/musl-1.2.1`, run the following commands:

   ```bash
   $ MUSL_BASE=`pwd`
   $ ../../src/musl-1.2.1/configure --prefix=$MUSL_BASE
   $ make
   $ make install
   $ 
   $ cd $MUSL_BASE/bin
   $ ln -s `which ar` musl-ar
   $ ln -s `which strip` musl-strip
   $ cd $MUSL_BASE/include
   $ ln -s /usr/include/linux linux
   $ ln -s /usr/include/mtd mtd
   $ ln -s /usr/include/asm asm
   $ ln -s /usr/include/asm-generic asm-generic
   $
   $ PATH=$MUSL_BASE/bin:$PATH
   ```

6. Assuming current directory is `kernel-module/src/busybox-1.32.0`, run the following commands:
   
   ```bash
   $ make O=../../build/busybox-1.32.0 defconfig
   $ make O=../../build/busybox-1.32.0 menuconfig
   ```
   
   A menu will pop up. Find and enable STATIC option in Settings -> Build static binary (no shared libs). Also set CROSS_COMPILER_PREFIX to `musl-` in Settings -> Cross compiler prefix. Close the menu with saving configuration.
   
7. Go to `kernel-module/build/busybox-1.32.0` and build BusyBox:
   
   ```bash
   $ make -j4
   $ make install
   ```
   
8. Now we need to create a minimal file system. Create directory `kernel-module/build/initramfs` and go into it. Run:
   
   ```bash
   $ mkdir -pv {bin,sbin,etc,proc,sys,usr/{bin,sbin}}
   $ cp -rv ../busybox-1.31.1/_install/* .
   ```
   
9. Create init script:
   
   ```bash
   $ touch init
   $ chmod +x init
   ```
   
   Paste the following code to it:
   
   ```bash
   #!/bin/sh
   
   mount -t proc none /proc
   mount -t sysfs none /sys
   mount -t devtmpfs none /dev
   
   echo "Welcome to your Linux kernel!"
   
   exec /bin/sh
   ```
    
10. Build initrams file: `find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz`. It is recommended to create a shell script `make-initramfs.sh` doing it and place it in the parent directory for future use:
    
    ```bash
    #!/bin/sh
    
    cd initramfs
    find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
    cd ..
    ```

11. Go to `kernel-module` directory and create a shell script `start.sh` with the following content:
    
    ```bash
    #!/bin/sh

    qemu-system-x86_64 \
        -kernel build/linux-5.9.1/arch/x86_64/boot/bzImage \
        -initrd build/initramfs.cpio.gz \
        -nographic \
        -append "console=ttyS0 nokaslr" \
        -cpu host \
        -enable-kvm \
        -gdb tcp::1234
    ```
    
12. Run `./start.sh` and check that everything works properly. To exit Qemu, press Ctrl+a -> c -> q -> Enter.

## Debugging the kernel

13. Create `debug.sh` shell script with the following command: `gdb build/linux-5.9.1/vmlinux`. Run it. If gdb asks you to add some path to .gdbinit, do it.

14. In gdb, run the following commands:
    
    ```
    (gdb) lx-symbols
    (gdb) target remote :1234
    ```
    
    Breakpoints are set like this: `b fs/read_write.c:452`. To continue running guest kernel, enter `c`. To break debuggee execution in any place, press Ctrl+c.
