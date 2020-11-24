# Module Buld Guide

We assume you already know how to [bulid your kernel](KERNEL.md)

## Bulding the module
   
1. Clone this repository.
   
   Navigate to drivers directory in your kernel sources e.g. `src/linux-5.9.1/drivers` and copy directory `proc-integrity` from this repository there.
   
2. Navigate up to `src/linux-5.9.1/drivers`.

   Edit `Kcofig`. Add the following line:

   `source "drivers/proc-integrity/Kconfig"`

   before `endmenu`
   
   Edit `Makefile`. Add the following line:

   `obj-$(CONFIG_PROC_INTEGRITY)	+= proc-integrity/`

3. With the `O` parametter specifying your kernel build location, run the following command:

   ```bash
   $ make O=/path/to/build/linux-5.9.1 menuconfig
   ```
   
   A menu will pop up. Find and enable the following options as built-in <*> (not module <M>!):
   
   - Simple process integrity checker (Device Drivers)
   - Streebog (Device Drivers)
   
   Close the menu with saving configuration.

4. Build the kernel: `make O=/path/to/build/linux-5.9.1/ -j4`. Parameter `j` stands for thread count. 

## Using the module

Just run your the kernel. You should now see integrity check results at regular intervals.
