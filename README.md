# Simple Process Integrity Checker

Simple Process Integrity Checker is a kernel module for monitoring the integrity of the process static memory segment during it's execution.

## Description

The module uses the Streebog256 hash to monitor the integrity of the memory segments of the process marked as non-writable. The memory state is hashed when the module detects the process at the first time and then checked for changes at regular intervals (5 seconds by default).

Currently there are three verbosity settings:

| Log level                      | Description                                                           |
|--------------------------------|-----------------------------------------------------------------------|
| `PI_LOG_LEVEL_LOW`             | Notify only when hash changes                                         |
| `PI_LOG_LEVEL_MEDIUM`          | Notify at every hash check                                            |
| `PI_LOG_LEVEL_HIGH` (default)  | Same as PI_LOG_LEVEL_MEDIUM, but also print the memory sections table |

This parameter can be changed by setting the PI_LOG_LEVEL in `logging.h`

The module has been tested with Linux 5.9.1.

## Getting Started

### Dependencies

The module requires Streebog hash enabled in the kernel. You can check the [Module Build Guide](MODULE.md) for reference on how to do this.

### Installing

See [Running a debuggable Linux kernel with QEMU](KERNEL.md) and [Module Build Guide](MODULE.md) for instructions on how to set up your kernel and use the module respectively.

## Authors

Daniil Kovalev    <dyukovalev@edu.hse.ru>

Igor Shcherbakov  <ilscherbakov@edu.hse.ru>

## License

This project is licensed under the GNU GPL v2 License - see the LICENSE file for details
