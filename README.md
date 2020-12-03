# Simple Process Integrity Checker

Simple Process Integrity Checker is a kernel module for monitoring the integrity of the process static memory segment during it's execution.

## Description

### Overview

The module uses the Streebog256 hash to monitor the integrity of the memory segments of the process marked as non-writable. The memory state is hashed when the module detects the process at the first time (after `_do_fork` returns) and then checked for changes at regular intervals (5 seconds by default).

The module has been tested with Linux 5.9.1.

### Verbosity settings

Currently there are three verbosity settings:

| Log level                      | Description                                                           |
|--------------------------------|-----------------------------------------------------------------------|
| `PI_LOG_LEVEL_LOW`             | Notify only when digest changes                                       |
| `PI_LOG_LEVEL_MEDIUM`          | Notify at every digest check                                          |
| `PI_LOG_LEVEL_HIGH` (default)  | Same as PI_LOG_LEVEL_MEDIUM, but also:<br> - print the memory sections table<br> - notify when a process to be inspected is created<br> - notify when a process that is inspected dies |

This parameter can be changed by setting the `PI_LOG_LEVEL` in `logging.h` (see [here](https://github.com/kovdan01/proc-integrity/blob/fc625af5fda95d44669d4fbfac2b756bae8b1095/proc-integrity/logging.h#L31))

Sample output with `PI_LOG_LEVEL_HIGH`:

```
[    8.661280] PROC_INTEGRITY: info:  memory sections with VM_WRITE=false for PID=1
[    8.664900] PROC_INTEGRITY: info:              from               to            flags                                                             hash
[    8.670402] PROC_INTEGRITY: info:  0000000000400000-0000000000401000 0000000000000871 a1c270a547b226ad55a19810b7400b535b65f5c0e5cf8adcdae3726986b808d5
[    8.676080] PROC_INTEGRITY: info:  0000000000401000-00000000004e5000 0000000000000875 bbd4459b7d681e35648ad5bd6b4351b4f1310f642829cde0a414b92ff937faaf
[    8.681465] PROC_INTEGRITY: info:  00000000004e5000-0000000000516000 0000000000000871 4d236e72efafa35e49e7c41aacdd93016a4697034ed53fb8b25ba7abbf774206
[    8.686863] PROC_INTEGRITY: info:
[    8.688264] PROC_INTEGRITY: info:  non-writeable memory sections remain the same in process with PID 1
```

### Immediate actions settings

You can specify what action to perform when a digest change is detected. Currently there are three options:

| Immediate action                         | Description                                                |
|------------------------------------------|------------------------------------------------------------|
| `PI_IMMEDIATE_ACTION_NONE`               | Do nothing                                                 |
| `PI_IMMEDIATE_ACTION_POWEROFF` (default) | Call `kernel_power_off`                                    |
| `PI_IMMEDIATE_ACTION_KILL `              | Send `SIGKILL` to a process which memory state has changed |

This parameter can be changed by setting the `PI_IMMEDIATE_ACTION` in `immediate_action.h` (see [here](https://github.com/kovdan01/proc-integrity/blob/9e0927603f2579339955cee5af2df23ede54ff61/proc-integrity/immediate_action.h#L33))

### Other user-defined settings

The following parameters can be changed in `proc_integrity.c`

1. The module inspects processes at regular intervals, and this period can be set as `TIMER_PERIOD` (see [here](https://github.com/kovdan01/proc-integrity/blob/fc625af5fda95d44669d4fbfac2b756bae8b1095/proc-integrity/proc_integrity.c#L38))

2. The list of PIDs to inspect can be set as `MONITORED_PIDS` (see [here](https://github.com/kovdan01/proc-integrity/blob/fc625af5fda95d44669d4fbfac2b756bae8b1095/proc-integrity/proc_integrity.c#L42)). Do not forget to update `MONITORED_PIDS_COUNT` if necessary!

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
