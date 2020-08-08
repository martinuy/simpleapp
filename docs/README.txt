Simple App
=============================

Simple App is a toy application for educational purposes.
It provides a playground for exploring user and kernel APIs
in Linux, as well as privileged and unprivileged x86-64
instructions.

The application is made of the following components:

 * simpleapp (user-space executable)
 * libsimplelib.so (user-space library)
 * simplemodule.ko (kernel-space module)

Once started, simpleapp will dynamically load the kernel-module using
the library API. The kernel module will expose a character device
(/dev/simplemodule_dev) to communicate with the application through
IOCTLs. There are two IOCTL to retrieve the kernel-module output and
a general-purpose IOCTL to trigger chosen tests, with the capabilities
of sending and receiving data buffers of arbitrary length. At the end
of execution, the application will unload the kernel-module and free
resources for the next run.

The kernel-module can be used from multiple processes in parallel and
handle outputs separately.

One of the built-in tests is a syscalls-trampoline. System calls
executed from Simple App through the SM_SYS macro will be wrapped,
sent to the kernel-module and executed from there. This allows to
set breakpoints right before or after the call, while disabling
preemption and minimizing the chances of a breakpoint being hit
from a different process.

Macros 'BREAKPOINT' (user and kernel space) and BREAKPOINT_SET /
BREAKPOINT_UNSET (kernel space) allow to set programmatic breakpoints.
These macros, when used from kernel space, require help from GDB for
the necessary automation. BREAKPOINT generates a call to sm_debug
with the breakpoint number by parameter. From GDB we can set a breakpoint
there, print the breakpoint number and step out of the function for the
user to proceed. BREAKPOINT_SET / BREAKPOINT_UNSET generate a call to
sm_breakpoint_set / sm_breakpoint_unset, where the symbol of the function
to break is sent by parameter. From GDB we can break there, read the
symbol and set or unset a breakpoint, before continuing execution. To
debug the kernel-module with symbols, we need to load them at the
corresponding base address from GDB.

This code is not oriented to performance nor security, and should not
be used in production.

Requirements to run
=============================

 * Linux x86_64
  * Tested on Fedora Linux
 * Linux kernel headers

Simple App requires CAP_SYS_MODULE capabilities to run, as a
kernel-module has to be dynamically loaded. "root" user usually
satisfies this condition.

Run from the command line: ./simpleapp

NOTE: while compilation can be local, execution is expected to
occur in a remote virtual machine. The simpleapp.tar.gz tarball
is generated upon compilation for convenient deployment. Running
locally is NOT recommended and may compromise the system integrity.

How to build
=============================

Install the following build dependencies:

 * Linux kernel headers

Configure your environment and requirements:

 * Set 'KERNEL_HEADERS_PATH' environmental variable pointing to
   your kernel headers path.

 * In src/module/simplemodule.h, log verbosity can be set with
   LOG_VERBOSITY define.

Build:

 * ./build.sh
  * Binaries will be placed in the "bin" folder, and the "simpleapp.tar.gz"
    file (packing all binaries) will be generated.

To clean binaries:

 * ./build.sh clean


Changelog
=============================

.............................

Version: 1.0 - 2020-08-08

 * Initial version

.............................


License and credits
=============================

Simple App is under GPL v3 license. See docs/gpl.txt for
further information.

Original author: Martin Balao (martin.uy)
Contributors: Want to contribute? Join us on GitHub [1].

--
[1] - https://github.com/martinuy/simpleapp
