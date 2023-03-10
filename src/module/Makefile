#
#   Martin Balao (martin.uy) - © Copyright 2020, 2023
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

obj-m += ${MODULE_NAME}.o
simplemodule-objs := simplemodule_main.o simplemodule_core.o simplemodule_kernel_lib.o simplemodule_asm.o

ccflags-y := ${CFLAGS}

all:
	make -C ${KERNEL_HEADERS_PATH} M=$(PWD) modules

clean:
	make -C ${KERNEL_HEADERS_PATH} M=$(PWD) clean
