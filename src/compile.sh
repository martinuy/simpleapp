#!/bin/bash

#
#   Martin Balao (martin.uy) - Copyright 2020
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

CFLAGS="-g -DDEBUG -O3"
CXXFLAGS="-g"

export CFLAGS="$CFLAGS"
export CXXFLAGS="$CXXFLAGS"

echo "Compiling lib..."
LIB_COMPILE_COMMAND="gcc ${CFLAGS} -o user/lib${LIB_NAME}.so -Imodule -fPIC -shared user/${LIB_NAME}.c -pthread"
echo "$LIB_COMPILE_COMMAND"
$LIB_COMPILE_COMMAND && chmod +x user/lib${LIB_NAME}.so

echo "Compiling app..."
TEST_COMPILE_COMMAND="gcc ${CFLAGS} -o user/${APP_NAME} -Wl,-rpath,\$ORIGIN -Iuser -Imodule -Luser user/${APP_NAME}.c -l${LIB_NAME} -pthread"
echo "$TEST_COMPILE_COMMAND"
$TEST_COMPILE_COMMAND

echo "Compiling module..."
cd module && make all && $(xz --compress --stdout ${MODULE_NAME}.ko > ${MODULE_NAME}.ko.xz) && chmod +x ${MODULE_NAME}.ko.xz && chmod +x ${MODULE_NAME}.ko && cd ..

