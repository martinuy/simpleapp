#!/bin/bash

#
#   Martin Balao (martin.uy) - Copyright 2020, 2024
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

########################
##       Configs      ##
########################

export APP_NAME="simpleapp"
export LIB_NAME="simplelib"
export MODULE_NAME="simplemodule"

######################
##      Script      ##
######################

if [[ -z "${KERNEL_HEADERS_PATH}" ]]; then
    echo "Must define KERNEL_HEADERS_PATH environmental variable to compile."
exit
fi

##
# Clean
##

cd src
./clean.sh
cd ..

rm -f ${APP_NAME}.tar.gz
rm -rf bin

if [ $1 = "clean" ]; then
    exit 0
fi

##
# Build
##

cd src
./compile.sh
cd ..

mkdir bin
cp src/user/${APP_NAME} bin
cp src/user/lib${LIB_NAME}.so bin
cp src/module/${MODULE_NAME}.ko bin

tar cvzf ${APP_NAME}.tar.gz --transform s/bin/${APP_NAME}/ bin
mv ${APP_NAME}.tar.gz bin
