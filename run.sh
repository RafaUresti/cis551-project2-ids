#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export LD_LIBRARY_PATH=$DIR/lib:$LD_LIBRARY_PATH
java  -classpath bin:lib/jpcap.jar IDS $1 $2
