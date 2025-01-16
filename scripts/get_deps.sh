#!/bin/bash

AX_ROOT=.arceos

test ! -d "$AX_ROOT" && echo "Cloning repositories ..." || true
test ! -d "$AX_ROOT" && git clone git@github.com:yiming-gu/arceos.git -b monolithic --depth=1 "$AX_ROOT" || true

$(dirname $0)/set_ax_root.sh $AX_ROOT
