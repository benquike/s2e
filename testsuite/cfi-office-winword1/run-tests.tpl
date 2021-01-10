#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

CALL_COUNT=$(grep "calls:" $S2E_LAST/debug.txt | tail -n 1 | cut -d ':' -f 3 | cut -d ' ' -f 2)
if [ "x$CALL_COUNT" = "x" ]; then
    echo "Invalid call count"
    exit 1
fi

if [ ! $CALL_COUNT -gt 0 ]; then
    echo "Call count is null"
    exit 1
fi

CALLV_COUNT=$(grep "calls:" $S2E_LAST/debug.txt | tail -n 1 | cut -d ':' -f 5 | cut -d ' ' -f 2)
if [ "x$CALLV_COUNT" = "x" ]; then
    echo "Invalid call violation count"
    exit 1
fi

if [ $CALLV_COUNT -gt 0 ]; then
    echo "Call violation count is not null"
    exit 1
fi

RETV_COUNT=$(grep "calls:" $S2E_LAST/debug.txt | tail -n 1 | cut -d ':' -f 6 | cut -d ' ' -f 2)
if [ "x$RETV_COUNT" = "x" ]; then
    echo "Invalid ret violation count"
    exit 1
fi

if [ $RETV_COUNT -gt 0 ]; then
    echo "Ret violation count is not null"
    exit 1
fi
