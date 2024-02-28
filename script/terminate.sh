#!/bin/bash
TERM_LOG="$ROOT_PATH/terminate.log"

echo "서비스 종료 " >> $TERM_LOG
kill -15 $(sudo lsof -t -i:9000)