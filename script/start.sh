#!/bin/bash

ROOT_PATH="/root/apps/spring-oauth2-auth-server"
JAR="$ROOT_PATH/build/libs/spring-oauth2-auth-server-1.0.0.jar"

ERROR_LOG="$ROOT_PATH/error.log"
START_LOG="$ROOT_PATH/start.log"

NOW=$(date +%c)

echo "[$NOW] > 실행" >> $START_LOG
nohup java -jar $JAR 2> $ERROR_LOG > /dev/null &

SERVICE_PID=$(pgrep -f $JAR)
echo "[$NOW] > 서비스 PID: $SERVICE_PID" >> $START_LOG