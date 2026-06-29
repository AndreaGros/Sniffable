#!/bin/bash

cd /home/andrew/Sniffable || exit 1

pulizia(){
 kill $SERVER_PID 2>/dev/null
 wait $SERVRR_PID 2>/dev/null
}

trap pulizia EXIT SIGINT SIGTERM

sudo ./venv/bin/python ./code/server.py &
SERVER_PID=$!

npm start