#!/bin/bash

cd /home/andrew/Sniffable || exit 1

./venv/bin/python ./code/server.py &

npm start
