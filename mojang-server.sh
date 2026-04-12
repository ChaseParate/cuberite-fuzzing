#!/bin/sh

killall java
rm -rf minecraft
cp -r minecraft-template minecraft
cd minecraft
java -jar server.jar --nogui
