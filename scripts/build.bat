@echo off
echo "--- BUILDING C++ SENSOR ---"
cd ../sensor
$ g++ src/main.cpp src/packet_sniffer.cpp -I "C:/npcap-sdk/Include" -L "C:/npcap-sdk/Lib" -o build/nids_sensor.exe -lwpcap -lpacket -lws2_32 -O2
echo "--- INSTALLING BACKEND DEPENDENCIES ---"
cd ../backend
npm install

echo "--- BUILD COMPLETE ---"
pause