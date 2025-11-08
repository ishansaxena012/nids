@echo off
echo "--- BUILDING C++ SENSOR ---"
cd ../sensor
g++ src/main.cpp src/packet_sniffer.cpp -o build/nids_sensor.exe -std=c++17 -lws2_32 -I"C:\npcap-sdk\Include" -L"C:\npcap-sdk\Lib" -lwpcap

echo "--- INSTALLING BACKEND DEPENDENCIES ---"
cd ../backend
npm install

echo "--- BUILD COMPLETE ---"
pause