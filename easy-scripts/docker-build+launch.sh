echo "If you want to stop docker, type docker stop \$(docker ps -aq)"
read -p "Press <ENTER> to continue" response
docker pull embsec2024/labs:x86_64
docker run -p 8888:8888 -e JUPYTER_ENABLE_LAB=yes embsec2024/labs:x86_64