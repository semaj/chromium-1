set -e
autoninja -C out/Default chrome
#CHROME_IPC_LOGGING=1 ./out/Default/chrome --log-level=0 --enable-logging=stderr --headless --remote-debugging-port=9222  --disable-gpu --no-first-run=true --no-default-browser-check=true --no-proxy-server=true --no-sandbox --origin-to-force-quic-on=jameslarisch.com:443 --host-resolver-rules="MAP jameslarisch.com:443 127.0.0.1:443" https://jameslarisch.com/latency-assets/catsock.html --user-data-dir=/tmp/$(openssl rand -hex 16)

