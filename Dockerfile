# Conpot honeypot with a custom ICS template.
#
# The stock honeynet/conpot image ships the "default" template, whose slave 1
# has no holding/input registers — so Modbus reads return IllegalAddress. This
# image bakes in conpot_template/, which gives slave 1 realistic, reproducible
# register data (a small pumping/water-treatment station) at address 0, so a
# normal client reads real process values and an attacker's write is accepted.
#
#   docker build -t conpot-ics:latest .
#   docker run -d --name conpot --restart unless-stopped \
#     -p 127.0.0.1:502:5020/tcp -p 127.0.0.1:102:10201/tcp \
#     -p 127.0.0.1:161:16100/udp -p 127.0.0.1:8080:8800/tcp \
#     -p 127.0.0.1:2121:2121/tcp -p 127.0.0.1:47808:47808/udp \
#     conpot-ics:latest
#
# Our template intentionally omits the stock ssl/ dir (an unused HTTPS/proxy
# cert + private key); Conpot starts and serves Modbus/S7/SNMP/HTTP fine without
# it, and no key lives in the repo.
FROM honeynet/conpot:latest

COPY conpot_template /template

CMD ["/home/conpot/.local/bin/conpot", "--template", "/template", \
     "--logfile", "/var/log/conpot/conpot.log", "-f", "--temp_dir", "/tmp"]
