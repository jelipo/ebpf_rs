FROM harbor.jelipo.com/luna/ubuntu:22.04

COPY target/release/protocol /app/

CMD /app/protocol --pid 1111
