from alpine:latest

run apk add wget libsodium libsodium-dev cmake pkgconfig sqlite unzip build-base libmagic file-dev perl perl-dev perl-app-cpanminus

run cpanm --notest IPC::Run DBD::SQLite Net::DNS::Resolver Crypt::Eksblowfish::Bcrypt JSON URI::Escape HTTP::Accept Net::Server HTTP::Server::Simple HTTP::Server::Simple::Static Crypt::Random

run mkdir -p /tmp/minisign && \
  cd /tmp/minisign && \
  wget -O minisign.zip https://github.com/jedisct1/minisign/archive/master.zip && \
  unzip minisign.zip && \
  cd minisign-master && \
  mkdir build && \
  cd build && \
  cmake .. && \
  make && \
  make install

run mkdir -p /opt/data/plans
copy schema.sql /opt/data
run cat /opt/data/schema.sql | sqlite3 /opt/data/users.db
run rm /opt/data/schema.sql

run apk del build-base perl-dev perl-app-cpanminus wget sqlite unzip file-dev cmake pkgconfig libsodium-dev

copy server.pl /opt
workdir /opt

entrypoint ["/usr/bin/perl", "server.pl"]
