from alpine:latest

run apk add wget gnupg sqlite unzip build-base perl perl-dev perl-app-cpanminus
run cpanm --notest IPC::Run DBD::SQLite Net::DNS::Resolver Crypt::Eksblowfish::Bcrypt JSON URI::Escape HTML::Entities String::ShellQuote Net::Server HTTP::Server::Simple Crypt::Random

run mkdir -p /opt/data/plans
copy schema.sql /opt/data
run cat /opt/data/schema.sql | sqlite3 /opt/data/users.db
run rm /opt/data/schema.sql

run apk del build-base perl-dev perl-app-cpanminus wget sqlite unzip

copy server.pl /opt
workdir /opt

entrypoint ["/usr/bin/perl", "server.pl"]
