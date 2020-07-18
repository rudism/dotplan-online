#!/usr/bin/env sh

cmd=$1

killserver() {
  if [ -f "dotplan.pid" ]; then
    kill -9 $(cat dotplan.pid)
    rm dotplan.pid
  fi
}

if [ "$cmd" = "run" ]; then
  killserver
  perl server.pl
elif [ "$cmd" = "daemon" ]; then
  killserver
  perl server.pl -d
elif [ "$cmd" = "kill" ]; then
  killserver
elif [ "$cmd" = "initdb" ]; then
  if [ -f "users.db" ]; then
    rm users.db
  fi
  cat schema.sql | sqlite3 users.db
else
  echo 'Usage: ctl [command]'
  echo
  echo 'Commands:'
  echo '  run'
  echo '  kill'
  echo '  initdb'
fi
