#!/usr/bin/env bash

BASEDIR=$(cd "$(dirname "$0")"; pwd)
PORT=14227
TEST_USER=testuser@example.com
FAILED=0

###################
# Utility Functions
###################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

wait_file() {
  local file="$1"
  local wait_seconds="${2:-10}"
  until test $((wait_seconds--)) -eq 0 -o -f "$file" ; do sleep 1; done
  ((++wait_seconds))
}

curl_test() {
  test_name=$1;shift
  expect_response_code=$1;shift
  expect_content_type=$1;shift
  TEST_CONTENT=$(curl -s -H "Content-Type: application/json" -w '%{stderr}%{response_code}|%{content_type}' "$@" 2>"$BASEDIR/data/err")
  exit_code=$?
  if [ $exit_code -ne 0 ]; then
    printf "${RED}✗ TEST${NC} ${BOLD}$test_name${NC} with exit code $exit_code\n"
    ((++FAILED))
    return 1
  fi
  stderr=$(<"$BASEDIR/data/err")
  response_code=$(echo $stderr | cut -f1 -d'|')
  content_type=$(echo $stderr | cut -f2 -d'|')
  if [ "$response_code" != "$expect_response_code" ]; then
    printf "${RED}✗ TEST${NC} ${BOLD}$test_name${NC} with response code $response_code\n"
    ((++FAILED))
    return 1
  fi
  if [ "$content_type" != "$expect_content_type" ]; then
    printf "${RED}✗ TEST${NC} ${BOLD}$test_name${NC} with content type $content_type\n"
    ((++FAILED))
    return 1
  fi
  printf "${GREEN}✓ TEST${NC} ${BOLD}$test_name${NC}\n"
  return 0
}

assert_equal() {
  check_name=$1;shift
  actual=$1;shift
  expected=$1;shift
  if [ "$actual" != "$expected" ]; then
    printf "${RED}✗ CHECK${NC} ${BOLD}$check_name${NC}\n\n\"${YELLOW}"; echo -n "$actual"; printf "${NC}\" != \"${YELLOW}"; echo -n "$expected"; printf "${NC}\"\n\n"
    ((++FAILED))
    return 1
  fi
  printf "${GREEN}✓ CHECK${NC} ${BOLD}$check_name${NC}\n"
  return 0;
}

assert_equal_jq() {
  selector=$1;shift
  expected=$1;shift
  actual=$(echo "$TEST_CONTENT" | jq -r "$selector")
  if [ "$actual" != "$expected" ]; then
    printf "${RED}✗ CHECK${NC} ${BOLD}$selector${NC}\n\n\"${YELLOW}"; echo -n "$actual"; printf "${NC}\" != \"${YELLOW}"; echo -n "$expected"; printf "${NC}\"\n\n"
    ((++FAILED))
    return 1
  fi
  printf "${GREEN}✓ CHECK${NC} ${BOLD}$selector${NC}\n"
  return 0;
}

assert_notequal_jq() {
  selector=$1;shift
  expected=$1;shift
  actual=$(echo "$TEST_CONTENT" | jq -r "$selector")
  if [ "$actual" == "$expected" ]; then
    printf "${RED}✗ CHECK${NC} ${BOLD}$selector${NC}\n\n\"${YELLOW}"; echo -n "$selector"; printf "${NC}\" = \"${YELLOW}"; echo -n "$expected"; printf "${NC}\"\n\n"
    ((++FAILED))
    return 1
  fi
  printf "${GREEN}✓ CHECK${NC} ${BOLD}$selector${NC}\n"
  return 0;
}

assert_exists() {
  check_name=$1;shift
  dir=$1;shift
  file=$1;shift
  if [ ! -e "$BASEDIR/$dir/$file" ]; then
    printf "${RED}✗ CHECK${NC} ${BOLD}$check_name${NC}\n\n\"${YELLOW}"; echo -n "$BASEDIR/$dir/$file"; printf "${NC}\" does not exist\n\n"
    ((++FAILED))
    return 1
  fi
  printf "${GREEN}✓ CHECK${NC} ${BOLD}$check_name${NC}\n"
  return 0;
}

assert_not_exists() {
  check_name=$1;shift
  dir=$1;shift
  file=$1;shift
  if [ -e "$BASEDIR/$dir/$file" ]; then
    printf "${RED}✗ CHECK${NC} ${BOLD}$check_name${NC}\n\n\"${YELLOW}"; echo -n "$BASEDIR/$dir/$file"; printf "${NC}\" exists\n\n"
    ((++FAILED))
    return 1
  fi
  printf "${GREEN}✓ CHECK${NC} ${BOLD}$check_name${NC}\n"
  return 0;
}

############
# Test Setup
############

TEST_CONTENT=
printf "Setting up test server on port $PORT...\n\n"

rm -rf "$BASEDIR/data"
mkdir -p "$BASEDIR/data/plans"
sqlite3 "$BASEDIR/data/test.db" < "$BASEDIR/../schema.sql"

# run the test server
if [ -z "$USE_DOCKER" ]; then
  PORT=$PORT \
  PID_FILE="$BASEDIR/data/test.pid" \
  LOG_FILE="$BASEDIR/data/test.log" \
  DATABASE="$BASEDIR/data/test.db" \
  PLAN_DIR="$BASEDIR/data/plans" \
  CACHE_DIR="$BASEDIR/data/cache" \
  perl "$BASEDIR/../server.pl" -d >>/dev/null
else
  docker build -t dotplan-online-test "$BASEDIR/.."
  docker run --name dotplan_online_test -d --rm \
    -v "$BASEDIR/data":"/opt/data" -p $PORT:$PORT \
    -e PORT=$PORT \
    -e PID_FILE="/opt/data/test.pid" \
    -e LOG_FILE="/opt/data/test.log" \
    -e DATABASE="/opt/data/test.db" \
    -e PLAN_DIR="/opt/data/plans" \
    -e CACHE_DIR="$BASEDIR/data/cache" \
    dotplan-online-test
fi

wait_file "$BASEDIR/data/test.pid" || {
  echo "Pid file didn't appear after $? seconds, bailing."
  exit 1
}

#######
# Tests
#######

REQ_DATA='{"password":"test1234"}'

curl_test 'Register a new user' 200 'application/json' -XPOST -d "$REQ_DATA" localhost:$PORT/users/$TEST_USER \
  && assert_equal_jq '.email' $TEST_USER

curl_test 'Rate limit registrations' 429 'application/json' -XPOST -d "$REQ_DATA" localhost:$PORT/users/$TEST_USER

pw_token=$(echo "select pw_token from users where email='$TEST_USER'" | sqlite3 "$BASEDIR/data/test.db")

curl_test 'Reject bad verification token' 401 'application/json' -XPUT -d "{\"token\":\"thisiswrong\"}" localhost:$PORT/users/$TEST_USER \
  && assert_notequal_jq '.success' 1

curl_test 'Reject bad verification email' 404 'application/json' -XPUT -d "{\"token\":\"$pw_token\"}" localhost:$PORT/users/testuser@exmapl3.com \
  && assert_notequal_jq '.success' 1

curl_test 'Verify email address' 200 'application/json' -XPUT -d "{\"token\":\"$pw_token\"}" localhost:$PORT/users/$TEST_USER \
  && assert_equal_jq '.success' 1

curl_test 'Reject incorrect email' 401 'application/json' -u testuser@exampl3.com:test1234 localhost:$PORT/token

curl_test 'Reject incorrect password' 401 'application/json' -u $TEST_USER:thisiswrong localhost:$PORT/token

curl_test 'Get authentication token' 200 'application/json' -u $TEST_USER:test1234 localhost:$PORT/token

token=$(echo "$TEST_CONTENT" | jq -r '.token')

curl_test 'No plan by default' 404 'text/plain' localhost:$PORT/plan/$TEST_USER

curl_test 'Reject bad authentication token' 401 'application/json' -XPUT -d '{"plan":"something","auth":"wrong"}' localhost:$PORT/plan/$TEST_USER

curl_test 'Create a plan' 200 'application/json' -XPUT -d "{\"plan\":\"something\",\"auth\":\"$token\"}" localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.success' 1

curl_test 'Get initial plan' 200 'application/json' -H 'Accept: application/json' localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.plan' 'something'

curl_test 'Bad accept type' 406 'application/json' -H 'Accept: text/html' localhost:$PORT/plan/$TEST_USER

curl_test 'Bad method' 405 'application/json' -XDELETE -H 'Accept: text/html' localhost:$PORT/plan/$TEST_USER

curl_test 'Create a plan' 200 'application/json' -XPUT -d "{\"plan\":\"some&thing\\nelse\",\"auth\":\"$token\"}" localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.success' 1

curl_test 'Get updated plan json' 200 'application/json' -H 'Accept: application/json' localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.plan' 'some&thing
else'

curl_test 'Get updated plan text' 200 'text/plain' localhost:$PORT/plan/$TEST_USER \
  && assert_equal 'text content' "$TEST_CONTENT" 'some&thing
else'

curl_test 'Delete a plan' 200 'application/json' -XPUT -d "{\"auth\":\"$token\"}" localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.success' 1

curl_test 'Verify deleted plan' 404 'text/plain' -H 'Accept: text/*' localhost:$PORT/plan/$TEST_USER

curl_test 'Create another plan for future tests' 200 'application/json' -XPUT -d "{\"plan\":\"for future tests\",\"auth\":\"$token\"}" localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.success' 1

curl_test 'Check missing plan in json' 404 'application/json' -H 'Accept: application/json' localhost:$PORT/plan/testuser@exampl3.com

curl_test 'Check missing plan in text' 404 'text/plain' -H 'Accept: text/*' localhost:$PORT/plan/testuser@exampl3.com

curl_test 'Delete authentication token' 200 'application/json' -u $TEST_USER:test1234 -XDELETE localhost:$PORT/token

curl_test 'Reject deleted authentication token' 401 'application/json' -XPUT -d "{\"plan\":\"this should fail\",\"auth\":\"$token\"}" localhost:$PORT/plan/$TEST_USER

curl_test 'Get new authentication token' 200 'application/json' -u $TEST_USER:test1234 localhost:$PORT/token

token=$(echo "$TEST_CONTENT" | jq -r '.token')

curl_test 'Accept new authentication token' 200 'application/json' -XPUT -d "{\"plan\":\"this should not fail\",\"auth\":\"$token\"}" localhost:$PORT/plan/$TEST_USER

curl_test 'Generate password reset token' 200 'application/json' localhost:$PORT/users/$TEST_USER/pwchange \
  && assert_equal_jq '.success' 1

pw_token=$(echo "select pw_token from users where email='$TEST_USER'" | sqlite3 "$BASEDIR/data/test.db")

curl_test 'Reject invalid password reset token' 400 'application/json' -XPUT -d "{\"password\":\"newpassword\",\"token\":\"thisiswrong\"}" localhost:$PORT/users/$TEST_USER/pwchange

curl_test 'Reset password' 200 'application/json' -XPUT -d "{\"password\":\"newpassword\",\"token\":\"$pw_token\"}" localhost:$PORT/users/$TEST_USER/pwchange \
  && assert_equal_jq '.success' 1

curl_test 'Reject authentication token after password reset' 401 'application/json' -XPUT -d "{\"plan\":\"this should fail\",\"auth\":\"$token\"}" localhost:$PORT/plan/$TEST_USER

curl_test 'Reject old password' 401 'application/json' -u $TEST_USER:test1234 localhost:$PORT/token

curl_test 'Get authentication token with new password' 200 'application/json' -u $TEST_USER:newpassword localhost:$PORT/token

token=$(echo "$TEST_CONTENT" | jq -r '.token')

export TEST_EXPORTED_TOKEN=$token
put_data=$(cat "$BASEDIR/signed-create.json" | envsubst)
curl_test 'Create signed plan' 200 'application/json' -XPUT -d "$put_data" localhost:$PORT/plan/$TEST_USER

curl_test 'Get signed plan' 200 'application/json' -H 'Accept: application/json' localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.plan' 'this is a plan
that is signed' \
  && assert_notequal_jq '.signature' 'null'

curl_test 'Fail to verify with bad pubkey' 403 'text/plain' -H 'Accept: text/*' -H 'X-Dotplan-Pubkey: RWSM/86eVMfThd89U/aVHVpFrXhTO7x2PXGVJ2mu1o3YLxVNKy+IKYPK' localhost:$PORT/plan/$TEST_USER

curl_test 'Verify signed plan' 200 'application/json' -H 'Accept: application/json' -H 'X-Dotplan-Pubkey: RWTbCoXPuccYts4F50FuQh3G/yIXAzINpW6Vk/X1AEgwwf3K5nNLHA8W' localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.plan' 'this is a plan
that is signed'

BADGUY='badguy@example.com%2F..%2Fgotya'
curl_test 'Avoid directory traversal 1 account creation' 404 'application/json' -XPOST -d '{"password":"test1234"}' localhost:$PORT/users/$BADGUY

BADGUY='badguy@example.com%252F..%252Fgotya'
BADGUY_ESC='badguy@example.com%2F..%2Fgotya'
curl_test 'Avoid directory traversal 2 account creation' 200 'application/json' -XPOST -d '{"password":"test1234"}' localhost:$PORT/users/$BADGUY \
  && assert_notequal_jq '.email' 'null'

pw_token=$(echo "select pw_token from users where email='$BADGUY_ESC'" | sqlite3 "$BASEDIR/data/test.db")

curl_test 'Verify directory traversal address 2' 200 'application/json' -XPUT -d "{\"token\":\"$pw_token\"}" localhost:$PORT/users/$BADGUY \
  && assert_equal_jq '.success' 1

curl_test 'Get directory traversal 2 authentication token' 200 'application/json' -u "$BADGUY_ESC:test1234" localhost:$PORT/token

token=$(echo "$TEST_CONTENT" | jq -r '.token')

curl_test 'Create directory traversal 2 plan' 200 'application/json' -XPUT -d "{\"plan\":\"something\",\"auth\":\"$token\"}" localhost:$PORT/plan/$BADGUY \
  && assert_equal_jq '.success' 1 \
  && assert_not_exists 'malicious file' 'data' 'gotya' \
  && assert_exists 'benign plan file' 'data/plans' "$BADGUY_ESC.plan"

BADGUY="badguy@example.com\\..\\gotya"
curl_test 'Avoid directory traversal 3 account creation' 200 'application/json' -XPOST -d '{"password":"test1234"}' localhost:$PORT/users/$BADGUY

pw_token=$(echo "select pw_token from users where email='$BADGUY'" | sqlite3 "$BASEDIR/data/test.db")

curl_test 'Verify directory traversal address 3' 200 'application/json' -XPUT -d "{\"token\":\"$pw_token\"}" localhost:$PORT/users/$BADGUY \
  && assert_equal_jq '.success' 1

curl_test 'Get directory traversal 3 authentication token' 200 'application/json' -u "$BADGUY:test1234" localhost:$PORT/token

token=$(echo "$TEST_CONTENT" | jq -r '.token')

curl_test 'Create directory traversal 3 plan' 200 'application/json' -XPUT -d "{\"plan\":\"something\",\"auth\":\"$token\"}" localhost:$PORT/plan/$BADGUY \
  && assert_equal_jq '.success' 1 \
  && assert_not_exists 'malicious file' 'data' 'gotya' \
  && assert_exists 'benign plan file' 'data/plans' "$BADGUY.plan"

BADGUY="badguy%40example.com%27%3Bdrop%20table%20users%3B"
BADGUY_ESC="badguy@example.com';drop table users;"
curl_test 'Avoid SQL injection account creation' 200 'application/json' -XPOST -d '{"password":"test1234"}' "localhost:$PORT/users/$BADGUY" \
  && assert_equal_jq '.email' "$BADGUY_ESC"

pw_token=$(echo "select pw_token from users where email='${BADGUY_ESC//\'/\'\'}'" | sqlite3 "$BASEDIR/data/test.db")

curl_test 'Verify SQL injection address' 200 'application/json' -XPUT -d "{\"token\":\"$pw_token\"}" localhost:$PORT/users/$BADGUY \
  && assert_equal_jq '.success' 1

curl_test 'Get SQL injection authentication token' 200 'application/json' -u "$BADGUY_ESC:test1234" localhost:$PORT/token

token=$(echo "$TEST_CONTENT" | jq -r '.token')

curl_test 'Create SQL injection plan' 200 'application/json' -XPUT -d "{\"plan\":\"something\",\"auth\":\"$token\"}" localhost:$PORT/plan/$BADGUY \
  && assert_equal_jq '.success' 1 \
  && assert_exists 'benign plan file' 'data/plans' "$BADGUY_ESC.plan"

now=`perl -e 'use HTTP::Date; print HTTP::Date::time2str(time)'`
curl_test 'If-Modified-Since header' 304 'text/plain' -H 'Accept: text/*' -H "If-Modified-Since: $now" localhost:$PORT/plan/$TEST_USER \
  && assert_equal 'Empty content' "$TEST_CONTENT" ""

curl_test 'Static index' 200 'text/html' localhost:$PORT/

###############
# Test Teardown
###############

printf "\nTearing down...\n"

if [ -z "$USE_DOCKER" ]; then
  if [ -f "$BASEDIR/data/test.pid" ]; then
    kill -9 `cat "$BASEDIR/data/test.pid"`
    rm "$BASEDIR/data/test.pid"
  fi
else
  docker exec dotplan_online_test rm /opt/data/test.pid
  docker kill dotplan_online_test
fi

if [ $FAILED -gt 0 ]; then
  printf "${RED}"
else
  printf "${GREEN}"
fi
printf "Tests complete. $FAILED failed.${NC}\n"
exit $FAILED
