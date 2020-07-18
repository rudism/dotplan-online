#!/usr/bin/env bash

BASEDIR=$(dirname "$0")
PORT=14227
TEST_USER=testuser@example.com

###################
# Utility Functions
###################

RED='\033[0;31m'
GREEN='\033[0;32m'
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
  printf -- "- ${BOLD}TEST $test_name:${NC} "
  if [ $exit_code -ne 0 ]; then
    printf "${RED}FAIL${NC} with exit code $exit_code\n"
    return 1
  fi
  stderr=$(<"$BASEDIR/data/err")
  response_code=$(echo $stderr | cut -f1 -d'|')
  content_type=$(echo $stderr | cut -f2 -d'|')
  if [ "$response_code" != "$expect_response_code" ]; then
    printf "${RED}FAIL${NC} with response code $response_code\n"
    return 1
  fi
  if [ "$content_type" != "$expect_content_type" ]; then
    printf "${RED}FAIL${NC} with content type $content_type\n"
    return 1
  fi
  printf "${GREEN}PASS${NC}\n"
  return 0
}

assert_equal() {
  check_name=$1;shift
  actual=$1;shift
  expected=$1;shift
  printf "  - ${BOLD}CHECK $check_name:${NC} "
  if [ "$actual" != "$expected" ]; then
    printf "${RED}FAIL${NC} \"$actual\" != \"$expected\"\n"
    return 1
  fi
  printf "${GREEN}PASS${NC}\n"
  return 0;
}

assert_equal_jq() {
  selector=$1;shift
  expected=$1;shift
  printf "  - ${BOLD}CHECK $selector:${NC} "
  actual=$(echo "$TEST_CONTENT" | jq -r "$selector")
  if [ "$actual" != "$expected" ]; then
    printf "${RED}FAIL${NC} \"$actual\" != \"$expected\"\n"
    return 1
  fi
  printf "${GREEN}PASS${NC}\n"
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
PORT=$PORT \
PID_FILE="$BASEDIR/data/test.pid" \
LOG_FILE="$BASEDIR/data/test.log" \
DATABASE="$BASEDIR/data/test.db" \
PLAN_DIR="$BASEDIR/data/plans" \
SENDMAIL=/usr/bin/true \
perl "$BASEDIR/../server.pl" -d >>/dev/null 2>>/dev/null

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

token=$(echo "select pw_token from users where email='$TEST_USER'" | sqlite3 "$BASEDIR/data/test.db")

curl_test 'Reject bad verification token' 400 'text/html' localhost:$PORT/users/$TEST_USER?token=thisiswrong

curl_test 'Reject bad verification email' 404 'text/html' localhost:$PORT/users/testuser@exmapl3.com?token=$token

curl_test 'Verify email address' 200 'text/html' localhost:$PORT/users/$TEST_USER?token=$token

curl_test 'Reject incorrect email' 401 'application/json' -u testuser@exampl3.com:test1234 localhost:$PORT/token

curl_test 'Reject incorrect password' 401 'application/json' -u $TEST_USER:thisiswrong localhost:$PORT/token

curl_test 'Get authentication token' 200 'application/json' -u $TEST_USER:test1234 localhost:$PORT/token

token=$(echo "$TEST_CONTENT" | jq -r '.token')

curl_test 'No plan by default' 404 'text/plain' localhost:$PORT/plan/$TEST_USER

curl_test 'Reject bad authentication token' 401 'application/json' -XPUT -d '{"plan":"something","auth":"wrong"}' localhost:$PORT/plan/$TEST_USER

curl_test 'Create a plan' 200 'application/json' -XPUT -d "{\"plan\":\"something\",\"auth\":\"$token\"}" localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.success' 1

curl_test 'Get initial plan' 200 'application/json' localhost:$PORT/plan/$TEST_USER?format=json \
  && assert_equal_jq '.plan' 'something'

curl_test 'Create a plan' 200 'application/json' -XPUT -d "{\"plan\":\"some&thing\\nelse\",\"auth\":\"$token\"}" localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.success' 1

curl_test 'Get updated plan json using accept' 200 'application/json' -H 'Accept: application/json' localhost:$PORT/plan/$TEST_USER \
  && assert_equal_jq '.plan' 'some&thing
else'

curl_test 'Get updated plan json using querystring' 200 'application/json' localhost:$PORT/plan/$TEST_USER?format=json \
  && assert_equal_jq '.plan' 'some&thing
else'

curl_test 'Get updated plan html using accept' 200 'text/html' -H 'Accept: text/html' localhost:$PORT/plan/$TEST_USER \
  && assert_equal 'html content' "$TEST_CONTENT" 'some&amp;thing<br>
else'

curl_test 'Get updated plan html using querystring' 200 'text/html' localhost:$PORT/plan/$TEST_USER?format=html \
  && assert_equal 'html content' "$TEST_CONTENT" 'some&amp;thing<br>
else'

curl_test 'Get updated plan text' 200 'text/plain' localhost:$PORT/plan/$TEST_USER \
  && assert_equal 'text content' "$TEST_CONTENT" 'some&thing
else'

curl_test 'Check missing plan in json using accept' 404 'application/json' -H 'Accept: application/json' localhost:$PORT/plan/testuser@exampl3.com

curl_test 'Check missing plan in json using querystring' 404 'application/json' localhost:$PORT/plan/testuser@exampl3.com?format=json

curl_test 'Check missing plan in html using accept' 404 'text/html' -H 'Accept: text/html' localhost:$PORT/plan/testuser@exampl3.com

curl_test 'Check missing plan in html using querystring' 404 'text/html' localhost:$PORT/plan/testuser@exampl3.com?format=html

curl_test 'Check missing plan in text by omitting accept' 404 'text/plain' localhost:$PORT/plan/testuser@exampl3.com

###############
# Test Teardown
###############

printf "\nTearing down...\n"

if [ -f "$BASEDIR/data/test.pid" ]; then
  kill -9 `cat "$BASEDIR/data/test.pid"`
  rm "$BASEDIR/data/test.pid"
fi

printf "Tests complete.\n"