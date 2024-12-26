#!/bin/bash

url="http://2million.htb/api/v1/invite/"
headers=(
  -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8"
  -H "X-Requested-With: XMLHttpRequest"
  -H "Accept: application/json, text/javascript, */*; q=0.01"
  -H "Referer: http://2million.htb/invite"
  -H "Origin: http://2million.htb"
  -H "Accept-Encoding: gzip, deflate"
  -H "Accept-Language: en-US,en;q=0.9"
)
while IFS= read -r param; do
  full_url="${url}${param}"
  response=$(curl -s -X POST "${headers[@]}" "$full_url" -d "code=$param")
  http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${headers[@]}" "$full_url" -d "code=$param")
  echo "Path: $param"
  echo "HTTP Code: $http_code"
  echo "Response:"
  
  if echo "$response" | jq . >/dev/null 2>&1; then
    echo "$response" | jq .
  else
    echo "$response"
  fi
  
  echo "-------------------------"
done < wordlist.txt

