#!/bin/sh
set -eu

while IFS= read -r request; do
  case "${request}" in
    *'"method":"initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"server":"codex-app-server"}}'
      ;;
    *'"method":"initialized"'*)
      ;;
    *'"method":"thread/start"'*)
      case "${request}" in
        *'"dynamicTools"'*'"get_me"'*'"issue_read"'*'"list_issues"'*'"search_issues"'*'"search_orgs"'*) ;;
        *) exit 70 ;;
      esac
      case "${request}" in
        *'"shell_tool":false'*'"unified_exec":false'*) ;;
        *) exit 70 ;;
      esac
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}'
      ;;
    *'"method":"turn/start"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":5,"result":{"turn":{"id":"turn-1"}}}'
      printf '%s\n' '{"jsonrpc":"2.0","id":"dynamic-1","method":"item/tool/call","params":{"threadId":"thread-1","turnId":"turn-1","tool":"issue_read","arguments":{"owner":"helixbox","repo":"codeoff","issue_number":1}}}'
      ;;
    *'"id":"dynamic-1"'*'"success":true'*)
      printf '%s\n' '{"jsonrpc":"2.0","method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","item":{"type":"agentMessage","phase":"final_answer","text":"{\"schema_version\":1,\"summary\":\"process dynamic tool completed\"}"}}}'
      printf '%s\n' '{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","usage":{"inputTokens":1,"outputTokens":1},"items":[{"type":"agentMessage","phase":"final_answer","text":"{\"schema_version\":1,\"summary\":\"process dynamic tool completed\"}"}]}}}'
      exit 0
      ;;
    *)
      exit 71
      ;;
  esac
done
