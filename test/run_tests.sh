#!/usr/bin/env bash
# =============================================================================
# run_tests.sh — ckb-light-esp host test runner
#
# Builds and runs all host test suites, then prints a formatted report.
# Optionally saves a markdown report to test/REPORT.md.
#
# Usage:
#   bash test/run_tests.sh            # run all, print report
#   bash test/run_tests.sh --md       # also save test/REPORT.md
#   bash test/run_tests.sh --verbose  # show full output of each suite
# =============================================================================

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$REPO_ROOT/test"
CKBESP="$REPO_ROOT/../CKB-ESP32/src"
REPORT_MD="$TEST_DIR/REPORT.md"

BASE_FLAGS="-DHOST_TEST -std=c++17 \
  -I$REPO_ROOT \
  -I$REPO_ROOT/src \
  -I$REPO_ROOT/src/core \
  -I$REPO_ROOT/src/transport \
  -I$REPO_ROOT/src/vm \
  -I$TEST_DIR \
  -I$CKBESP \
  -Wno-unused-function -Wno-unused-variable"

# ── Colours ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  R='\033[0m'; BOLD='\033[1m'; GRN='\033[0;32m'; RED='\033[0;31m'
  YEL='\033[0;33m'; CYN='\033[0;36m'; DIM='\033[2m'
else
  R=''; BOLD=''; GRN=''; RED=''; YEL=''; CYN=''; DIM=''
fi

# ── CLI flags ─────────────────────────────────────────────────────────────────
OPT_MD=0; OPT_VERBOSE=0
for arg in "$@"; do
  case "$arg" in --md) OPT_MD=1;; --verbose) OPT_VERBOSE=1;; esac
done

# ── Suite definitions: "name|bin|build_command" ───────────────────────────────
# %B% = BASE_FLAGS, %T% = TEST_DIR, %S% = SRC (REPO_ROOT/src)
SUITES=(
  "header_chain|test/test_headers|g++ %B% %T%/test_header_chain.cpp src/core/eaglesong.cpp src/core/header_chain.cpp -o %T%/test_headers"
  "merkle|test/test_merkle|g++ %B% %T%/test_merkle.cpp src/core/merkle.cpp -o %T%/test_merkle"
  "block_filter|test/test_bf|g++ %B% %T%/test_block_filter.cpp src/core/block_filter.cpp -o %T%/test_bf"
  "wifi_transport|test/test_wifi_transport|g++ %B% %T%/test_wifi_transport.cpp -o %T%/test_wifi_transport"
  "light_client|test/test_lc|g++ %B% %T%/test_light_client.cpp -o %T%/test_lc"
  "helpers|test/test_helpers|g++ %B% %T%/test_helpers.cpp -o %T%/test_helpers"
  "native_locks|test/test_nl|g++ %B% %T%/test_native_locks.cpp src/vm/native_locks.cpp -lsecp256k1 -o %T%/test_nl"
  "ckbvm_interp|test/test_vm|g++ %B% -DLIGHT_WITH_VM %T%/test_ckbvm_interp.cpp src/vm/ckbvm_interp.cpp -o %T%/test_vm"
  "lora_transport|test/test_lora|g++ %B% %T%/test_lora_transport.cpp src/transport/lora_transport.cpp -o %T%/test_lora"
  "bitchat|test/test_bitchat|g++ %B% -Isrc/bitchat %T%/test_bitchat.cpp -o %T%/test_bitchat"
  "noise|test/test_noise_bin|gcc -DHOST_TEST -w -c -I/home/phill/workspace/CKB-ESP32/src/trezor_crypto /home/phill/workspace/CKB-ESP32/src/trezor_crypto/memzero.c -o /tmp/nz_memzero.o && gcc -DHOST_TEST -w -c -I/home/phill/workspace/CKB-ESP32/src/trezor_crypto /home/phill/workspace/CKB-ESP32/src/trezor_crypto/sha3.c -o /tmp/nz_sha3.o && gcc -DHOST_TEST -w -c -I/home/phill/workspace/CKB-ESP32/src/trezor_crypto /home/phill/workspace/CKB-ESP32/src/trezor_crypto/sha2.c -o /tmp/nz_sha2.o && gcc -DHOST_TEST -w -c -I/home/phill/workspace/CKB-ESP32/src/chacha20poly1305 /home/phill/workspace/CKB-ESP32/src/chacha20poly1305/poly1305-donna.c -o /tmp/nz_poly.o && gcc -DHOST_TEST -w -c -I/home/phill/workspace/CKB-ESP32/src/chacha20poly1305 /home/phill/workspace/CKB-ESP32/src/chacha20poly1305/chacha_merged.c -o /tmp/nz_chacha.o && gcc -DHOST_TEST -w -c -I/home/phill/workspace/CKB-ESP32/src/chacha20poly1305 /home/phill/workspace/CKB-ESP32/src/chacha20poly1305/chacha20poly1305.c -o /tmp/nz_c20p.o && gcc -DHOST_TEST -w -c -I/home/phill/workspace/CKB-ESP32/src/chacha20poly1305 -I/home/phill/workspace/CKB-ESP32/src/trezor_crypto /home/phill/workspace/CKB-ESP32/src/chacha20poly1305/rfc7539.c -o /tmp/nz_rfc7539.o && g++ %B% -Isrc/bitchat -I/home/phill/workspace/CKB-ESP32/src -I/home/phill/workspace/CKB-ESP32/src/trezor_crypto -I/home/phill/workspace/CKB-ESP32/src/chacha20poly1305 -I/home/phill/workspace/CKB-ESP32/src/curve25519 %T%/test_bitchat_noise.cpp /tmp/nz_memzero.o /tmp/nz_sha3.o /tmp/nz_sha2.o /tmp/nz_poly.o /tmp/nz_chacha.o /tmp/nz_c20p.o /tmp/nz_rfc7539.o -lsodium -o %T%/test_noise_bin"
)

elapsed_ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }

# ── Result arrays ─────────────────────────────────────────────────────────────
RES_NAMES=(); RES_PASS=(); RES_FAIL=()
RES_BUILD=(); RES_TIME=(); RES_OUTPUT=()
GRAND_PASS=0; GRAND_FAIL=0; GRAND_BUILD_ERR=0
SUITE_START=$(date +%s%N)

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
printf "${BOLD}${CYN}╔══════════════════════════════════════════════════════════════╗${R}\n"
printf "${BOLD}${CYN}║        ckb-light-esp  ·  Host Test Suite Runner             ║${R}\n"
printf "${BOLD}${CYN}╚══════════════════════════════════════════════════════════════╝${R}\n"
printf "  ${DIM}%s  ·  %s  ·  g++ %s${R}\n" \
  "$(date '+%Y-%m-%d %H:%M:%S')" \
  "$(uname -m)" \
  "$(g++ --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
echo ""

# ── Run each suite ────────────────────────────────────────────────────────────
for suite_def in "${SUITES[@]}"; do
  IFS='|' read -r sname sbin sbuild <<< "$suite_def"

  sbuild="${sbuild//%B%/$BASE_FLAGS}"
  sbuild="${sbuild//%T%/test}"
  sbuild="${sbuild//%S%/src}"

  printf "  ${BOLD}%-18s${R}" "$sname"
  t_start=$(date +%s%N)

  # Build
  build_out=$(cd "$REPO_ROOT" && eval "$sbuild" 2>&1) || true
  build_errs=$(echo "$build_out" | grep -E ": error:" 2>/dev/null | wc -l || echo 0)

  if [ "${build_errs:-0}" -gt 0 ]; then
    t_ms=$(elapsed_ms $t_start)
    printf "${RED}BUILD FAILED${R}  ${DIM}(%sms)${R}\n" "$t_ms"
    [ "$OPT_VERBOSE" -eq 1 ] && echo "$build_out" | grep "error:" | sed 's/^/      /'
    RES_NAMES+=("$sname"); RES_PASS+=(0); RES_FAIL+=(0)
    RES_BUILD+=("FAIL"); RES_TIME+=("${t_ms}ms"); RES_OUTPUT+=("BUILD: $build_out")
    GRAND_BUILD_ERR=$((GRAND_BUILD_ERR+1))
    continue
  fi

  # Run
  run_out=$(cd "$REPO_ROOT" && eval "./$sbin" 2>&1) || true
  t_ms=$(elapsed_ms $t_start)

  passed=$(echo "$run_out" | grep -oP '\d+(?= passed)' | awk '{s+=$1}END{print s+0}')
  failed=$(echo "$run_out" | grep -oP '\d+(?= failed)' | awk '{s+=$1}END{print s+0}')
  passed=${passed:-0}; failed=${failed:-0}

  RES_NAMES+=("$sname"); RES_PASS+=("$passed"); RES_FAIL+=("$failed")
  RES_BUILD+=("ok"); RES_TIME+=("${t_ms}ms"); RES_OUTPUT+=("$run_out")
  GRAND_PASS=$((GRAND_PASS+passed)); GRAND_FAIL=$((GRAND_FAIL+failed))

  if [ "$failed" -gt 0 ]; then
    printf "${RED}✗ FAIL${R}  ${RED}%dp${R} / ${RED}%df${R}  ${DIM}(%sms)${R}\n" "$passed" "$failed" "$t_ms"
    echo "$run_out" | grep "^FAIL:" | sed "s/^/    /"
  else
    printf "${GRN}✓ pass${R}  ${GRN}%d tests${R}  ${DIM}(%sms)${R}\n" "$passed" "$t_ms"
  fi

  [ "$OPT_VERBOSE" -eq 1 ] && echo "$run_out" | sed 's/^/    /' && echo ""
done

TOTAL_MS=$(elapsed_ms $SUITE_START)

# ── Summary table ─────────────────────────────────────────────────────────────
echo ""
printf "${BOLD}${CYN}┌────────────────────────┬──────────┬─────────┬──────────┬────────────┐${R}\n"
printf "${BOLD}${CYN}│${R} ${BOLD}%-22s${R} ${BOLD}${CYN}│${R} ${BOLD}%-8s${R} ${BOLD}${CYN}│${R} ${BOLD}%-7s${R} ${BOLD}${CYN}│${R} ${BOLD}%-8s${R} ${BOLD}${CYN}│${R} ${BOLD}%-10s${R} ${BOLD}${CYN}│${R}\n" \
  " Suite" "Passed" "Failed" " Time" " Status"
printf "${BOLD}${CYN}├────────────────────────┼──────────┼─────────┼──────────┼────────────┤${R}\n"

for i in "${!RES_NAMES[@]}"; do
  nm="${RES_NAMES[$i]}"; p="${RES_PASS[$i]}"; f="${RES_FAIL[$i]}"
  t="${RES_TIME[$i]}"; b="${RES_BUILD[$i]}"
  if [ "$b" != "ok" ]; then
    pc="$RED"; fc="$RED"; st="${RED}✗ build${R}"
  elif [ "$f" -gt 0 ]; then
    pc="$YEL"; fc="$RED"; st="${RED}✗ fail${R}"
  else
    pc="$GRN"; fc="$DIM"; st="${GRN}✓ ok${R}"
  fi
  printf "${BOLD}${CYN}│${R} %-22s ${BOLD}${CYN}│${R} ${pc}%-8s${R} ${BOLD}${CYN}│${R} ${fc}%-7s${R} ${BOLD}${CYN}│${R} ${DIM}%-8s${R} ${BOLD}${CYN}│${R} %-10b ${BOLD}${CYN}│${R}\n" \
    " $nm" "$p" "$f" " $t" "$st"
done

printf "${BOLD}${CYN}├────────────────────────┼──────────┼─────────┼──────────┼────────────┤${R}\n"

if [ "$GRAND_FAIL" -eq 0 ] && [ "$GRAND_BUILD_ERR" -eq 0 ]; then
  RES_STR="${GRN}${BOLD}✓ ALL PASS${R}"
else
  RES_STR="${RED}${BOLD}✗ FAILING${R}"
fi
printf "${BOLD}${CYN}│${R} %-22s ${BOLD}${CYN}│${R} ${GRN}${BOLD}%-8s${R} ${BOLD}${CYN}│${R} ${RED}%-7s${R} ${BOLD}${CYN}│${R} ${DIM}%-8s${R} ${BOLD}${CYN}│${R} %-10b ${BOLD}${CYN}│${R}\n" \
  " TOTAL" "$GRAND_PASS" "$GRAND_FAIL" " ${TOTAL_MS}ms" "$RES_STR"
printf "${BOLD}${CYN}└────────────────────────┴──────────┴─────────┴──────────┴────────────┘${R}\n"
echo ""

# ── Function breakdown ────────────────────────────────────────────────────────
echo -e "${BOLD}  Test cases by suite:${R}"
for i in "${!RES_NAMES[@]}"; do
  nm="${RES_NAMES[$i]}"; out="${RES_OUTPUT[$i]}"
  [ "${RES_BUILD[$i]}" != "ok" ] && continue

  # Extract unique test names from PASS: lines — take the text after ": "
  funcs=$(echo "$out" | grep -E "^\s*PASS:" | sed 's/^[[:space:]]*PASS: //' | sed 's/ (.*//' | sed 's/:.*//' | sort -u)
  count=$(printf "%s" "$funcs" | grep -c "." 2>/dev/null || echo 0); count=${count:-0}
  [ "${count:-0}" -eq 0 ] 2>/dev/null && continue || true; [ "${count:-0}" = "0" ] && continue

  printf "  ${CYN}${BOLD}%-20s${R} ${DIM}%d cases${R}\n" "$nm" "$count"
  echo "$funcs" | head -10 | sed "s/^/    ${DIM}·${R} /"
  [ "$count" -gt 10 ] && printf "    ${DIM}  … %d more${R}\n" "$((count-10))"
done
echo ""

# ── Markdown report ───────────────────────────────────────────────────────────
if [ "$OPT_MD" -eq 1 ]; then
  GIT_SHA=$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
  {
    echo "# ckb-light-esp — Test Report"
    echo ""
    echo "| | |"
    echo "|---|---|"
    echo "| **Generated** | $(date '+%Y-%m-%d %H:%M:%S') |"
    echo "| **Platform** | \`$(uname -srm)\` |"
    echo "| **Compiler** | \`$(g++ --version 2>&1 | head -1)\` |"
    echo "| **Commit** | \`$GIT_SHA\` |"
    echo "| **Total time** | ${TOTAL_MS}ms |"
    echo ""
    echo "## Summary"
    echo ""

    if [ "$GRAND_FAIL" -eq 0 ] && [ "$GRAND_BUILD_ERR" -eq 0 ]; then
      echo "✅ **All ${GRAND_PASS} tests passing**"
    else
      echo "❌ **${GRAND_FAIL} failing, ${GRAND_BUILD_ERR} build errors**"
    fi
    echo ""
    echo "| Suite | Passed | Failed | Time | Status |"
    echo "|---|---:|---:|---:|---|"

    for i in "${!RES_NAMES[@]}"; do
      nm="${RES_NAMES[$i]}"; p="${RES_PASS[$i]}"; f="${RES_FAIL[$i]}"
      t="${RES_TIME[$i]}"; b="${RES_BUILD[$i]}"
      if [ "$b" != "ok" ]; then st="🔴 build error"
      elif [ "$f" -gt 0 ];  then st="🔴 $f failing"
      else                       st="🟢 pass"
      fi
      echo "| \`$nm\` | $p | $f | $t | $st |"
    done
    echo "| **TOTAL** | **$GRAND_PASS** | **$GRAND_FAIL** | **${TOTAL_MS}ms** | $([ "$GRAND_FAIL" -eq 0 ] && [ "$GRAND_BUILD_ERR" -eq 0 ] && echo "✅ **ALL PASS**" || echo "❌ **FAILING**") |"
    echo ""
    echo "## Per-Suite Details"
    echo ""

    for i in "${!RES_NAMES[@]}"; do
      nm="${RES_NAMES[$i]}"; p="${RES_PASS[$i]}"; f="${RES_FAIL[$i]}"
      t="${RES_TIME[$i]}"; b="${RES_BUILD[$i]}"; out="${RES_OUTPUT[$i]}"

      echo "### \`$nm\`"
      echo ""
      if [ "$b" != "ok" ]; then
        echo "**Build failed.**"
        echo ""
        echo '```'
        echo "$out" | grep "error:" | head -5
        echo '```'
        echo ""
        continue
      fi

      echo "**${p} passed · ${f} failed · ${t}**"
      echo ""

      # Sections from output
      sects=$(echo "$out" | grep -E '^\s*\[.*\]|--- .* ---' | sed 's/^[[:space:]]*//' | sed 's/--- //; s/ ---//' | head -12)
      if [ -n "$sects" ]; then
        echo "**Sections:**"
        echo "$sects" | sed 's/^/- /'
        echo ""
      fi

      # Failures
      fails=$(echo "$out" | grep "^FAIL:")
      if [ -n "$fails" ]; then
        echo "**Failures:**"
        echo '```'
        echo "$fails"
        echo '```'
        echo ""
      fi

      # All test cases
      funcs=$(echo "$out" | grep -E "^\s*PASS:" | sed 's/^[[:space:]]*PASS: //' | sort -u)
      fc=$(echo "$funcs" | grep -c "." 2>/dev/null | tr -d "\n" || echo 0); fc=${fc:-0}
      if [ "$fc" -gt 0 ]; then
        echo "<details>"
        echo "<summary>Test cases (${fc})</summary>"
        echo ""
        echo "$funcs" | sed 's/^/- /'
        echo ""
        echo "</details>"
        echo ""
      fi
    done

    echo "---"
    echo "*Generated by \`test/run_tests.sh --md\`*"
  } > "$REPORT_MD"
  printf "  ${DIM}Markdown report → %s${R}\n\n" "$REPORT_MD"
fi

[ "$GRAND_FAIL" -eq 0 ] && [ "$GRAND_BUILD_ERR" -eq 0 ] && exit 0 || exit 1
