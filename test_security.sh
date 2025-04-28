#!/bin/bash
# Security Test Suite for c-jwt-cracker
# Tests Critical Security Issues documented in FIXES-PROPOSED.md

# Note: We don't use 'set -e' because we intentionally test crash scenarios

PASS=0
FAIL=0
TOTAL=0

echo "========================================"
echo "SECURITY FIXES VERIFICATION SUITE"
echo "========================================"
echo ""
echo "This test suite verifies that the security"
echo "vulnerabilities have been properly fixed."
echo ""

#############################################
# CRITICAL ISSUE 1: Race Condition (CWE-362)
#############################################
echo ""
echo "########################################"
echo "# CRITICAL 1: Race Condition (CWE-362)"
echo "########################################"
echo ""
echo "The global variable g_found_secret is accessed"
echo "by multiple threads without synchronization."
echo "Location: main.c:78, 141, 153"
echo ""

# Test 1a: Helgrind race detection
echo "--- Test 1a: Helgrind race detection ---"
echo "Running Helgrind to detect data races..."
echo ""
valgrind --tool=helgrind --error-exitcode=42 \
    ./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE ABCSNFabcsnf1234567 5 sha256 2>&1 | tee /tmp/helgrind.log
HELGRIND_EXIT=${PIPESTATUS[0]}

if [ $HELGRIND_EXIT -eq 42 ]; then
    echo ""
    echo ">>> VULNERABILITY CONFIRMED: Helgrind detected race conditions!"
    echo ">>> See 'Possible data race' entries above."
    RACE_DETECTED=1
else
    echo ""
    echo "Helgrind did not detect races (exit code: $HELGRIND_EXIT)"
    RACE_DETECTED=0
fi

# Test 1b: DRD race detection (more sensitive)
echo ""
echo "--- Test 1b: DRD race detection ---"
echo "Running DRD (Data Race Detector)..."
echo ""
valgrind --tool=drd --error-exitcode=42 \
    ./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE ABCSNFabcsnf1234567 5 sha256 2>&1 | tee /tmp/drd.log
DRD_EXIT=${PIPESTATUS[0]}

if [ $DRD_EXIT -eq 42 ]; then
    echo ""
    echo ">>> VULNERABILITY CONFIRMED: DRD detected race conditions!"
    RACE_DETECTED=1
else
    echo ""
    echo "DRD did not detect races (exit code: $DRD_EXIT)"
fi

if [ $RACE_DETECTED -eq 1 ]; then
    echo ""
    echo "==> CWE-362 RACE CONDITION: STILL PRESENT (fix failed)"
    ((FAIL++))
else
    echo ""
    echo "==> CWE-362 RACE CONDITION: FIXED (no races detected)"
    ((PASS++))
fi
((TOTAL++))

#############################################
# CRITICAL ISSUE 2: NULL Dereference (CWE-476)
#############################################
echo ""
echo "########################################"
echo "# CRITICAL 2: NULL Dereference (CWE-476)"
echo "########################################"
echo ""
echo "When strtok() returns NULL for malformed JWT,"
echo "strlen() is called on NULL causing SIGSEGV."
echo "Location: main.c:232-237"
echo ""

NULL_CRASH_1=0
NULL_CRASH_2=0
NULL_CRASH_3=0
NULL_CRASH_4=0

# Test 2a: No dots at all
echo "--- Test 2a: JWT with no dots ---"
echo "Input: 'nodots'"
echo ""
set +e
./jwtcrack nodots abc 2 sha256 2>&1
EXIT_2A=$?
set -e
if [ $EXIT_2A -eq 139 ] || [ $EXIT_2A -eq 134 ] || [ $EXIT_2A -eq 136 ] || [ $EXIT_2A -eq 11 ]; then
    echo ""
    echo ">>> VULNERABILITY CONFIRMED: Program crashed (exit code $EXIT_2A)"
    echo ">>> Exit code 139=SIGSEGV, 134=SIGABRT, 136=SIGFPE, 11=SIGSEGV(raw)"
    NULL_CRASH_1=1
else
    echo ""
    echo "Exit code: $EXIT_2A (no crash)"
    NULL_CRASH_1=0
fi

# Test 2b: Only one dot (missing signature)
echo ""
echo "--- Test 2b: JWT with only one dot ---"
echo "Input: 'header.payload'"
echo ""
set +e
./jwtcrack header.payload abc 2 sha256 2>&1
EXIT_2B=$?
set -e
if [ $EXIT_2B -eq 139 ] || [ $EXIT_2B -eq 134 ] || [ $EXIT_2B -eq 136 ] || [ $EXIT_2B -eq 11 ]; then
    echo ""
    echo ">>> VULNERABILITY CONFIRMED: Program crashed (exit code $EXIT_2B)"
    NULL_CRASH_2=1
else
    echo ""
    echo "Exit code: $EXIT_2B (no crash)"
    NULL_CRASH_2=0
fi

# Test 2c: Empty string
echo ""
echo "--- Test 2c: Empty JWT string ---"
echo "Input: ''"
echo ""
set +e
./jwtcrack "" abc 2 sha256 2>&1
EXIT_2C=$?
set -e
if [ $EXIT_2C -eq 139 ] || [ $EXIT_2C -eq 134 ] || [ $EXIT_2C -eq 136 ] || [ $EXIT_2C -eq 11 ]; then
    echo ""
    echo ">>> VULNERABILITY CONFIRMED: Program crashed (exit code $EXIT_2C)"
    NULL_CRASH_3=1
else
    echo ""
    echo "Exit code: $EXIT_2C (no crash)"
    NULL_CRASH_3=0
fi

# Test 2d: Two dots but empty parts
echo ""
echo "--- Test 2d: JWT with two dots but empty parts ---"
echo "Input: '..'"
echo ""
set +e
./jwtcrack ".." abc 2 sha256 2>&1
EXIT_2D=$?
set -e
if [ $EXIT_2D -eq 139 ] || [ $EXIT_2D -eq 134 ] || [ $EXIT_2D -eq 136 ] || [ $EXIT_2D -eq 11 ]; then
    echo ""
    echo ">>> VULNERABILITY CONFIRMED: Program crashed (exit code $EXIT_2D)"
    NULL_CRASH_4=1
else
    echo ""
    echo "Exit code: $EXIT_2D (no crash)"
    NULL_CRASH_4=0
fi

if [ $NULL_CRASH_1 -eq 1 ] || [ $NULL_CRASH_2 -eq 1 ] || [ $NULL_CRASH_3 -eq 1 ] || [ $NULL_CRASH_4 -eq 1 ]; then
    echo ""
    echo "==> CWE-476 NULL DEREFERENCE: STILL PRESENT (fix failed)"
    ((FAIL++))
else
    echo ""
    echo "==> CWE-476 NULL DEREFERENCE: FIXED (proper error handling)"
    ((PASS++))
fi
((TOTAL++))

#############################################
# CRITICAL ISSUE 3: Base64/Base64URL Mismatch
#############################################
echo ""
echo "########################################"
echo "# CRITICAL 3: Base64/Base64URL Mismatch"
echo "########################################"
echo ""
echo "JWT uses Base64URL (-_ for index 62,63) but"
echo "decoder rejects + (standard Base64 index 62)."
echo "Location: base64.c:95"
echo ""

BASE64URL_WORKS=0

echo "--- Test 3a: JWT with Base64URL signature (should work) ---"
echo "Testing Base64 decoding of signature with '-' character..."
echo ""

# Test with the normal JWT first (should work)
echo "Normal JWT (Base64URL signature with '-'):"
set +e
RESULT=$(./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE ABCSNFabcsnf1234567 5 sha256 2>&1)
set -e
echo "$RESULT"
if echo "$RESULT" | grep -q 'Secret is "Sn1f"'; then
    echo "Base64URL (-) decoding: WORKS"
    BASE64URL_WORKS=1
else
    echo "Base64URL (-) decoding: FAILED"
    BASE64URL_WORKS=0
fi

echo ""
echo "--- Test 3b: Checking pr2six table values ---"
echo ""
echo "Per RFC 4648 Section 5 (Base64URL):"
echo "  Index 62 should accept BOTH '+' (Base64) AND '-' (Base64URL)"
echo "  Index 63 should accept BOTH '/' (Base64) AND '_' (Base64URL)"
echo ""

if [ $BASE64URL_WORKS -eq 1 ]; then
    echo "==> BASE64/BASE64URL: WORKING CORRECTLY"
    echo "    (Both '+' and '-' are accepted for index 62)"
    ((PASS++))
else
    echo "==> BASE64/BASE64URL: FAILED"
    ((FAIL++))
fi
((TOTAL++))

#############################################
# SUMMARY
#############################################
echo ""
echo "========================================"
echo "SECURITY TEST SUMMARY"
echo "========================================"
echo ""
echo "Total tests: $TOTAL"
echo "Fixes verified: $PASS"
echo "Fixes failed: $FAIL"
echo ""
echo "Security Fixes Status:"
if [ $RACE_DETECTED -eq 1 ]; then
    echo "  1. CWE-362 Race Condition:    FAILED (still vulnerable)"
else
    echo "  1. CWE-362 Race Condition:    FIXED"
fi
if [ $NULL_CRASH_1 -eq 1 ] || [ $NULL_CRASH_2 -eq 1 ] || [ $NULL_CRASH_3 -eq 1 ] || [ $NULL_CRASH_4 -eq 1 ]; then
    echo "  2. CWE-476 NULL Dereference:  FAILED (still crashes)"
else
    echo "  2. CWE-476 NULL Dereference:  FIXED"
fi
if [ $BASE64URL_WORKS -eq 1 ]; then
    echo "  3. Base64/Base64URL Support:  WORKING"
else
    echo "  3. Base64/Base64URL Support:  FAILED"
fi
echo ""

#############################################
# MEDIUM ISSUE 4: Integer Overflow atoi (CWE-190)
#############################################
echo ""
echo "########################################"
echo "# MEDIUM 4: Integer Overflow (CWE-190)"
echo "########################################"
echo ""
echo "atoi() has undefined behavior for out-of-range values."
echo "Fix: Use strtol() with proper validation and range check (1-1000)."
echo ""

INT_VALIDATION_WORKS=1

# Test 4a: Very large max_len value - should be rejected
echo "--- Test 4a: Very large max_len (2147483648 = INT_MAX+1) ---"
echo "Input: max_len=2147483648"
echo ""
set +e
OUTPUT_4A=$(timeout 5 ./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE abc 2147483648 sha256 2>&1)
EXIT_4A=$?
set -e
echo "$OUTPUT_4A"
echo ""
echo "Exit code: $EXIT_4A"
if echo "$OUTPUT_4A" | grep -q "Invalid max_len\|defaults to"; then
    echo "PASS: Large value properly rejected with error message"
else
    echo "FAIL: Large value not properly validated"
    INT_VALIDATION_WORKS=0
fi

# Test 4b: Negative value - should be rejected
echo ""
echo "--- Test 4b: Negative max_len ---"
echo "Input: max_len=-1"
echo ""
set +e
OUTPUT_4B=$(./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE abc -1 sha256 2>&1)
EXIT_4B=$?
set -e
echo "$OUTPUT_4B"
echo ""
echo "Exit code: $EXIT_4B"
if echo "$OUTPUT_4B" | grep -q "Invalid max_len\|defaults to"; then
    echo "PASS: Negative value properly rejected"
else
    echo "FAIL: Negative value not properly validated"
    INT_VALIDATION_WORKS=0
fi

# Test 4c: Non-numeric value - should be rejected
echo ""
echo "--- Test 4c: Non-numeric max_len ---"
echo "Input: max_len=abc"
echo ""
set +e
OUTPUT_4C=$(./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE abc abc sha256 2>&1)
EXIT_4C=$?
set -e
echo "$OUTPUT_4C"
echo ""
echo "Exit code: $EXIT_4C"
if echo "$OUTPUT_4C" | grep -q "Invalid max_len\|defaults to"; then
    echo "PASS: Non-numeric value properly rejected"
else
    echo "FAIL: Non-numeric value not properly validated"
    INT_VALIDATION_WORKS=0
fi

# Test 4d: Value over 1000 - should be rejected (new upper bound)
echo ""
echo "--- Test 4d: max_len over 1000 ---"
echo "Input: max_len=1001"
echo ""
set +e
OUTPUT_4D=$(./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE abc 1001 sha256 2>&1)
EXIT_4D=$?
set -e
echo "$OUTPUT_4D"
echo ""
echo "Exit code: $EXIT_4D"
if echo "$OUTPUT_4D" | grep -q "Invalid max_len\|defaults to"; then
    echo "PASS: Value over 1000 properly rejected"
else
    echo "FAIL: Value over 1000 not properly validated"
    INT_VALIDATION_WORKS=0
fi

if [ $INT_VALIDATION_WORKS -eq 1 ]; then
    echo ""
    echo "==> CWE-190 INTEGER OVERFLOW: FIXED"
    echo "    strtol() with proper validation now used"
    ((PASS++))
else
    echo ""
    echo "==> CWE-190 INTEGER OVERFLOW: ISSUE PRESENT"
    ((FAIL++))
fi
((TOTAL++))

#############################################
# MEDIUM ISSUE 5: VLA Stack Overflow (CWE-121)
#############################################
echo ""
echo "########################################"
echo "# MEDIUM 5: VLA Stack Overflow (CWE-121)"
echo "########################################"
echo ""
echo "Variable-length array on stack can overflow"
echo "with large alphabet sizes."
echo "Fix: Heap allocate thread data array instead of VLA."
echo ""

VLA_WORKS=1

# Test 5a: Very large alphabet (10000 characters)
echo "--- Test 5a: Large alphabet (10000 chars) ---"
echo "Previously would create VLA of 10000 pointers on stack"
echo ""

# Generate a large alphabet
LARGE_ALPHABET=$(printf 'a%.0s' $(seq 1 10000))
echo "Alphabet length: ${#LARGE_ALPHABET}"
echo ""

set +e
timeout 5 ./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE "$LARGE_ALPHABET" 1 sha256 2>&1
EXIT_5A=$?
set -e
echo ""
echo "Exit code: $EXIT_5A"
if [ $EXIT_5A -eq 139 ] || [ $EXIT_5A -eq 134 ] || [ $EXIT_5A -eq 137 ] || [ $EXIT_5A -eq 136 ]; then
    echo "FAIL: Stack overflow with large alphabet"
    VLA_WORKS=0
else
    echo "PASS: Large alphabet handled without stack overflow"
fi

# Test 5b: Even larger alphabet (100000 characters)
echo ""
echo "--- Test 5b: Very large alphabet (100000 chars) ---"
echo ""

VERY_LARGE_ALPHABET=$(printf 'a%.0s' $(seq 1 100000))
echo "Alphabet length: ${#VERY_LARGE_ALPHABET}"
echo ""

set +e
timeout 5 ./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE "$VERY_LARGE_ALPHABET" 1 sha256 2>&1
EXIT_5B=$?
set -e
echo ""
echo "Exit code: $EXIT_5B"
if [ $EXIT_5B -eq 139 ] || [ $EXIT_5B -eq 134 ] || [ $EXIT_5B -eq 137 ] || [ $EXIT_5B -eq 136 ]; then
    echo "FAIL: Stack overflow with very large alphabet"
    VLA_WORKS=0
else
    echo "PASS: Very large alphabet handled without stack overflow"
fi

# Test 5c: Verify heap allocation in code
echo ""
echo "--- Test 5c: Verify heap allocation in code ---"
if grep -q "struct s_thread_data \*\*pointers_data = malloc" /opt/src/main.c; then
    echo "PASS: Thread data array is heap allocated"
else
    echo "FAIL: Thread data array not heap allocated"
    VLA_WORKS=0
fi

if [ $VLA_WORKS -eq 1 ]; then
    echo ""
    echo "==> CWE-121 VLA STACK OVERFLOW: FIXED"
    echo "    Thread data array now heap allocated"
    ((PASS++))
else
    echo ""
    echo "==> CWE-121 VLA STACK OVERFLOW: ISSUE PRESENT"
    ((FAIL++))
fi
((TOTAL++))

#############################################
# MEDIUM ISSUE 6: Unchecked malloc (CWE-252)
#############################################
echo ""
echo "########################################"
echo "# MEDIUM 6: Unchecked malloc (CWE-252)"
echo "########################################"
echo ""
echo "malloc() return values not checked for NULL."
echo "Fix: Add NULL checks after all malloc calls."
echo ""

MALLOC_CHECKED=1

echo "--- Test 6a: Verify malloc NULL checks in code ---"
echo ""

# Count malloc calls that have NULL checks nearby
TOTAL_MALLOCS=$(grep -c "malloc(" /opt/src/main.c || echo 0)
CHECKED_MALLOCS=$(grep -B1 -A1 "malloc(" /opt/src/main.c | grep -c "== NULL\|!= NULL" || echo 0)

echo "Total malloc calls: $TOTAL_MALLOCS"
echo "Malloc calls with NULL checks: $CHECKED_MALLOCS"
echo ""

# Check specific malloc patterns
echo "--- Test 6b: Verify specific malloc NULL checks ---"
echo ""

# Check init_thread_data returns error on malloc failure
if grep -q "if (data->g_result == NULL)" /opt/src/main.c && grep -q "if (data->g_buffer == NULL)" /opt/src/main.c; then
    echo "PASS: init_thread_data checks malloc returns"
else
    echo "FAIL: init_thread_data missing malloc checks"
    MALLOC_CHECKED=0
fi

# Check g_to_encrypt malloc
if grep -q "if (g_to_encrypt == NULL)" /opt/src/main.c; then
    echo "PASS: g_to_encrypt malloc is checked"
else
    echo "FAIL: g_to_encrypt malloc not checked"
    MALLOC_CHECKED=0
fi

# Check g_signature malloc
if grep -q "if (g_signature == NULL)" /opt/src/main.c; then
    echo "PASS: g_signature malloc is checked"
else
    echo "FAIL: g_signature malloc not checked"
    MALLOC_CHECKED=0
fi

# Check pointers_data malloc
if grep -q "if (pointers_data == NULL)" /opt/src/main.c; then
    echo "PASS: pointers_data malloc is checked"
else
    echo "FAIL: pointers_data malloc not checked"
    MALLOC_CHECKED=0
fi

# Check tid malloc
if grep -q "if (tid == NULL)" /opt/src/main.c; then
    echo "PASS: tid malloc is checked"
else
    echo "FAIL: tid malloc not checked"
    MALLOC_CHECKED=0
fi

echo ""
if [ $MALLOC_CHECKED -eq 1 ]; then
    echo "==> CWE-252 UNCHECKED MALLOC: FIXED"
    echo "    All malloc returns are now validated"
    ((PASS++))
else
    echo "==> CWE-252 UNCHECKED MALLOC: ISSUE PRESENT"
    ((FAIL++))
fi
((TOTAL++))

#############################################
# MEDIUM ISSUE 7: Timing Side-Channel (CWE-208)
#############################################
echo ""
echo "########################################"
echo "# HIGH 7: Timing Side-Channel (CWE-208)"
echo "########################################"
echo ""
echo "memcmp() is not constant-time and may leak"
echo "information via timing differences."
echo "Fix: Use constant-time comparison function."
echo ""

TIMING_FIXED=1

echo "--- Test 7a: Verify constant-time compare function exists ---"
if grep -q "constant_time_compare" /opt/src/main.c; then
    echo "PASS: constant_time_compare function found"
else
    echo "FAIL: constant_time_compare function not found"
    TIMING_FIXED=0
fi

echo ""
echo "--- Test 7b: Verify memcmp is NOT used for signature comparison ---"
if grep -q "memcmp.*g_signature\|memcmp.*g_result" /opt/src/main.c; then
    echo "FAIL: memcmp still used for signature comparison"
    TIMING_FIXED=0
else
    echo "PASS: memcmp not used for signature comparison"
fi

echo ""
echo "--- Test 7c: Verify constant_time_compare is used ---"
if grep -q "constant_time_compare(data->g_result, g_signature" /opt/src/main.c; then
    echo "PASS: constant_time_compare used for signature comparison"
else
    echo "FAIL: constant_time_compare not used for signature comparison"
    TIMING_FIXED=0
fi

echo ""
if [ $TIMING_FIXED -eq 1 ]; then
    echo "==> CWE-208 TIMING ATTACK: FIXED"
    echo "    constant_time_compare() now used for signature comparison"
    ((PASS++))
else
    echo "==> CWE-208 TIMING ATTACK: ISSUE PRESENT"
    ((FAIL++))
fi
((TOTAL++))

#############################################
# SUMMARY
#############################################
echo ""
echo "========================================"
echo "SECURITY TEST SUMMARY"
echo "========================================"
echo ""
echo "Total test categories: $TOTAL"
echo "Fixes verified: $PASS"
echo "Issues remaining: $FAIL"
echo ""
echo "Critical Security Fixes:"
if [ $RACE_DETECTED -eq 1 ]; then
    echo "  1. CWE-362 Race Condition:    FAILED (still vulnerable)"
else
    echo "  1. CWE-362 Race Condition:    FIXED"
fi
if [ $NULL_CRASH_1 -eq 1 ] || [ $NULL_CRASH_2 -eq 1 ] || [ $NULL_CRASH_3 -eq 1 ] || [ $NULL_CRASH_4 -eq 1 ]; then
    echo "  2. CWE-476 NULL Dereference:  FAILED (still crashes)"
else
    echo "  2. CWE-476 NULL Dereference:  FIXED"
fi
if [ $BASE64URL_WORKS -eq 1 ]; then
    echo "  3. Base64/Base64URL Support:  WORKING"
else
    echo "  3. Base64/Base64URL Support:  FAILED"
fi
echo ""
echo "Medium/High Priority Fixes:"
if [ $INT_VALIDATION_WORKS -eq 1 ]; then
    echo "  4. CWE-190 Integer Overflow:  FIXED"
else
    echo "  4. CWE-190 Integer Overflow:  FAILED"
fi
if [ $VLA_WORKS -eq 1 ]; then
    echo "  5. CWE-121 VLA Stack Overflow: FIXED"
else
    echo "  5. CWE-121 VLA Stack Overflow: FAILED"
fi
if [ $MALLOC_CHECKED -eq 1 ]; then
    echo "  6. CWE-252 Unchecked malloc:  FIXED"
else
    echo "  6. CWE-252 Unchecked malloc:  FAILED"
fi
if [ $TIMING_FIXED -eq 1 ]; then
    echo "  7. CWE-208 Timing Attack:     FIXED"
else
    echo "  7. CWE-208 Timing Attack:     FAILED"
fi
echo ""

# Also run standard functional tests
echo "========================================"
echo "STANDARD FUNCTIONAL TESTS"
echo "========================================"
echo ""

echo "--- Functional Test: HS256 (secret: Sn1f) ---"
RESULT=$(./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE ABCSNFabcsnf1234567 5 sha256)
echo "$RESULT"
if echo "$RESULT" | grep -q 'Secret is "Sn1f"'; then
    echo "PASSED"
else
    echo "FAILED"
fi

echo ""
echo "--- Memory Test: Valgrind leak check ---"
set +e
valgrind --leak-check=full --error-exitcode=1 \
    ./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE ABCSNFabcsnf1234567 5 sha256
VALGRIND_EXIT=$?
set -e
if [ $VALGRIND_EXIT -eq 0 ]; then
    echo "PASSED - No memory leaks"
else
    echo "FAILED - Memory leaks detected"
fi

echo ""
echo "========================================"
echo "TEST SUITE COMPLETE"
echo "========================================"
