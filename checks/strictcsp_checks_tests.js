/**
 * @license
 * Copyright 2016 Google Inc. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @fileoverview Tests for strict CSP checks.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.strictcspChecksTest');
goog.setTestOnly();

goog.require('csp.Csp');
goog.require('csp.CspParser');
goog.require('csp.strictcspChecks');

goog.require('goog.testing.jsunit');


/**
 * Helper function for running a check on a CSP string.
 *
 * @param {string} test CSP string.
 * @param {!function(!csp.Csp):!Array.<!csp.Finding>} checkFunction check.
 * @return {!Array.<!csp.Finding>}
 */
function checkCsp(test, checkFunction) {
  var parsedCsp = new csp.CspParser(test).csp;
  return checkFunction(parsedCsp);
}


/** Tests for csp.strictcspChecks.checkStrictDynamic */
function testCheckStrictDynamic() {
  var test = 'script-src foo.bar';

  var violations = checkCsp(test, csp.strictcspChecks.checkStrictDynamic);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.STRICT_CSP, violations[0].severity);
}


/** Tests for csp.strictcspChecks.checkStrictDynamicNotStandalone */
function testCheckStrictDynamicNotStandalone() {
  var test = "script-src 'strict-dynamic'";

  var violations = checkCsp(
      test, csp.strictcspChecks.checkStrictDynamicNotStandalone);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.INFO, violations[0].severity);
}

function testCheckStrictDynamicNotStandaloneDoesntFireIfNoncePresent() {
  var test = "script-src 'strict-dynamic' 'nonce-foobar'";

  var violations = checkCsp(
      test, csp.strictcspChecks.checkStrictDynamicNotStandalone);
  assertEquals(0, violations.length);
}


/** Tests for csp.strictcspChecks.checkUnsafeInlineFallback */
function testCheckUnsafeInlineFallback() {
  var test = "script-src 'nonce-test'";

  var violations = checkCsp(
      test, csp.strictcspChecks.checkUnsafeInlineFallback);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.STRICT_CSP, violations[0].severity);
}


function testCheckUnsafeInlineFallbackDoesntFireIfFallbackPresent() {
  var test = "script-src 'nonce-test' 'unsafe-inline'";

  var violations = checkCsp(
      test, csp.strictcspChecks.checkUnsafeInlineFallback);
  assertEquals(0, violations.length);
}


/** Tests for csp.strictcspChecks.checkWhitelistFallback */
function testCheckWhitelistFallback() {
  var test = "script-src 'nonce-test' 'strict-dynamic'";

  var violations = checkCsp(
      test, csp.strictcspChecks.checkWhitelistFallback);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.STRICT_CSP, violations[0].severity);
}


function testCheckWhitelistFallbackDoesntFireIfSchemeFallbackPresent() {
  var test = "script-src 'nonce-test' 'strict-dynamic' https:";

  var violations = checkCsp(
      test, csp.strictcspChecks.checkWhitelistFallback);
  assertEquals(0, violations.length);
}


function testCheckWhitelistFallbackDoesntFireIfURLFallbackPresent() {
  var test = "script-src 'nonce-test' 'strict-dynamic' foo.bar";

  var violations = checkCsp(
      test, csp.strictcspChecks.checkWhitelistFallback);
  assertEquals(0, violations.length);
}


function testCheckWhitelistFallbackDoesntFireInAbsenceOfStrictDynamic() {
  var test = "script-src 'nonce-test'";

  var violations = checkCsp(
      test, csp.strictcspChecks.checkWhitelistFallback);
  assertEquals(0, violations.length);
}
