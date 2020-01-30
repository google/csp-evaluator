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
 * @fileoverview Tests for CSP Parser checks.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.parserChecksTest');
goog.setTestOnly();

goog.require('csp.Csp');
goog.require('csp.CspParser');
goog.require('csp.Finding');
goog.require('csp.parserChecks');

goog.require('goog.array');
goog.require('goog.string');
goog.require('goog.testing.jsunit');


/**
 * Runs a check on a CSP string.
 *
 * @param {string} test CSP string.
 * @param {!function(!csp.Csp):!Array.<!csp.Finding>} checkFunction check.
 * @return {!Array.<!csp.Finding>}
 */
function checkCsp(test, checkFunction) {
  var parsedCsp = new csp.CspParser(test).csp;
  return checkFunction(parsedCsp);
}


/** Tests for csp.parserChecks.checkUnknownDirective */

function testCheckUnknownDirective() {
  var test = "foobar-src http:";

  var violations = checkCsp(test, csp.parserChecks.checkUnknownDirective);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.SYNTAX, violations[0].severity);
  assertEquals('foobar-src', violations[0].value);
}


/** Tests for csp.parserChecks.checkMissingSemicolon */

function testCheckMissingSemicolon() {
  var test = "default-src foo.bar script-src \'none\'";

  var violations = checkCsp(test, csp.parserChecks.checkMissingSemicolon);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.SYNTAX, violations[0].severity);
  assertEquals('script-src', violations[0].value);
}


/** Tests for csp.parserChecks.checkInvalidKeyword */

function testCheckInvalidKeywordForgottenSingleTicks() {
  var test = "script-src strict-dynamic nonce-test sha256-asdf";

  var violations = checkCsp(test, csp.parserChecks.checkInvalidKeyword);
  assertEquals(3, violations.length);
  assertTrue(goog.array.every(
      violations, v => v.severity == csp.Finding.Severity.SYNTAX));
  assertTrue(goog.array.every(
      violations, v => goog.string.contains(v.description, 'single-ticks')));
}


function testCheckInvalidKeywordUnknownKeyword() {
  var test = "script-src \'foo-bar\'";

  var violations = checkCsp(test, csp.parserChecks.checkInvalidKeyword);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.SYNTAX, violations[0].severity);
  assertEquals("\'foo-bar\'", violations[0].value);
}

function testCheckInvalidKeywordAllowsRequireTrustedTypesForScript() {
  var test = "require-trusted-types-for 'script'";

  var violations = checkCsp(test, csp.parserChecks.checkInvalidKeyword);
  assertEquals(0, violations.length);
}

function testCheckInvalidKeywordAllowsTrustedTypesAllowDuplicateKeyword() {
  var test = "trusted-types 'allow-duplicates' policy1";

  var violations = checkCsp(test, csp.parserChecks.checkInvalidKeyword);
  assertEquals(0, violations.length);
}
