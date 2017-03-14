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
 * @fileoverview Tests for CSP Evaluator Checks.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.securityChecksTest');
goog.setTestOnly();

goog.require('csp.Csp');
goog.require('csp.CspParser');
goog.require('csp.securityChecks');
goog.require('csp.whitelistBypasses.angular');
goog.require('csp.whitelistBypasses.flash');
goog.require('csp.whitelistBypasses.jsonp');

goog.require('goog.Uri');
goog.require('goog.array');
goog.require('goog.string');
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


/** Tests for csp.securityChecks.checkScriptUnsafeInline */

function testCheckScriptUnsafeInlineInScriptSrc() {
  var test = "default-src https:; script-src 'unsafe-inline'";

  var violations = checkCsp(test, csp.securityChecks.checkScriptUnsafeInline);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.HIGH, violations[0].severity);
}

function testCheckScriptUnsafeInlineInDefaultSrc() {
  var test = "default-src 'unsafe-inline'";

  var violations = checkCsp(test, csp.securityChecks.checkScriptUnsafeInline);
  assertEquals(1, violations.length);
}

function testCheckScriptUnsafeInlineInDefaultSrcAndNotInScriptSrc() {
  var test = "default-src 'unsafe-inline'; script-src https:";

  var violations = checkCsp(test, csp.securityChecks.checkScriptUnsafeInline);
  assertEquals(0, violations.length);
}

function testCheckScriptUnsafeInlineWithNonce() {
  var test = "script-src 'unsafe-inline' 'nonce-foobar'";
  var parsedCsp = new csp.CspParser(test).csp;

  var effectiveCsp = csp.Csp.getEffectiveCsp(parsedCsp, csp.Version.CSP1);
  var violations = csp.securityChecks.checkScriptUnsafeInline(effectiveCsp);
  assertEquals(1, violations.length);

  effectiveCsp = csp.Csp.getEffectiveCsp(parsedCsp, csp.Version.CSP3);
  violations = csp.securityChecks.checkScriptUnsafeInline(effectiveCsp);
  assertEquals(0, violations.length);

}


/** Tests for csp.securityChecks.checkScriptUnsafeEval */

function testCheckScriptUnsafeEvalInScriptSrc() {
  var test = "default-src https:; script-src 'unsafe-eval'";

  var violations = checkCsp(test, csp.securityChecks.checkScriptUnsafeEval);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.MEDIUM_MAYBE, violations[0].severity);
}

function testCheckScriptUnsafeEvalInDefaultSrc() {
  var test = "default-src 'unsafe-eval'";

  var violations = checkCsp(test, csp.securityChecks.checkScriptUnsafeEval);
  assertEquals(1, violations.length);
}


/** Tests for csp.securityChecks.checkPlainUrlSchemes */

function testCheckPlainUrlSchemesInScriptSrc() {
  var test = "script-src data: http: https: sthInvalid:";

  var violations = checkCsp(test, csp.securityChecks.checkPlainUrlSchemes);
  assertEquals(3, violations.length);
  assertTrue(
    goog.array.every(violations, v => v.severity == csp.Finding.Severity.HIGH));
}

function testCheckPlainUrlSchemesInObjectSrc() {
  var test = "object-src data: http: https: sthInvalid:";

  var violations = checkCsp(test, csp.securityChecks.checkPlainUrlSchemes);
  assertEquals(3, violations.length);
  assertTrue(
    goog.array.every(violations, v => v.severity == csp.Finding.Severity.HIGH));
}

function testCheckPlainUrlSchemesInBaseUri() {
  var test = "base-uri data: http: https: sthInvalid:";

  var violations = checkCsp(test, csp.securityChecks.checkPlainUrlSchemes);
  assertEquals(3, violations.length);
  assertTrue(
    goog.array.every(violations, v => v.severity == csp.Finding.Severity.HIGH));
}

function testCheckPlainUrlSchemesMixed() {
  var test = "default-src https:; object-src data: sthInvalid:";

  var violations = checkCsp(test, csp.securityChecks.checkPlainUrlSchemes);
  assertEquals(2, violations.length);
  assertTrue(
    goog.array.every(violations, v => v.severity == csp.Finding.Severity.HIGH));
  assertEquals(csp.Directive.DEFAULT_SRC, violations[0].directive);
  assertEquals(csp.Directive.OBJECT_SRC, violations[1].directive);
}

function testCheckPlainUrlSchemesDangerousDirectivesOK() {
  var test = "default-src https:; object-src 'none'; script-src 'none'; " +
      "base-uri 'none'";

  var violations = checkCsp(test, csp.securityChecks.checkPlainUrlSchemes);
  assertEquals(0, violations.length);
}


/** Tests for csp.securityChecks.checkWildcards */

function testCheckWildcardsInScriptSrc() {
  var test = "script-src * http://* //*";

  var violations = checkCsp(test, csp.securityChecks.checkWildcards);
  assertEquals(3, violations.length);
  assertTrue(
    goog.array.every(violations, v => v.severity == csp.Finding.Severity.HIGH));
}

function testCheckWildcardsInObjectSrc() {
  var test = "object-src * http://* //*";

  var violations = checkCsp(test, csp.securityChecks.checkWildcards);
  assertEquals(3, violations.length);
  assertTrue(
    goog.array.every(violations, v => v.severity == csp.Finding.Severity.HIGH));
}

function testCheckWildcardsInBaseUri() {
  var test = "base-uri * http://* //*";

  var violations = checkCsp(test, csp.securityChecks.checkWildcards);
  assertEquals(3, violations.length);
  assertTrue(
    goog.array.every(violations, v => v.severity == csp.Finding.Severity.HIGH));
}

function testCheckWildcardsSchemesMixed() {
  var test = "default-src *; object-src * ignore.me.com";

  var violations = checkCsp(test, csp.securityChecks.checkWildcards);
  assertEquals(2, violations.length);
  assertTrue(
    goog.array.every(violations, v => v.severity == csp.Finding.Severity.HIGH));
  assertEquals(csp.Directive.DEFAULT_SRC, violations[0].directive);
  assertEquals(csp.Directive.OBJECT_SRC, violations[1].directive);
}

function testCheckWildcardsDangerousDirectivesOK() {
  var test = "default-src *; object-src *.foo.bar; script-src 'none'; " +
      "base-uri 'none'";

  var violations = checkCsp(test, csp.securityChecks.checkWildcards);
  assertEquals(0, violations.length);
}


/** Tests for csp.securityChecks.checkMissingDirectives */

function testCheckMissingDirectivesMissingObjectSrc() {
  var test = "script-src 'none'";

  var violations = checkCsp(test, csp.securityChecks.checkMissingDirectives);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.HIGH, violations[0].severity);
}

function testCheckMissingDirectivesMissingScriptSrc() {
  var test = "object-src 'none'";

  var violations = checkCsp(test, csp.securityChecks.checkMissingDirectives);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.HIGH, violations[0].severity);
}

function testCheckMissingDirectivesMissingBaseUriInNonceCsp() {
  var test = "script-src 'nonce-123'; object-src 'none'";

  var violations = checkCsp(test, csp.securityChecks.checkMissingDirectives);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.HIGH, violations[0].severity);
}

function testCheckMissingDirectivesMissingBaseUriInHashWStrictDynamicCsp() {
  var test = "script-src 'sha256-123456' 'strict-dynamic'; object-src 'none'";

  var violations = checkCsp(test, csp.securityChecks.checkMissingDirectives);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.HIGH, violations[0].severity);
}

function testCheckMissingDirectivesMissingBaseUriInHashCsp() {
  var test = "script-src 'sha256-123456'; object-src 'none'";

  var violations = checkCsp(test, csp.securityChecks.checkMissingDirectives);
  assertEquals(0, violations.length);
}

function testCheckMissingDirectivesScriptAndObjectSrcSet() {
  var test = "script-src 'none'; object-src 'none'";

  var violations = checkCsp(test, csp.securityChecks.checkMissingDirectives);
  assertEquals(0, violations.length);
}

function testCheckMissingDirectivesDefaultSrcSet() {
  var test = "default-src https:;";

  var violations = checkCsp(test, csp.securityChecks.checkMissingDirectives);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.HIGH_MAYBE, violations[0].severity);
}

function testCheckMissingDirectivesDefaultSrcSetToNone() {
  var test = "default-src 'none';";

  var violations = checkCsp(test, csp.securityChecks.checkMissingDirectives);
  assertEquals(0, violations.length);
}


/** Tests for csp.securityChecks.checkScriptWhitelistBypass */
csp.whitelistBypasses.jsonp.URLS = goog.array.map([
  '//googletagmanager.com/gtm/js',
  '//www.google.com/jsapi',
  '//ajax.googleapis.com/ajax/services/feed/load'
], url => new goog.Uri(url));


csp.whitelistBypasses.jsonp.NEEDS_EVAL = [
  'googletagmanager.com'
];


csp.whitelistBypasses.angular.URLS = goog.array.map([
  '//gstatic.com/fsn/angular_js-bundle1.js'
], url => new goog.Uri(url));


function testCheckScriptWhitelistBypassJSONPBypass() {
  var test = 'script-src *.google.com';

  var violations = checkCsp(
      test, csp.securityChecks.checkScriptWhitelistBypass);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.HIGH, violations[0].severity);
  assertTrue(goog.string.contains(
      violations[0].description,
      'www.google.com is known to host JSONP endpoints which'));
}

function testCheckScriptWhitelistBypassJSONPBypassEvalRequired() {
  var test = "script-src https://googletagmanager.com 'unsafe-eval'";

  var violations = checkCsp(
      test, csp.securityChecks.checkScriptWhitelistBypass);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.HIGH, violations[0].severity);
}


function testCheckScriptWhitelistBypassJSONPBypassEvalRequiredNotPresent() {
  var test = 'script-src https://googletagmanager.com';

  var violations = checkCsp(
      test, csp.securityChecks.checkScriptWhitelistBypass);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.MEDIUM_MAYBE, violations[0].severity);
}


function testCheckScriptWhitelistBypassAngularBypass() {
  var test = 'script-src gstatic.com';

  var violations = checkCsp(
      test, csp.securityChecks.checkScriptWhitelistBypass);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.HIGH, violations[0].severity);
  assertTrue(goog.string.contains(
      violations[0].description,
      'gstatic.com is known to host Angular libraries which'));
}


function testCheckScriptWhitelistBypassNoBypassWarningOnly() {
  var test = 'script-src foo.bar';

  var violations = checkCsp(
      test, csp.securityChecks.checkScriptWhitelistBypass);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.MEDIUM_MAYBE, violations[0].severity);
}


function testCheckScriptWhitelistBypassNoBypassSelfWarningOnly() {
  var test = 'script-src \'self\'';

  var violations = checkCsp(
      test, csp.securityChecks.checkScriptWhitelistBypass);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.MEDIUM_MAYBE, violations[0].severity);
}


/** Tests for csp.securityChecks.checkFlashObjectWhitelistBypass */
csp.whitelistBypasses.flash.URLS = goog.array.map([
  '//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'
], url => new goog.Uri(url));


function testCheckFlashObjectWhitelistBypassFlashBypass() {
  var test = 'object-src https://*.googleapis.com';

  var violations = checkCsp(
      test, csp.securityChecks.checkFlashObjectWhitelistBypass);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.HIGH, violations[0].severity);
}


function testCheckFlashObjectWhitelistBypassNoFlashBypass() {
  var test = 'object-src https://foo.bar';

  var violations = checkCsp(
      test, csp.securityChecks.checkFlashObjectWhitelistBypass);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.MEDIUM_MAYBE, violations[0].severity);
}


function testCheckFlashObjectWhitelistBypassSelfAllowed() {
  var test = 'object-src \'self\'';

  var violations = checkCsp(
      test, csp.securityChecks.checkFlashObjectWhitelistBypass);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.MEDIUM_MAYBE, violations[0].severity);
  assertEquals(
      "Can you restrict object-src to 'none' only?", violations[0].description);
}


/** Tests for csp.securityChecks.checkIpSource */
function testCheckIpSource() {
  var test = 'script-src 8.8.8.8; font-src //127.0.0.1 https://[::1] not.an.ip';

  var violations = checkCsp(test, csp.securityChecks.checkIpSource);
  assertEquals(3, violations.length);
  assertTrue(
    goog.array.every(violations, v => v.severity == csp.Finding.Severity.INFO));
  }


/** Tests for csp.securityChecks.checkIpSource */
function testCheckDeprecatedDirective() {
  var test = 'report-uri foo.bar/csp';

  var violations = checkCsp(test, csp.securityChecks.checkDeprecatedDirective);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.INFO, violations[0].severity);
}


/** Tests for csp.securityChecks.checkNonceLength */
function testCheckNonceLengthWithLongNonce() {
  var test = 'script-src \'nonce-veryLongRandomNonce\'';

  var violations = checkCsp(test, csp.securityChecks.checkNonceLength);
  assertEquals(0, violations.length);
}

function testCheckNonceLengthWithShortNonce() {
  var test = 'script-src \'nonce-short\'';

  var violations = checkCsp(test, csp.securityChecks.checkNonceLength);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.MEDIUM, violations[0].severity);
}

function testCheckNonceLengthInvalidCharset() {
  var test = 'script-src \'nonce-***notBase64***\'';

  var violations = checkCsp(test, csp.securityChecks.checkNonceLength);
  assertEquals(1, violations.length);
  assertEquals(csp.Finding.Severity.INFO, violations[0].severity);
}


/** Tests for csp.securityChecks.checkSrcHttp */
function testCheckSrcHttp() {
  var test =
      'script-src http://foo.bar https://test.com; report-uri http://test.com';

  var violations = checkCsp(test, csp.securityChecks.checkSrcHttp);
  assertEquals(2, violations.length);
  assertTrue(goog.array.every(
      violations, v => v.severity == csp.Finding.Severity.MEDIUM));
}
