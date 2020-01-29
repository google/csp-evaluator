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
 * @fileoverview Tests for CSP Defintions.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.CspTest');
goog.setTestOnly('csp.CspTest');

goog.require('csp');
goog.require('csp.Csp');
goog.require('csp.CspParser');
goog.require('csp.Directive');
goog.require('csp.Keyword');
goog.require('csp.Version');
goog.require('goog.array');
goog.require('goog.object');
goog.require('goog.testing.jsunit');


function testConvertToString() {
  var testCsp =
      "default-src 'none'; " +
      "script-src 'nonce-unsafefoobar' 'unsafe-eval' 'unsafe-inline' " +
      'https://example.com/foo.js foo.bar; ' +
      "img-src 'self' https: data: blob:; ";

  var parsed = new csp.CspParser(testCsp).csp;
  assertEquals(testCsp, csp.Csp.convertToString(parsed));
}


function testGetEffectiveCspVersion1() {
  var testCsp =
    "default-src 'unsafe-inline' 'strict-dynamic' 'nonce-123' " +
    "'sha256-foobar' 'self'; report-to foo.bar; worker-src *; manifest-src *";
  var parsed = new csp.CspParser(testCsp).csp;
  var effectiveCsp = csp.Csp.getEffectiveCsp(parsed, csp.Version.CSP1);

  assertElementsEquals(
    ["'unsafe-inline'", "'self'"],
    effectiveCsp[csp.Directive.DEFAULT_SRC]);
  assertFalse(effectiveCsp.hasOwnProperty(csp.Directive.REPORT_TO));
  assertFalse(effectiveCsp.hasOwnProperty(csp.Directive.WORKER_SRC));
  assertFalse(effectiveCsp.hasOwnProperty(csp.Directive.MANIFEST_SRC));
}


function testGetEffectiveCspVersion2() {
  var testCsp =
    "default-src 'unsafe-inline' 'strict-dynamic' 'nonce-123' " +
    "'sha256-foobar' 'self'; report-to foo.bar; worker-src *; manifest-src *";
  var parsed = new csp.CspParser(testCsp).csp;
  var effectiveCsp = csp.Csp.getEffectiveCsp(parsed, csp.Version.CSP2);

  assertElementsEquals(
    ["'nonce-123'", "'sha256-foobar'", "'self'"],
    effectiveCsp[csp.Directive.DEFAULT_SRC]);
  assertFalse(effectiveCsp.hasOwnProperty(csp.Directive.REPORT_TO));
  assertFalse(effectiveCsp.hasOwnProperty(csp.Directive.WORKER_SRC));
  assertFalse(effectiveCsp.hasOwnProperty(csp.Directive.MANIFEST_SRC));
}


function testGetEffectiveCspVersion3() {
  var testCsp =
    "default-src 'unsafe-inline' 'strict-dynamic' 'nonce-123' " +
    "'sha256-foobar' 'self'; report-to foo.bar; worker-src *; manifest-src *";
  var parsed = new csp.CspParser(testCsp).csp;
  var effectiveCsp = csp.Csp.getEffectiveCsp(parsed, csp.Version.CSP3);

  assertElementsEquals(
    ["'strict-dynamic'", "'nonce-123'", "'sha256-foobar'"],
    effectiveCsp[csp.Directive.DEFAULT_SRC]);
  assertElementsEquals(['foo.bar'], effectiveCsp[csp.Directive.REPORT_TO]);
  assertElementsEquals(['*'], effectiveCsp[csp.Directive.WORKER_SRC]);
  assertElementsEquals(['*'], effectiveCsp[csp.Directive.MANIFEST_SRC]);
}


function testGetEffectiveDirective() {
  var testCsp = 'default-src https:; script-src foo.bar';
  var parsed = new csp.CspParser(testCsp).csp;

  var script = csp.Csp.getEffectiveDirective(parsed, csp.Directive.SCRIPT_SRC);
  assertEquals(csp.Directive.SCRIPT_SRC, script);
  var style = csp.Csp.getEffectiveDirective(parsed, csp.Directive.STYLE_SRC);
  assertEquals(csp.Directive.DEFAULT_SRC, style);
}


function testGetEffectiveDirectives() {
  var testCsp = 'default-src https:; script-src foo.bar';
  var parsed = new csp.CspParser(testCsp).csp;

  var directives = csp.Csp.getEffectiveDirectives(
    parsed, [csp.Directive.SCRIPT_SRC, csp.Directive.STYLE_SRC]);
  assertElementsEquals(
      [csp.Directive.SCRIPT_SRC, csp.Directive.DEFAULT_SRC],
      directives);
}


function testPolicyHasScriptNoncesScriptSrcWithNonce() {
  var testCsp = "default-src https:; script-src 'nonce-test123'";
  var parsed = new csp.CspParser(testCsp).csp;

  assertTrue(csp.Csp.policyHasScriptNonces(parsed));
}


function testPolicyHasScriptNoncesNoNonce() {
  var testCsp = "default-src https: 'nonce-ignored'; script-src nonce-invalid";
  var parsed = new csp.CspParser(testCsp).csp;

  assertFalse(csp.Csp.policyHasScriptNonces(parsed));
}


function testPolicyHasScriptHashesScriptSrcWithHash() {
  var testCsp = "default-src https:; script-src 'sha256-asdfASDF'";
  var parsed = new csp.CspParser(testCsp).csp;

  assertTrue(csp.Csp.policyHasScriptHashes(parsed));
}


function testPolicyHasScriptHashesNoHash() {
  var testCsp = "default-src https: 'nonce-ignored'; script-src sha256-invalid";
  var parsed = new csp.CspParser(testCsp).csp;

  assertFalse(csp.Csp.policyHasScriptHashes(parsed));
}


function testPolicyHasStrictDynamicScriptSrcWithStrictDynamic() {
  var testCsp = "default-src https:; script-src 'strict-dynamic'";
  var parsed = new csp.CspParser(testCsp).csp;

  assertTrue(csp.Csp.policyHasStrictDynamic(parsed));
}


function testPolicyHasStrictDynamicDefaultSrcWithStrictDynamic() {
  var testCsp = "default-src https 'strict-dynamic'";
  var parsed = new csp.CspParser(testCsp).csp;

  assertTrue(csp.Csp.policyHasStrictDynamic(parsed));
}


function testPolicyHasStrictDynamicNoStrictDynamic() {
  var testCsp = "default-src 'strict-dynamic'; script-src foo.bar";
  var parsed = new csp.CspParser(testCsp).csp;

  assertFalse(csp.Csp.policyHasStrictDynamic(parsed));
}


function testIsDirective() {
  var directives =
    goog.object.getKeys(csp.Directive).map(name => csp.Directive[name]);

  assertTrue(goog.array.every(directives, csp.isDirective));
  assertFalse(csp.isDirective('invalid-src'));
}


function testIsKeyword() {
  var keywords =
    goog.object.getKeys(csp.Keyword).map(name => csp.Keyword[name]);

  assertTrue(goog.array.every(keywords, csp.isKeyword));
  assertFalse(csp.isKeyword('invalid'));
}


function testIsUrlScheme() {
  assertTrue(csp.isUrlScheme('http:'));
  assertTrue(csp.isUrlScheme('https:'));
  assertTrue(csp.isUrlScheme('data:'));
  assertTrue(csp.isUrlScheme('blob:'));
  assertTrue(csp.isUrlScheme('b+l.o-b:'));
  assertTrue(csp.isUrlScheme('filesystem:'));
  assertFalse(csp.isUrlScheme('invalid'));
  assertFalse(csp.isUrlScheme('ht_tp:'));
}


function testIsNonce() {
  assertTrue(csp.isNonce("'nonce-asdfASDF='"));
  assertFalse(csp.isNonce("'sha256-asdfASDF='"));
  assertFalse(csp.isNonce("'asdfASDF='"));
  assertFalse(csp.isNonce('example.com'));
}


function testIsStrictNonce() {
  assertTrue(csp.isNonce("'nonce-asdfASDF='", true));
  assertTrue(csp.isNonce("'nonce-as+df/A0234SDF=='", true));
  assertTrue(csp.isNonce("'nonce-as_dfASDF='", true));
  assertFalse(csp.isNonce("'nonce-asdfASDF==='", true));
  assertFalse(csp.isNonce("'sha256-asdfASDF='", true));
}


function testIsHash() {
  assertTrue(csp.isHash("'sha256-asdfASDF='"));
  assertFalse(csp.isHash("'sha777-asdfASDF='"));
  assertFalse(csp.isHash("'asdfASDF='"));
  assertFalse(csp.isHash('example.com'));
}

function testIsStrictHash() {
  assertTrue(csp.isHash("'sha256-asdfASDF='", true));
  assertTrue(csp.isHash("'sha256-as+d/f/ASD0+4F=='", true));
  assertFalse(csp.isHash("'sha256-asdfASDF==='", true));
  assertFalse(csp.isHash("'sha256-asd_fASDF='", true));
  assertFalse(csp.isHash("'sha777-asdfASDF='", true));
  assertFalse(csp.isHash("'asdfASDF='", true));
  assertFalse(csp.isHash('example.com', true));
}
