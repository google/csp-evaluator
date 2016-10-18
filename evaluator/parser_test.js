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
 * @fileoverview Tests for CSP Parser.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.CspParserTest');
goog.setTestOnly('csp.CspParserTest');

goog.require('csp.CspParser');
goog.require('goog.testing.jsunit');


function testCspParser() {
  var validCsp =  // Test policy with different features from CSP2.
      "default-src 'none';" +
      "script-src 'nonce-unsafefoobar' 'unsafe-eval'   'unsafe-inline' \n" +
      'https://example.com/foo.js foo.bar;      ' +
      "object-src 'none';" +
      "img-src 'self' https: data: blob:;" +
      "style-src 'self' 'unsafe-inline' 'sha256-1DCfk1NYWuHMfoobarfoobar=';" +
      'font-src *;' +
      'child-src *.example.com:9090;' +
      'upgrade-insecure-requests;\n' +
      'report-uri /csp/test';

  var parser = new csp.CspParser(validCsp);
  var parsedCsp = parser.csp;

  // check directives
  var directives = Object.keys(parsedCsp);
  var expectedDirectives = [
    'default-src', 'script-src', 'object-src', 'img-src', 'style-src',
    'font-src', 'child-src', 'upgrade-insecure-requests', 'report-uri'];
  assertSameElements(expectedDirectives, directives);

  // check directive values
  assertSameElements(["'none'"], parsedCsp['default-src']);
  assertSameElements(
      ["'nonce-unsafefoobar'", "'unsafe-eval'", "'unsafe-inline'",
       'https://example.com/foo.js', 'foo.bar'],
      parsedCsp['script-src']);
  assertSameElements(["'none'"], parsedCsp['object-src']);
  assertSameElements(
      ["'self'", 'https:', 'data:', 'blob:'], parsedCsp['img-src']);
  assertSameElements(
      ["'self'", "'unsafe-inline'", "'sha256-1DCfk1NYWuHMfoobarfoobar='"],
      parsedCsp['style-src']);
  assertSameElements(['*'], parsedCsp['font-src']);
  assertSameElements(['*.example.com:9090'], parsedCsp['child-src']);
  assertSameElements([], parsedCsp['upgrade-insecure-requests']);
  assertSameElements(['/csp/test'], parsedCsp['report-uri']);
}


function testCspParserDuplicateDirectives() {
  var validCsp =
      "default-src 'none';" +
      'default-src foo.bar;' +
      "object-src 'none';" +
      'OBJECT-src foo.bar;';

  var parser = new csp.CspParser(validCsp);
  var parsedCsp = parser.csp;

  // check directives
  var directives = Object.keys(parsedCsp);
  var expectedDirectives = ['default-src', 'object-src'];
  assertSameElements(expectedDirectives, directives);

  // check directive values
  assertSameElements(["'none'"], parsedCsp['default-src']);
  assertSameElements(["'none'"], parsedCsp['object-src']);
}


function testCspParserMixedCaseKeywords() {
  var validCsp =
      "DEFAULT-src 'NONE';" +  // Keywords should be case insensetive.
      "img-src 'sElf' HTTPS: Example.com/CaseSensitive;";

  var parser = new csp.CspParser(validCsp);
  var parsedCsp = parser.csp;

  // check directives
  var directives = Object.keys(parsedCsp);
  var expectedDirectives = ['default-src', 'img-src'];
  assertSameElements(expectedDirectives, directives);

  // check directive values
  assertSameElements(["'none'"], parsedCsp['default-src']);
  assertSameElements(
      ["'self'", 'https:', 'Example.com/CaseSensitive'], parsedCsp['img-src']);
}


function testNormalizeDirectiveValue() {
  assertEquals("'none'", csp.CspParser.normalizeDirectiveValue_("'nOnE'"));
  assertEquals(
      "'nonce-aBcD'", csp.CspParser.normalizeDirectiveValue_("'nonce-aBcD'"));
  assertEquals(
      "'hash-XyZ=='", csp.CspParser.normalizeDirectiveValue_("'hash-XyZ=='"));
  assertEquals('https:', csp.CspParser.normalizeDirectiveValue_('HTTPS:'));
  assertEquals(
      'example.com/TEST',
      csp.CspParser.normalizeDirectiveValue_('example.com/TEST'));
}
