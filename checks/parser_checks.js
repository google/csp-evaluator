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
 * @fileoverview Collection of CSP parser checks which can be used to find
 * common syntax mistakes like missing semicolons, invalid directives or
 * invalid keywords.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.parserChecks');

goog.require('csp');
goog.require('csp.Finding');
goog.require('csp.Keyword');
goog.require('goog.array');
goog.require('goog.object');


/**
 * Checks if the csp contains invalid directives.
 *
 * Example policy where this check would trigger:
 *  foobar-src foo.bar
 *
 * @param {!csp.Csp} parsedCsp A parsed csp.
 * @return {!Array.<!csp.Finding>}
 */
csp.parserChecks.checkUnknownDirective = function(parsedCsp) {
  var findings = [];

  for (let directive of Object.keys(parsedCsp)) {
    if (csp.isDirective(directive)) {
      continue;  // Directive is known.
    }

    if (directive.endsWith(':')) {
      findings.push(new csp.Finding(
          csp.Finding.Type.UNKNOWN_DIRECTIVE,
          'CSP directives don\'t end with a colon.',
          csp.Finding.Severity.SYNTAX, directive));
    } else {
      findings.push(new csp.Finding(
          csp.Finding.Type.UNKNOWN_DIRECTIVE,
          'Directive "' + directive + '" is not a known CSP directive.',
          csp.Finding.Severity.SYNTAX, directive));
    }
  }

  return findings;
};


/**
 * Checks if semicolons are missing in the csp.
 *
 * Example policy where this check would trigger (missing semicolon before
 * start of object-src):
 *  script-src foo.bar object-src 'none'
 *
 * @param {!csp.Csp} parsedCsp A parsed csp.
 * @return {!Array.<!csp.Finding>}
 */
csp.parserChecks.checkMissingSemicolon = function(parsedCsp) {
  var findings = [];

  for (let directive of Object.keys(parsedCsp)) {
    for (let value of parsedCsp[directive]) {
      // If we find a known directive inside a directive value, it is very
      // likely that a semicolon was forgoten.
      if (csp.isDirective(value)) {
        findings.push(new csp.Finding(
            csp.Finding.Type.MISSING_SEMICOLON,
            'Did you forget the semicolon? ' +
            '"' + value + '" seems to be a directive, not a value',
            csp.Finding.Severity.SYNTAX, directive, value));
      }
    }
  }

  return findings;
};


/**
 * Checks if csp contains invalid keywords.
 *
 * Example policy where this check would trigger:
 *  script-src 'notAkeyword'
 *
 * @param {!csp.Csp} parsedCsp A parsed csp.
 * @return {!Array.<!csp.Finding>}
 */
csp.parserChecks.checkInvalidKeyword = function(parsedCsp) {
  var findings = [];
  var keywordsNoTicks = goog.array.map(
      goog.object.getValues(csp.Keyword), k => k.replace(/'/g,''));

  for (let directive of Object.keys(parsedCsp)) {
    for (let value of parsedCsp[directive]) {
      // Check if single ticks have been forgotten.
      if (goog.array.some(keywordsNoTicks, k => k == value) ||
          value.startsWith('nonce-') ||
          value.match(/^(sha256|sha384|sha512)-/)) {
        findings.push(new csp.Finding(
            csp.Finding.Type.INVALID_KEYWORD,
            'Did you forget to surround "' + value + '" with single-ticks?',
            csp.Finding.Severity.SYNTAX, directive, value));
        continue;
      }

      // Continue, if the value doesn't start with single tick.
      // All CSP keywords start with a single tick.
      if (!value.startsWith("'")) {
        continue;
      }

      if (directive == csp.Directive.REQUIRE_TRUSTED_TYPES_FOR) {
        // Continue, if it's an allowed Trusted Types sink.
        if (value == csp.TrustedTypesSink.SCRIPT) {
          continue;
        }
      } else if (directive == csp.Directive.TRUSTED_TYPES) {
        // Continue, if it's an allowed Trusted Types keyword.
        if (directive == csp.Directive.TRUSTED_TYPES &&
            value == '\'allow-duplicates\'') {
          continue;
        }
      } else {
        // Continue, if it's a valid keyword.
        if (csp.isKeyword(value) || csp.isHash(value) || csp.isNonce(value)) {
          continue;
        }
      }

      findings.push(new csp.Finding(
          csp.Finding.Type.INVALID_KEYWORD,
          value + ' seems to be an invalid CSP keyword.',
          csp.Finding.Severity.SYNTAX, directive, value));
    }
  }

  return findings;
};

//TODO(user): Add check for NON_ASCII_CHAR
