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
 * @fileoverview Collection of "strict" CSP and backward compatibility checks.
 * A "strict" CSP is based on nonces or hashes and drops the whitelist.
 * These checks ensure that 'strict-dynamic' and a CSP nonce/hash are present.
 * Due to 'strict-dynamic' any whitelist will get dropped in CSP3.
 * The backward compatibility checks ensure that the strict nonce/hash based CSP
 * will be a no-op in older browsers by checking for presence of 'unsafe-inline'
 * (will be dropped in newer browsers if a nonce or hash is present) and for
 * prsensence of http: and https: url schemes (will be droped in the presence of
 * 'strict-dynamic' in newer browsers).
 *
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.strictcspChecks');

goog.require('csp');
goog.require('csp.Finding');
goog.require('csp.Keyword');
goog.require('goog.array');
goog.require('goog.string');


/**
 * Checks if 'strict-dynamic' is present.
 *
 * Example policy where this check would trigger:
 *  script-src foo.bar
 *
 * @param {!csp.Csp} parsedCsp A parsed csp.
 * @return {!Array.<!csp.Finding>}
 */
csp.strictcspChecks.checkStrictDynamic = function(parsedCsp) {
  var directiveName =
      csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.SCRIPT_SRC);
  var values = parsedCsp[directiveName] || [];

  var schemeOrHostPresent = goog.array.some(values, v => !v.startsWith('\''));

  // Check if strict-dynamic is present in case a host/scheme whitelist is used.
  if (schemeOrHostPresent &&
      !goog.array.contains(values, csp.Keyword.STRICT_DYNAMIC)) {
    return [new csp.Finding(
        csp.Finding.Type.STRICT_DYNAMIC,
        'Host whitelists can frequently be bypassed. Consider using ' +
        '\'strict-dynamic\' in combination with CSP nonces or hashes.',
        csp.Finding.Severity.STRICT_CSP, directiveName)];
  }

  return [];
};


/**
 * Checks if 'strict-dynamic' is only used together with a nonce or a hash.
 *
 * Example policy where this check would trigger:
 *  script-src 'strict-dynamic'
 *
 * @param {!csp.Csp} parsedCsp A parsed csp.
 * @return {!Array.<!csp.Finding>}
 */
csp.strictcspChecks.checkStrictDynamicNotStandalone = function(parsedCsp) {
  var directiveName =
      csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.SCRIPT_SRC);
  var values = parsedCsp[directiveName] || [];

  if (goog.array.contains(values, csp.Keyword.STRICT_DYNAMIC) &&
      (!csp.Csp.policyHasScriptNonces(parsedCsp) &&
       !csp.Csp.policyHasScriptHashes(parsedCsp))) {
    return [new csp.Finding(
        csp.Finding.Type.STRICT_DYNAMIC_NOT_STANDALONE,
        '\'strict-dynamic\' without a CSP nonce/hash will block all scripts.',
        csp.Finding.Severity.INFO, directiveName)];
  }

  return [];
};


/**
 * Checks if the policy has 'unsafe-inline' when a nonce or hash are present.
 * This will ensure backward compatibility to browser that don't support
 * CSP nonces or hasehs.
 *
 * Example policy where this check would trigger:
 *  script-src 'nonce-test'
 *
 * @param {!csp.Csp} parsedCsp A parsed csp.
 * @return {!Array.<!csp.Finding>}
 */
csp.strictcspChecks.checkUnsafeInlineFallback = function(parsedCsp) {
  if (!csp.Csp.policyHasScriptNonces(parsedCsp) &&
      !csp.Csp.policyHasScriptHashes(parsedCsp)) {
    return [];
  }

  var directiveName =
      csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.SCRIPT_SRC);
  var values = parsedCsp[directiveName] || [];

  if (!goog.array.contains(values, csp.Keyword.UNSAFE_INLINE)) {
    return [new csp.Finding(
        csp.Finding.Type.UNSAFE_INLINE_FALLBACK,
        'Consider adding \'unsafe-inline\' (ignored by browsers supporting ' +
        'nonces/hashes) to be backward compatible with older browsers.',
        csp.Finding.Severity.STRICT_CSP, directiveName)];
  }

  return [];
};


/**
 * Checks if the policy has whitelist fallback (* or http: and https:) when a
 * 'strict-dynamic' is present.
 * This will ensure backward compatibility to browser that don't support
 * 'strict-dynamic'.
 *
 * Example policy where this check would trigger:
 *  script-src 'nonce-test' 'strict-dynamic'
 *
 * @param {!csp.Csp} parsedCsp A parsed csp.
 * @return {!Array.<!csp.Finding>}
 */
csp.strictcspChecks.checkWhitelistFallback = function(parsedCsp) {
  var directiveName =
      csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.SCRIPT_SRC);
  var values = parsedCsp[directiveName] || [];

  if (!goog.array.contains(values, csp.Keyword.STRICT_DYNAMIC)) {
    return [];
  }

  // Check if there's already a whitelist (url scheme or url)
  if (!goog.array.some(values, v => (
        goog.array.contains(['http:', 'https:', '*'], v) ||
        goog.string.contains(v, '.')))) {
    return [new csp.Finding(
        csp.Finding.Type.WHITELIST_FALLBACK,
        'Consider adding https: and http: url schemes (ignored by browsers ' +
        'supporting \'strict-dynamic\') to be backward compatible with older ' +
        'browsers.',
        csp.Finding.Severity.STRICT_CSP, directiveName)];
  }

  return [];
};

