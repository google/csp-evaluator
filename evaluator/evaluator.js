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
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.CspEvaluator');

goog.require('csp');
goog.require('csp.parserChecks');
goog.require('csp.securityChecks');
goog.require('csp.strictcspChecks');

goog.require('goog.debug.Console');
goog.require('goog.log');



/**
 * A class to hold a CSP Evaluator.
 * Evaluates a parsed CSP and reports security findings.
 *
 * @constructor
 * @param {!csp.Csp} parsedCsp A parsed Content Security Policy.
 * @param {!csp.Version=} opt_cspVersion CSP version to apply checks for.
 * @export
 */
csp.CspEvaluator = function(parsedCsp, opt_cspVersion) {
  goog.debug.Console.autoInstall();
  /** @private {?goog.debug.Logger} */
  this.logger_ = goog.log.getLogger('csp.CspEvaluator');

  /**
   * CSP version.
   * @type {!csp.Version}
   */
  this.version = opt_cspVersion || csp.Version.CSP3;

  /**
   * Parsed CSP.
   * @type {!csp.Csp}
   */
  this.csp = parsedCsp;

  /** List of findings reported by checks.
   *
   * @type {!Array.<!csp.Finding>}
   */
  this.findings = [];
};


/**
 * Set of default checks to run.
 * @type {!Array.<!function(!csp.Csp):!Array.<!csp.Finding>>}
 */
csp.CspEvaluator.DEFAULT_CHECKS = [
    csp.securityChecks.checkScriptUnsafeInline,
    csp.securityChecks.checkScriptUnsafeEval,
    csp.securityChecks.checkPlainUrlSchemes,
    csp.securityChecks.checkWildcards,
    csp.securityChecks.checkMissingDirectives,
    csp.securityChecks.checkScriptWhitelistBypass,
    csp.securityChecks.checkFlashObjectWhitelistBypass,
    csp.securityChecks.checkIpSource,
    csp.securityChecks.checkNonceLength,
    csp.securityChecks.checkSrcHttp,
// TODO(user): re-enable this check when report-to becomes relevant.
//  csp.securityChecks.checkDeprecatedDirective,
    csp.parserChecks.checkUnknownDirective,
    csp.parserChecks.checkMissingSemicolon,
    csp.parserChecks.checkInvalidKeyword
];


/**
 * Strict CSP and backward compatibility checks.
 * @type {!Array.<!function(!csp.Csp):!Array.<!csp.Finding>>}
 */
csp.CspEvaluator.STRICTCSP_CHECKS = [
    csp.strictcspChecks.checkStrictDynamic,
    csp.strictcspChecks.checkStrictDynamicNotStandalone,
    csp.strictcspChecks.checkUnsafeInlineFallback,
    csp.strictcspChecks.checkWhitelistFallback
];


/**
 * Evaluates a parsed CSP against a set of checks
 * @param {!Array.<!function(!csp.Csp):!Array.<!csp.Finding>>=}
 *   opt_parsedCspChecks list of checks to run on the parsed CSP (i.e. checks
 *     like backward compatibility checks, which are independent of the actual
 *     CSP version).
 * @param {!Array.<!function(!csp.Csp):!Array.<!csp.Finding>>=}
 *   opt_effectiveCspChecks list of checks to run on the effective CSP.
 * @return {!Array.<!csp.Finding>} List of Findings.
 * @export
 */
csp.CspEvaluator.prototype.evaluate = function(
  opt_parsedCspChecks, opt_effectiveCspChecks) {
  this.findings = [];
  var checks = opt_effectiveCspChecks || csp.CspEvaluator.DEFAULT_CHECKS;

  // We're applying checks on the policy as it would be seen by a browser
  // supporting a specific version of CSP.
  // For example a browser supporting only CSP1 will ignore nonces and therefore
  // 'unsafe-inline' would not get ignored if a policy has nonces.
  var effectiveCsp = csp.Csp.getEffectiveCsp(
      this.csp, this.version, this.findings);

  // Checks independent of CSP version.
  if (opt_parsedCspChecks) {
    for (let check of opt_parsedCspChecks) {
      this.findings = this.findings.concat(check(this.csp));
    }
  }

  // Checks depenent on CSP version.
  for (let check of checks) {
    this.findings = this.findings.concat(check(effectiveCsp));
  }

  return this.findings;
};
