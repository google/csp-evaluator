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

goog.provide('csp.Finding');



/**
 * A CSP Finding is returned by a CSP check and can either reference a directive
 * value or a directive. If a directive value is referenced opt_index must be
 * provided.
 *
 * @constructor
 * @param {!csp.Finding.Type} type Type of the finding.
 * @param {string} description Description of the finding.
 * @param {!csp.Finding.Severity} severity Severity of the finding.
 * @param {string} directive The CSP directive in which the
 *    finding occurred.
 * @param {string=} opt_value The directive value, if exists.
 */
csp.Finding = function(type, description, severity, directive, opt_value) {
  /** @type {!csp.Finding.Type} */
  this.type = type;

  /** @type {string} */
  this.description = description;

  /** @type {!csp.Finding.Severity} */
  this.severity = severity;

  /** @type {string} */
  this.directive = directive;

  /** @type {string|undefined} */
  this.value = opt_value;
};


/**
 * Finding severities.
 * @enum {number}
 */
csp.Finding.Severity = {
  HIGH: 10,
  SYNTAX: 20,
  MEDIUM: 30,
  HIGH_MAYBE: 40,
  STRICT_CSP: 45,
  MEDIUM_MAYBE: 50,
  INFO: 60,
  NONE: 100
};


/**
 * Finding types for evluator checks.
 * @enum {number}
 */
// LINT.IfChange
csp.Finding.Type = {
  // Parser checks
  MISSING_SEMICOLON: 100,
  UNKNOWN_DIRECTIVE: 101,
  INVALID_KEYWORD: 102,

  // Security cheks
  MISSING_DIRECTIVES: 300,
  SCRIPT_UNSAFE_INLINE: 301,
  SCRIPT_UNSAFE_EVAL: 302,
  PLAIN_URL_SCHEMES: 303,
  PLAIN_WILDCARD: 304,
  SCRIPT_WHITELIST_BYPASS: 305,
  OBJECT_WHITELIST_BYPASS: 306,
  NONCE_LENGTH: 307,
  IP_SOURCE: 308,
  DEPRECATED_DIRECTIVE: 309,
  SRC_HTTP: 310,

  // Strict dynamic and backward compatibility checks
  STRICT_DYNAMIC: 400,
  STRICT_DYNAMIC_NOT_STANDALONE: 401,
  NONCE_HASH: 402,
  UNSAFE_INLINE_FALLBACK: 403,
  WHITELIST_FALLBACK: 404,
  IGNORED: 405
};


/**
 * Returns the highest severity of a list of findings.
 * @param {!Array.<!csp.Finding>} findings List of findings.
 * @return {!csp.Finding.Severity} highest severity of a list of findings.
 */
csp.Finding.getHighestSeverity = function(findings) {
  if (goog.array.isEmpty(findings)) {
    return csp.Finding.Severity.NONE;
  }

  var severities = goog.array.map(findings, finding => finding.severity);
  var min = (prev, cur) => prev < cur ? prev : cur;
  return goog.array.reduce(severities, min, csp.Finding.Severity.NONE);
};
