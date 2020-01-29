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

goog.provide('csp.CspParser');

goog.require('csp');
goog.require('csp.Csp');
goog.require('goog.array');
goog.require('goog.debug.Console');
goog.require('goog.log');



/**
 * A class to hold a parser for CSP in string format.
 * TODO: Extend parser to detect common syntax and semantic errors in CSPs.
 *
 * @constructor
 * @param {string} unparsedCsp A Content Security Policy as string.
 */
csp.CspParser = function(unparsedCsp) {
  goog.debug.Console.autoInstall();

  /** @private {?goog.debug.Logger} */
  this.logger_ = goog.log.getLogger('csp.CspParser');

  /** Parsed CSP
   * @type {!csp.Csp}
   */
  this.csp = new csp.Csp();

  this.parse(unparsedCsp);
};


/**
 * Parses a CSP from a string.
 * @param {string} unparsedCsp CSP as string.
 * @return {!csp.Csp}
 */
csp.CspParser.prototype.parse = function(unparsedCsp) {
  this.csp = new csp.Csp();  // reset

  goog.log.info(this.logger_, 'Parsing: ' + unparsedCsp);

  // Split CSP into directive tokens.
  var directiveTokens = unparsedCsp.split(';');
  for (var i = 0; i < directiveTokens.length; i++) {
    var directiveToken = directiveTokens[i].trim();

    // Split directive tokens into directive name and directive values.
    var directiveParts = directiveToken.match(/\S+/g);
    if (goog.isArray(directiveParts)) {
      var directiveName = directiveParts[0].toLowerCase();

      // Cannot use `in` with structs... bypass this check.
      var /** ? */ any = this.csp;

      // If the set of directives already contains a directive whose name is a
      // case insensitive match for directive name, ignore this instance of the
      // directive and continue to the next token.
      if (directiveName in any) {
        // TODO(user): propagate this information to the UI.
        goog.log.warning(
            this.logger_, 'Duplicate directive detected: ' + directiveName);
        continue;
      }

      if (!csp.isDirective(directiveName)) {
        // TODO(user): propagate this information to the UI.
        goog.log.warning(
            this.logger_, 'Invalid directive detected: ' + directiveName);
      }

      this.csp[directiveName] = [];
      for (var directiveValue, j = 1; directiveValue = directiveParts[j]; j++) {
        directiveValue = csp.CspParser.normalizeDirectiveValue_(directiveValue);
        goog.array.insert(this.csp[directiveName], directiveValue);
      }
    }
  }

  return this.csp;
};


/**
 * Remove whitespaces and turn to lower case if CSP keyword or protocol handler.
 * @param {string} directiveValue directive value.
 * @return {string} normalized directive value.
 * @private
 */
csp.CspParser.normalizeDirectiveValue_ = function(directiveValue) {
  directiveValue = directiveValue.trim();
  var directiveValueLower = directiveValue.toLowerCase();
  if (csp.isKeyword(directiveValueLower) ||
      csp.isUrlScheme(directiveValue)) {
    return directiveValueLower;
  }
  return directiveValue;
};
