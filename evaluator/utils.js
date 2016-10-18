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
 * @fileoverview Utils for CSP evaluator.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.utils');

goog.require('goog.object');
goog.require('goog.string');


/**
 * Removes scheme from url.
 * @param {string} url Url.
 * @return {string} url without scheme.
 */
csp.utils.getSchemeFreeUrl = function(url) {
  url = url.replace(/^\w[+\w.-]*:\/\//i, '');  // Remove URI scheme.
  url = url.replace(/^\/\//, '');              // Remove protocol agnostic "//"
  return url;
};


/**
 * Searches for whitelisted CSP origin (URL with wildcards) in list of urls.
 * @param {!goog.Uri} cspUrl The whitelisted CSP origin. Can contain domain and
 *   path wildcards.
 * @param {!Array<!goog.Uri>} listOfUrls List of urls to search in.
 * @return {?goog.Uri} First match found in url list, null otherwise.
 */
csp.utils.matchWildcardUrls = function(cspUrl, listOfUrls) {
  var host = cspUrl.getDomain().toLowerCase();
  var hostHasWildcard = goog.string.startsWith(host, '*.');
  var wildcardFreeHost = host.replace(/^\*/i, '');
  var path = cspUrl.getPath();
  var hasPath = cspUrl.hasPath();

  for (let url of listOfUrls) {
    var domain = url.getDomain();
    if (!goog.string.endsWith(domain, wildcardFreeHost)) {
      continue;  // Urls don't match.
    }

    // If the host has no subdomain wildcard and doesn't match, continue.
    if (!hostHasWildcard && host != domain) {
      continue;
    }

    // If the whitelisted url has a path, check if on of the url paths match.
    if (hasPath) {
      // https://www.w3.org/TR/CSP2/#source-list-path-patching
      if (goog.string.endsWith(path, '/')) {
        if (!goog.string.startsWith(url.getPath(), path)) {
          continue;  // Path wildcard doesn't match.
        }
      } else {
        if (url.getPath() != path) {
          continue;  // Path doesn't match.
        }
      }
    }

    // We found a match.
    return url;
  }

  // No match was found.
  return null;
};


/**
 * Applies a check to all directive values of a csp.
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @param {!function(!string,!Array<string>)} check The check function that
 *   should get applied on directive values.
 * @param {!Array<string>=} opt_directives Directives to check. All directives
 *   will be checked if not provided.
 */
csp.utils.applyCheckFunktionToDirectives = function(
    parsedCsp, check, opt_directives) {
  var directiveNames = opt_directives || goog.object.getKeys(parsedCsp);

  for (let directive of directiveNames) {
    var directiveValues = parsedCsp[directive];
    if (directiveValues) {
      check(directive, directiveValues);
    }
  }
};
