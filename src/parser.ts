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

import {Csp, isKeyword, isUrlScheme} from './csp';
import {mergeCspHeaders} from './utils';

/**
 * A class to hold a parser for CSP in string format.
 * @unrestricted
 */
export class CspParser {
  csp: Csp;

  /**
   * @param unparsedCsp A Content Security Policy as string.
   */
  constructor(unparsedCsps: string | string[]) {
    /**
     * Parsed CSP
     */
    this.csp = new Csp();

    if (Array.isArray(unparsedCsps)) {
      unparsedCsps = mergeCspHeaders(unparsedCsps);
    }

    this.parse(unparsedCsps);
  }

  /**
   * Parses a CSP from a string.
   * @param unparsedCsp CSP as string.
   */
  parse(unparsedCsp: string): Csp {
    unparsedCsp.split(', ').forEach(currentCsp => {
      this.csp.directives.push(this.parseCsp(currentCsp));
    });

    return this.csp;
  }

  parseCsp(unparsedCsp: string): Record<string, string[] | undefined> {
    const retCspDirectives: Record<string, string[] | undefined> = {};

    // For each token returned by strictly splitting serialized on the U+003B SEMICOLON character (;):
    const directiveTokens = unparsedCsp.split(';');
    for (let i = 0; i < directiveTokens.length; i++) {
      // Strip leading and trailing ASCII whitespace from token.
      const directiveToken = directiveTokens[i].trim();

      // If token is an empty string, or if token is not an ASCII string, continue.
      /* eslint-disable no-control-regex */
      if (directiveToken === '' || !/^[\x00-\xFF]*$/.test(directiveToken)) {
        continue;
      }
      /* eslint-enable no-control-regex */

      // Let directive name be the result of collecting a sequence of code points from token which are not ASCII whitespace.
      // Let directive value be the result of splitting token on ASCII whitespace.
      const directiveParts = directiveToken.match(/\S+/g);
      if (Array.isArray(directiveParts)) {
        // Set directive name to be the result of running ASCII lowercase on directive name.
        const directiveName = directiveParts[0].toLowerCase();

        // If policy’s directive set contains a directive whose name is directive name, continue.
        if (directiveName in retCspDirectives) {
          continue;
        }

        const directiveValues: string[] = [];
        for (
          let directiveValue, j = 1;
          (directiveValue = directiveParts[j]);
          j++
        ) {
          // Let directive be a new directive whose name is directive name, and value is directive value.
          directiveValue = normalizeDirectiveValue(directiveValue);
          if (!directiveValues.includes(directiveValue)) {
            directiveValues.push(directiveValue);
          }
        }

        // Append directive to policy’s directive set.
        retCspDirectives[directiveName] = directiveValues;
      }
    }

    // Return policy.
    return retCspDirectives;
  }
}

/**
 * Remove whitespaces and turn to lower case if CSP keyword or protocol
 * handler.
 * @param directiveValue directive value.
 * @return normalized directive value.
 */
function normalizeDirectiveValue(directiveValue: string): string {
  directiveValue = directiveValue.trim();
  const directiveValueLower = directiveValue.toLowerCase();
  if (isKeyword(directiveValueLower) || isUrlScheme(directiveValue)) {
    return directiveValueLower;
  }
  return directiveValue;
}

export const TEST_ONLY = {normalizeDirectiveValue};
