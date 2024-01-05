/**
 * @fileoverview Enforce CSP definitions and helper functions.
 * @author mnadeau@gosecure.net (Maxime Nadeau)
 *
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
 */


import {Csp, Directive, Keyword, Version, isHash, isNonce} from './csp';
import { Finding, Severity, Type } from './finding';

/**
 * Enforced Content Security Policy object.
 *  - https://www.w3.org/TR/CSP2/#enforcing-multiple-policies
 */
export class EnforcedCsps extends Array<Csp> {
  /**
   * Clones a CSP object.
   * @return clone of parsedCsp.
   */
  clone(): EnforcedCsps {
    const clone = new EnforcedCsps();
    for (const csp of this) {
        clone.push(csp.clone());
    }

    return clone;
  }

  /**
   * Converts the enforced CSPs back into a string array.
   * @return The list of CSP string.
   */
  convertToStrings(): string[] {
    const retString: string[] = [];
    
    for (const appliedCsp of this) {
        retString.push(appliedCsp.convertToString());
    }

    return retString;
  }

  /**
   * Returns the passed directive if present in this CSP or default-src
   * otherwise.
   * @param directive The CSP directive to look for.
   * @return The effective directive.
   */
  getEffectiveDirective(directive: string): string {
    // Look in each CSP to find the directive
    for (const csp of this) {
        if (directive in csp.directives) {
          return directive;
        }
    }

    return Directive.DEFAULT_SRC;
  }

  /**
   * Returns CSP as it would be seen by a UA supporting a specific CSP version.
   * @param cspVersion CSP.
   * @param optFindings findings about ignored directive values will be added
   *     to this array, if passed. (e.g. CSP2 ignores 'unsafe-inline' in
   *     presence of a nonce or a hash)
   * @return The effective CSP.
   */
  getEffectiveCsps(cspVersion: Version, optFindings?: Finding[]): EnforcedCsps {
    const findings = optFindings || [];
    const effectiveCsps = this.clone();
    const directive = effectiveCsps.getEffectiveDirective(Directive.SCRIPT_SRC);

    for (let index = 0; index < effectiveCsps.length; index++) {
        const values = this[index].directives[directive] || [];
        const effectiveCspValues = effectiveCsps[index].directives[directive];

        if (effectiveCspValues &&
            (effectiveCsps[index].policyHasScriptNonces() ||
             effectiveCsps[index].policyHasScriptHashes())) {
          if (cspVersion >= Version.CSP2) {
            // Ignore 'unsafe-inline' in CSP >= v2, if a nonce or a hash is present.
            if (values.includes(Keyword.UNSAFE_INLINE)) {
              arrayRemove(effectiveCspValues, Keyword.UNSAFE_INLINE);
              findings.push(new Finding(
                  Type.IGNORED,
                  'unsafe-inline is ignored if a nonce or a hash is present. ' +
                      '(CSP2 and above)',
                  Severity.NONE, directive, Keyword.UNSAFE_INLINE));
            }
          } else {
            // remove nonces and hashes (not supported in CSP < v2).
            for (const value of values) {
              if (value.startsWith('\'nonce-') || value.startsWith('\'sha')) {
                arrayRemove(effectiveCspValues, value);
              }
            }
          }
        }

        if (effectiveCspValues && this[index].policyHasStrictDynamic()) {
          // Ignore allowlist in CSP >= v3 in presence of 'strict-dynamic'.
          if (cspVersion >= Version.CSP3) {
            for (const value of values) {
              // Because of 'strict-dynamic' all host-source and scheme-source
              // expressions, as well as the "'unsafe-inline'" and "'self'
              // keyword-sources will be ignored.
              // https://w3c.github.io/webappsec-csp/#strict-dynamic-usage
              if (!value.startsWith('\'') || value === Keyword.SELF ||
                  value === Keyword.UNSAFE_INLINE) {
                arrayRemove(effectiveCspValues, value);
                findings.push(new Finding(
                    Type.IGNORED,
                    'Because of strict-dynamic this entry is ignored in CSP3 and above',
                    Severity.NONE, directive, value));
              }
            }
          } else {
            // strict-dynamic not supported.
            arrayRemove(effectiveCspValues, Keyword.STRICT_DYNAMIC);
          }
        }

        if (cspVersion < Version.CSP3) {
            // Remove CSP3 directives from pre-CSP3 policies.
            // https://w3c.github.io/webappsec-csp/#changes-from-level-2
            delete effectiveCsps[index].directives[Directive.REPORT_TO];
            delete effectiveCsps[index].directives[Directive.WORKER_SRC];
            delete effectiveCsps[index].directives[Directive.MANIFEST_SRC];
            delete effectiveCsps[index].directives[Directive.TRUSTED_TYPES];
            delete effectiveCsps[index].directives[Directive.REQUIRE_TRUSTED_TYPES_FOR];
        }
    }

    return effectiveCsps;
  }

  /**
   * Checks if this CSP is using nonces for scripts.
   * @return true, if this CSP is using script nonces.
   */
  policyHasScriptNonces(): boolean {
    const directiveName = this.getEffectiveDirective(Directive.SCRIPT_SRC);

    for (const csp of this) {
        const values = csp.directives[directiveName] || [];
        if (values.some((val) => isNonce(val))) {
            return true;
        }
    }

    return false;
  }

  /**
   * Checks if this CSP is using hashes for scripts.
   * @return true, if this CSP is using script hashes.
   */
  policyHasScriptHashes(): boolean {
    const directiveName = this.getEffectiveDirective(Directive.SCRIPT_SRC);

    for (const csp of this) {
        const values = csp.directives[directiveName] || [];
        if (values.some((val) => isHash(val))) {
            return true;
        }
    }

    return false;
  }

  /**
   * Checks if this CSP is using strict-dynamic.
   * @return true, if this CSP is using CSP nonces.
   */
  policyHasStrictDynamic(): boolean {
    const directiveName = this.getEffectiveDirective(Directive.SCRIPT_SRC);

    for (const csp of this) {
        const values = csp.directives[directiveName] || [];
        if (values.includes(Keyword.STRICT_DYNAMIC)) {
            return true;
        }
    }

    return false;
  }
}

/**
 * Mutate the given array to remove the first instance of the given item
 */
function arrayRemove<T>(arr: T[], item: T): void {
  if (arr.includes(item)) {
    const idx = arr.findIndex(elem => item === elem);
    arr.splice(idx, 1);
  }
}
