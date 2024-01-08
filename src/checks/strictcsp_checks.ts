/**
 * @fileoverview Collection of "strict" CSP and backward compatibility checks.
 * A "strict" CSP is based on nonces or hashes and drops the allowlist.
 * These checks ensure that 'strict-dynamic' and a CSP nonce/hash are present.
 * Due to 'strict-dynamic' any allowlist will get dropped in CSP3.
 * The backward compatibility checks ensure that the strict nonce/hash based CSP
 * will be a no-op in older browsers by checking for presence of 'unsafe-inline'
 * (will be dropped in newer browsers if a nonce or hash is present) and for
 * prsensence of http: and https: url schemes (will be droped in the presence of
 * 'strict-dynamic' in newer browsers).
 *
 * @author lwe@google.com (Lukas Weichselbaum)
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

import {Csp, Directive, Keyword, TrustedTypesSink} from '../csp';
import {Finding, Severity, Type} from '../finding';

/**
 * Checks if 'strict-dynamic' is present.
 *
 * Example policy where this check would trigger:
 *  script-src foo.bar
 *
 * @param parsedCsp A parsed csp.
 */
export function checkStrictDynamic(parsedCsps: Csp): Finding[] {
  const directiveName = parsedCsps.getEffectiveDirective(Directive.SCRIPT_SRC);
  const findings: Finding[] = [];

  for (const currentCsp of parsedCsps.directives) {
    const values: string[] = currentCsp[directiveName] || [];

    const schemeOrHostPresent = values.some(v => !v.startsWith("'"));

    // Check if strict-dynamic is present in case a host/scheme allowlist is used.
    if (schemeOrHostPresent && !values.includes(Keyword.STRICT_DYNAMIC)) {
      findings.push(
        new Finding(
          Type.STRICT_DYNAMIC,
          'Host allowlists can frequently be bypassed. Consider using ' +
            "'strict-dynamic' in combination with CSP nonces or hashes.",
          Severity.STRICT_CSP,
          directiveName
        )
      );
    }
  }

  return findings;
}

/**
 * Checks if 'strict-dynamic' is only used together with a nonce or a hash.
 *
 * Example policy where this check would trigger:
 *  script-src 'strict-dynamic'
 *
 * @param parsedCsp A parsed csp.
 */
export function checkStrictDynamicNotStandalone(parsedCsps: Csp): Finding[] {
  const directiveName = parsedCsps.getEffectiveDirective(Directive.SCRIPT_SRC);

  if (
    parsedCsps.policyHasStrictDynamic() &&
    !parsedCsps.policyHasScriptNonces() &&
    !parsedCsps.policyHasScriptHashes()
  ) {
    return [
      new Finding(
        Type.STRICT_DYNAMIC_NOT_STANDALONE,
        "'strict-dynamic' without a CSP nonce/hash will block all scripts.",
        Severity.INFO,
        directiveName
      ),
    ];
  }

  return [];
}

/**
 * Checks if the policy has 'unsafe-inline' when a nonce or hash are present.
 * This will ensure backward compatibility to browser that don't support
 * CSP nonces or hasehs.
 *
 * Example policy where this check would trigger:
 *  script-src 'nonce-test'
 *
 * @param parsedCsp A parsed csp.
 */
export function checkUnsafeInlineFallback(parsedCsps: Csp): Finding[] {
  if (
    !parsedCsps.policyHasScriptNonces() &&
    !parsedCsps.policyHasScriptHashes()
  ) {
    return [];
  }

  const directiveName = parsedCsps.getEffectiveDirective(Directive.SCRIPT_SRC);
  const findings: Finding[] = [];

  for (const currentCsp of parsedCsps.directives) {
    const values: string[] = currentCsp[directiveName] || [];

    if (!values.includes(Keyword.UNSAFE_INLINE)) {
      findings.push(
        new Finding(
          Type.UNSAFE_INLINE_FALLBACK,
          "Consider adding 'unsafe-inline' (ignored by browsers supporting " +
            'nonces/hashes) to be backward compatible with older browsers.',
          Severity.STRICT_CSP,
          directiveName
        )
      );
    }
  }

  return findings;
}

/**
 * Checks if the policy has an allowlist fallback (* or http: and https:) when
 * 'strict-dynamic' is present.
 * This will ensure backward compatibility to browser that don't support
 * 'strict-dynamic'.
 *
 * Example policy where this check would trigger:
 *  script-src 'nonce-test' 'strict-dynamic'
 *
 * @param parsedCsp A parsed csp.
 */
export function checkAllowlistFallback(parsedCsps: Csp): Finding[] {
  const directiveName = parsedCsps.getEffectiveDirective(Directive.SCRIPT_SRC);
  const findings: Finding[] = [];

  for (const currentCsp of parsedCsps.directives) {
    const values: string[] = currentCsp[directiveName] || [];

    if (!values.includes(Keyword.STRICT_DYNAMIC)) {
      return [];
    }

    // Check if there's already an allowlist (url scheme or url)
    if (
      !values.some(v => ['http:', 'https:', '*'].includes(v) || v.includes('.'))
    ) {
      findings.push(
        new Finding(
          Type.ALLOWLIST_FALLBACK,
          'Consider adding https: and http: url schemes (ignored by browsers ' +
            "supporting 'strict-dynamic') to be backward compatible with older " +
            'browsers.',
          Severity.STRICT_CSP,
          directiveName
        )
      );
    }
  }

  return findings;
}

/**
 * Checks if the policy requires Trusted Types for scripts.
 *
 * I.e. the policy should have the following dirctive:
 *  require-trusted-types-for 'script'
 *
 * @param parsedCsp A parsed csp.
 */
export function checkRequiresTrustedTypesForScripts(
  parsedCsps: Csp
): Finding[] {
  const directiveName = parsedCsps.getEffectiveDirective(
    Directive.REQUIRE_TRUSTED_TYPES_FOR
  );
  for (const cspChecked of parsedCsps.directives) {
    const values: string[] = cspChecked[directiveName] || [];

    if (values.includes(TrustedTypesSink.SCRIPT)) {
      return [];
    }
  }

  return [
    new Finding(
      Type.REQUIRE_TRUSTED_TYPES_FOR_SCRIPTS,
      'Consider requiring Trusted Types for scripts to lock down DOM XSS ' +
        'injection sinks. You can do this by adding ' +
        '"require-trusted-types-for \'script\'" to your policy.',
      Severity.INFO,
      Directive.REQUIRE_TRUSTED_TYPES_FOR
    ),
  ];
}
