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
 * @fileoverview Collection of CSP evaluation checks.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.securityChecks');

goog.require('csp');
goog.require('csp.Directive');
goog.require('csp.Finding');
goog.require('csp.Keyword');
goog.require('csp.utils');
goog.require('csp.whitelistBypasses.angular');
goog.require('csp.whitelistBypasses.flash');
goog.require('csp.whitelistBypasses.jsonp');
goog.require('goog.Uri');
goog.require('goog.array');
goog.require('goog.net.IpAddress');
goog.require('goog.string');


/**
 * @type {!Array.<string>}
 */
csp.securityChecks.DIRECTIVES_CAUSING_XSS =
    [csp.Directive.SCRIPT_SRC,
     csp.Directive.OBJECT_SRC,
     csp.Directive.BASE_URI];


/**
 * @type {!Array.<string>}
 */
csp.securityChecks.URL_SCHEMES_CAUSING_XSS = ['data:', 'http:', 'https:'];


/**
 * Checks if passed csp allows inline scripts.
 * Findings of this check are critical and FP free.
 * unsafe-inline is ignored in the presence of a nonce or a hash. This check
 * does not account for this and therefore the effectiveCsp needs to be passed.
 *
 * Example policy where this check would trigger:
 *  script-src 'unsafe-inline'
 *
 * @param {!csp.Csp} effectiveCsp A parsed csp that only contains values which
 *  are active in a certain version of CSP (e.g. no unsafe-inline if a nonce
 *  is present).
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkScriptUnsafeInline = function(effectiveCsp) {
  var directiveName =
      csp.Csp.getEffectiveDirective(effectiveCsp, csp.Directive.SCRIPT_SRC);
  var values = effectiveCsp[directiveName] || [];

  // Check if unsafe-inline is present.
  if (goog.array.contains(values, csp.Keyword.UNSAFE_INLINE)) {
    return [new csp.Finding(
        csp.Finding.Type.SCRIPT_UNSAFE_INLINE,
        '\'unsafe-inline\' allows the execution of unsafe in-page scripts ' +
        'and event handlers.',
        csp.Finding.Severity.HIGH, directiveName, csp.Keyword.UNSAFE_INLINE)];
  }

  return [];
};


/**
 * Checks if passed csp allows eval in scripts.
 * Findings of this check have a medium severity and are FP free.
 *
 * Example policy where this check would trigger:
 *  script-src 'unsafe-eval'
 *
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkScriptUnsafeEval = function(parsedCsp) {
  var directiveName =
      csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.SCRIPT_SRC);
  var values = parsedCsp[directiveName] || [];

  // Check if unsafe-eval is present.
  if (goog.array.contains(values, csp.Keyword.UNSAFE_EVAL)) {
    return [new csp.Finding(
        csp.Finding.Type.SCRIPT_UNSAFE_EVAL,
        '\'unsafe-eval\' allows the execution of code injected into DOM APIs ' +
        'such as eval().',
        csp.Finding.Severity.MEDIUM_MAYBE, directiveName,
        csp.Keyword.UNSAFE_EVAL)];
  }

  return [];
};


/**
 * Checks if plain URL schemes (e.g. http:) are allowed in sensitive directives.
 * Findings of this check have a high severity and are FP free.
 *
 * Example policy where this check would trigger:
 *  script-src https: http: data:
 *
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkPlainUrlSchemes = function(parsedCsp) {
  var violations = [];
  var directivesToCheck = csp.Csp.getEffectiveDirectives(
      parsedCsp, csp.securityChecks.DIRECTIVES_CAUSING_XSS);

  for (let directive of directivesToCheck) {
    var values = parsedCsp[directive] || [];
    for (let value of values) {
      if (goog.array.contains(
              csp.securityChecks.URL_SCHEMES_CAUSING_XSS, value)) {
        violations.push(new csp.Finding(
            csp.Finding.Type.PLAIN_URL_SCHEMES,
            value + ' URI in ' + directive + ' allows the execution of ' +
            'unsafe scripts.',
            csp.Finding.Severity.HIGH, directive, value));
      }
    }
  }

  return violations;
};


/**
 * Checks if csp contains wildcards in sensitive directives.
 * Findings of this check have a high severity and are FP free.
 *
 * Example policy where this check would trigger:
 *  script-src *
 *
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkWildcards = function(parsedCsp) {
  var violations = [];
  var directivesToCheck = csp.Csp.getEffectiveDirectives(
      parsedCsp, csp.securityChecks.DIRECTIVES_CAUSING_XSS);

  for (let directive of directivesToCheck) {
    var values = parsedCsp[directive] || [];
    for (let value of values) {
      var url = csp.utils.getSchemeFreeUrl(value);
      if (url == '*') {
        violations.push(new csp.Finding(
            csp.Finding.Type.PLAIN_WILDCARD,
            directive + ' should not allow \'*\' as source',
            csp.Finding.Severity.HIGH, directive, value));
        continue;
      }
    }
  }

  return violations;
};


/**
 * Checks if all necessary directives for preventing XSS are set.
 * Findings of this check have a high severity and are FP free.
 *
 * Example policy where this check would trigger:
 *  script-src 'none'
 *
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkMissingDirectives = function(parsedCsp) {
  var violations = [];
  var directivesCausingXss = csp.securityChecks.DIRECTIVES_CAUSING_XSS;

  // Cannot use `in` with structs... bypass this check.
  var /** ? */ any = parsedCsp;

  // If default-src is present, all missing directives will fallback to that.
  if (csp.Directive.DEFAULT_SRC in any) {
    var defaultSrcValues = parsedCsp[csp.Directive.DEFAULT_SRC];
    if (!(csp.Directive.OBJECT_SRC in any) &&
        !(goog.array.contains(defaultSrcValues, csp.Keyword.NONE))) {
      violations.push(new csp.Finding(
          csp.Finding.Type.MISSING_DIRECTIVES,
          'Can you restrict object-src to \'none\'?',
          csp.Finding.Severity.HIGH_MAYBE,
          csp.Directive.OBJECT_SRC));
    }
    if (csp.Directive.BASE_URI in any) {
      return violations;
    } else {
      // base-uri is not covered by default-src. It must be explicitly set.
      directivesCausingXss = [csp.Directive.BASE_URI];
    }
  }

  for (let directive of directivesCausingXss) {
    if (!(directive in any)) {
      var description = directive + ' directive is missing.';
      if (directive == csp.Directive.OBJECT_SRC) {
        description = 'Missing object-src allows the injection of plugins ' +
            'which can execute JavaScript. Can you set it to \'none\'?';
      } else if (directive == csp.Directive.BASE_URI) {
        if (!csp.Csp.policyHasScriptNonces(parsedCsp) &&
            !(csp.Csp.policyHasScriptHashes(parsedCsp) &&
              csp.Csp.policyHasStrictDynamic(parsedCsp))) {
          // Only nonce based CSPs and hash based (w. s-d) are affected by
          // missing base-uri.
          continue;
        }
        description = 'Missing base-uri allows the injection of base tags. ' +
            'They can be used to set the base URL for all relative (script) ' +
            'URLs to an attacker controlled domain. ' +
            'Can you set it to \'none\' or \'self\'?';
      }
      violations.push(new csp.Finding(
          csp.Finding.Type.MISSING_DIRECTIVES,
          description,
          csp.Finding.Severity.HIGH,
          directive));
    }
  }

  return violations;
};


/**
 * Checks if whitelisted origins are bypassable by JSONP/Angular endpoints.
 * High severity findings of this check are FP free.
 *
 * Example policy where this check would trigger:
 *  default-src 'none'; script-src www.google.com
 *
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkScriptWhitelistBypass = function(parsedCsp) {
  var violations = [];
  var effectiveScriptSrcDirective =
      csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.SCRIPT_SRC);
  var scriptSrcValues = parsedCsp[effectiveScriptSrcDirective] || [];
  if (goog.array.contains(scriptSrcValues, csp.Keyword.NONE)) {
    return violations;
  }

  for (let value of scriptSrcValues) {
    if (value == csp.Keyword.SELF) {
      violations.push(new csp.Finding(
          csp.Finding.Type.SCRIPT_WHITELIST_BYPASS,
          '\'self\' can be problematic if you host JSONP, Angular or user ' +
          'uploaded files.',
          csp.Finding.Severity.MEDIUM_MAYBE, effectiveScriptSrcDirective,
          value));
      continue;
    }

    // Ignore keywords, nonces and hashes (they start with a single quote).
    if (goog.string.startsWith(value, '\'')) {
      continue;
    }

    // Ignore standalone schemes and things that don't look like URLs (no dot).
    if (csp.isUrlScheme(value) || value.indexOf('.') == -1) {
      continue;
    }

    var url = new goog.Uri('//' + csp.utils.getSchemeFreeUrl(value));

    var angularBypass =
        csp.utils.matchWildcardUrls(url, csp.whitelistBypasses.angular.URLS);

    var jsonpBypass =
        csp.utils.matchWildcardUrls(url, csp.whitelistBypasses.jsonp.URLS);

    // Some JSONP bypasses only work in presence of unsafe-eval.
    if (jsonpBypass) {
      var evalRequired = goog.array.contains(
          csp.whitelistBypasses.jsonp.NEEDS_EVAL, jsonpBypass.getDomain());
      var evalPresent =
          goog.array.contains(scriptSrcValues, csp.Keyword.UNSAFE_EVAL);
      if (evalRequired && !evalPresent) {
        jsonpBypass = null;
      }
    }

    if (jsonpBypass || angularBypass) {
      var bypassDomain = '';
      var bypassTxt = '';
      if (jsonpBypass) {
        bypassDomain = jsonpBypass.getDomain();
        bypassTxt = ' JSONP endpoints';
      }
      if (angularBypass) {
        bypassDomain = angularBypass.getDomain();
        bypassTxt += goog.string.isEmptyOrWhitespace(bypassTxt) ? '' : ' and';
        bypassTxt += ' Angular libraries';
      }

      violations.push(new csp.Finding(
          csp.Finding.Type.SCRIPT_WHITELIST_BYPASS,
          bypassDomain + ' is known to host' + bypassTxt +
              ' which allow to bypass this CSP.',
          csp.Finding.Severity.HIGH, effectiveScriptSrcDirective, value));

    } else {
      violations.push(new csp.Finding(
          csp.Finding.Type.SCRIPT_WHITELIST_BYPASS,
          'No bypass found; make sure that this URL doesn\'t serve JSONP ' +
          'replies or Angular libraries.',
          csp.Finding.Severity.MEDIUM_MAYBE, effectiveScriptSrcDirective,
          value));
    }
  }

  return violations;
};


/**
 * Checks if whitelisted object-src origins are bypassable.
 * Findings of this check have a high severity and are FP free.
 *
 * Example policy where this check would trigger:
 *  default-src 'none'; object-src ajax.googleapis.com
 *
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkFlashObjectWhitelistBypass = function(parsedCsp) {
  var violations = [];
  var effectiveObjectSrcDirective =
      csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.OBJECT_SRC);
  var objectSrcValues = parsedCsp[effectiveObjectSrcDirective] || [];

  // If flash is not allowed in plugin-types, continue.
  var pluginTypes = parsedCsp[csp.Directive.PLUGIN_TYPES];
  if (pluginTypes &&
      !goog.array.contains(pluginTypes, 'application/x-shockwave-flash')) {
    return [];
  }

  for (let value of objectSrcValues) {
    // Nothing to do here if 'none'.
    if (value == csp.Keyword.NONE) {
      return [];
    }

    var url = new goog.Uri('//' + csp.utils.getSchemeFreeUrl(value));
    var flashBypass =
        csp.utils.matchWildcardUrls(url, csp.whitelistBypasses.flash.URLS);

    if (flashBypass) {
      violations.push(new csp.Finding(
          csp.Finding.Type.OBJECT_WHITELIST_BYPASS,
          flashBypass.getDomain() +
          ' is known to host Flash files which allow to bypass this CSP.',
          csp.Finding.Severity.HIGH, effectiveObjectSrcDirective, value));
    } else if (effectiveObjectSrcDirective == csp.Directive.OBJECT_SRC) {
      violations.push(new csp.Finding(
          csp.Finding.Type.OBJECT_WHITELIST_BYPASS,
          'Can you restrict object-src to \'none\' only?',
          csp.Finding.Severity.MEDIUM_MAYBE, effectiveObjectSrcDirective,
          value));
    }
  }

  return violations;
};


/**
 * Checks if csp contains IP addresses.
 * Findings of this check are informal only and are FP free.
 *
 * Example policy where this check would trigger:
 *  script-src 127.0.0.1
 *
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkIpSource = function(parsedCsp) {
  var violations = [];

  // Function for checking if directive values contain IP addresses.
  var checkIP = function(directive, directiveValues) {
    for (let value of directiveValues) {
      var url = '//' + csp.utils.getSchemeFreeUrl(value);
      var host = new goog.Uri(url).getDomain();
      var ip = goog.net.IpAddress.fromUriString(host);
      if (ip) {
        var ipString = ip.toString();

        // Check if localhost.
        // See 4.8 in https://www.w3.org/TR/CSP2/#match-source-expression
        if (ipString == '127.0.0.1') {
          violations.push(new csp.Finding(
              csp.Finding.Type.IP_SOURCE,
              directive + ' directive allows localhost as source. ' +
                  'Please make sure to remove this in production environments.',
              csp.Finding.Severity.INFO, directive, value));
        } else {
          violations.push(new csp.Finding(
              csp.Finding.Type.IP_SOURCE,
              directive + ' directive has an IP-Address as source: ' +
                  ipString + ' (will be ignored by browsers!). ',
              csp.Finding.Severity.INFO, directive, value));
        }
      }
    }
  };

  // Apply check to values of all directives.
  csp.utils.applyCheckFunktionToDirectives(parsedCsp, checkIP);
  return violations;
};


/**
 * Checks if csp contains directives that are deprecated in CSP3.
 * Findings of this check are informal only and are FP free.
 *
 * Example policy where this check would trigger:
 *  report-uri foo.bar/csp
 *
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkDeprecatedDirective = function(parsedCsp) {
  var violations = [];

  // Cannot use `in` with structs... bypass this check.
  var /** ? */ any = parsedCsp;

  // More details: https://www.chromestatus.com/feature/5769374145183744
  if (csp.Directive.REFLECTED_XSS in any) {
    violations.push(new csp.Finding(
        csp.Finding.Type.DEPRECATED_DIRECTIVE,
        'reflected-xss is deprecated since CSP2. ' +
        'Please, use the X-XSS-Protection header instead.',
        csp.Finding.Severity.INFO, csp.Directive.REFLECTED_XSS));
  }

  // More details: https://www.chromestatus.com/feature/5680800376815616
  if (csp.Directive.REFERRER in any) {
    violations.push(new csp.Finding(
        csp.Finding.Type.DEPRECATED_DIRECTIVE,
        'referrer is deprecated since CSP2. ' +
        'Please, use the Referrer-Policy header instead.',
        csp.Finding.Severity.INFO, csp.Directive.REFERRER));
  }

  // More details: https://github.com/w3c/webappsec-csp/pull/327
  if (csp.Directive.DISOWN_OPENER in any) {
    violations.push(new csp.Finding(
        csp.Finding.Type.DEPRECATED_DIRECTIVE,
        'disown-opener is deprecated since CSP3. ' +
        'Please, use the Cross Origin Opener Policy header instead.',
        csp.Finding.Severity.INFO, csp.Directive.DISOWN_OPENER));
  }
  return violations;
};


/**
 * Checks if csp nonce is at least 8 characters long.
 * Findings of this check are of medium severity and are FP free.
 *
 * Example policy where this check would trigger:
 *  script-src 'nonce-short'
 *
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkNonceLength = function(parsedCsp) {
  var nonce_pattern = new RegExp("^'nonce-(.+)'$");
  var violations = [];

  csp.utils.applyCheckFunktionToDirectives(
      parsedCsp, function(directive, directiveValues) {
        for (let value of directiveValues) {
          var match = value.match(nonce_pattern);
          if (!match) {
            continue;  // Not a nonce.
          }

          var nonceValue = match[1];
          if (nonceValue.length < 8) {
            violations.push(new csp.Finding(
                csp.Finding.Type.NONCE_LENGTH,
                'Nonces should be at least 8 characters long.',
                csp.Finding.Severity.MEDIUM, directive, value));
          }

          if (!csp.isNonce(value, true)) {
            violations.push(new csp.Finding(
                csp.Finding.Type.NONCE_LENGTH,
                'Nonces should only use the base64 charset.',
                csp.Finding.Severity.INFO, directive, value));
          }
        }
      });

  return violations;
};


/**
 * Checks if CSP allows sourcing from http://
 * Findings of this check are of medium severity and are FP free.
 *
 * Example policy where this check would trigger:
 *  report-uri http://foo.bar/csp
 *
 * @param {!csp.Csp} parsedCsp Parsed CSP.
 * @return {!Array.<!csp.Finding>}
 */
csp.securityChecks.checkSrcHttp = function(parsedCsp) {
  var violations = [];

  csp.utils.applyCheckFunktionToDirectives(
      parsedCsp, function(directive, directiveValues) {
        for (let value of directiveValues) {
          var description = directive == csp.Directive.REPORT_URI ?
              'Use HTTPS to send violation reports securely.' :
              'Allow only resources downloaded over HTTPS.';
          if (value.startsWith('http://')) {
            violations.push(new csp.Finding(
                csp.Finding.Type.SRC_HTTP,
                description,
                csp.Finding.Severity.MEDIUM, directive, value));
          }
        }
      });

  return violations;
};
