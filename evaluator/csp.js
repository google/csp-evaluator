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
 * @fileoverview CSP definitions and helper functions.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp');
goog.provide('csp.Csp');
goog.provide('csp.CspError');
goog.provide('csp.Directive');
goog.provide('csp.Keyword');
goog.provide('csp.Version');

goog.require('csp.Finding');
goog.require('goog.array');
goog.require('goog.debug.Error');
goog.require('goog.object');
goog.require('goog.string.StringBuffer');


/**
 * Content Security Policy object.
 * List of valid CSP directives:
 *  - http://www.w3.org/TR/CSP2/#directives
 *  - https://www.w3.org/TR/upgrade-insecure-requests/
 * @implements {IObject} For [] access
 */
csp.Csp = class {
  constructor() {
    // Fetch directives
    /** @type {!Array.<string>|undefined} */
    this.childSrc;
    /** @type {!Array.<string>|undefined} */
    this.connectSrc;
    /** @type {!Array.<string>|undefined} */
    this.defaultSrc;
    /** @type {!Array.<string>|undefined} */
    this.fontSrc;
    /** @type {!Array.<string>|undefined} */
    this.frameSrc;
    /** @type {!Array.<string>|undefined} */
    this.imgSrc;
    /** @type {!Array.<string>|undefined} */
    this.mediaSrc;
    /** @type {!Array.<string>|undefined} */
    this.objectSrc;
    /** @type {!Array.<string>|undefined} */
    this.scriptSrc;
    /** @type {!Array.<string>|undefined} */
    this.styleSrc;

    /** @type {!Array.<string>|undefined} */
    this.manifestSrc;
    /** @type {!Array.<string>|undefined} */
    this.workerSrc;

    // Document directives
    /** @type {!Array.<string>|undefined} */
    this.baseUri;
    /** @type {!Array.<string>|undefined} */
    this.pluginTypes;
    /** @type {!Array.<string>|undefined} */
    this.sandbox;

    // Navigation directives
    /** @type {!Array.<string>|undefined} */
    this.formAction;
    /** @type {!Array.<string>|undefined} */
    this.frameAncestors;

    // Reporting directives
    /** @type {!Array.<string>|undefined} */
    this.reportTo;
    /** @type {!Array.<string>|undefined} */
    this.reportUri;

    // Other directives
    /** @type {!Array.<string>|undefined} */
    this.blockAllMixedContent;
    /** @type {!Array.<string>|undefined} */
    this.upgradeInsecureRequests;
  }

  /**
   * Clones a CSP object.
   * @param {!csp.Csp} parsedCsp CSP.
   * @return {!csp.Csp} clone of parsedCsp.
   */
  static clone(parsedCsp) {
    var clone = new csp.Csp();
    for (let directive of Object.keys(parsedCsp)) {
      clone[directive] = goog.array.clone(parsedCsp[directive]);
    }
    return clone;
  }

  /**
   * Converts a parsed CSP back into a string.
   * @param {!csp.Csp} parsedCsp CSP.
   * @return {string} CSP string.
   */
  static convertToString(parsedCsp) {
    var cspString = new goog.string.StringBuffer();

    for (let directive of Object.keys(parsedCsp)) {
      cspString.append(directive);
      var directiveValues = parsedCsp[directive];
      for (var value, i = 0; value = directiveValues[i]; i++) {
        cspString.append(' ' + value);
      }
      cspString.append('; ');
    }

    return cspString.toString();
  }

  /**
   * Returns CSP as it would be seen by a UA supporting a specific CSP version.
   * @param {!csp.Csp} parsedCsp CSP.
   * @param {!csp.Version} cspVersion CSP.
   * @param {!Array.<!csp.Finding>=} opt_findings findings about ignored
   *     directive
   *   values will be added to this array, if passed.
   *   (e.g. CSP2 ignores 'unsafe-inline' in presence of a nonce or a hash)
   * @return {!csp.Csp} The effective CSP.
   */
  static getEffectiveCsp(parsedCsp, cspVersion, opt_findings) {
    var findings = opt_findings || [];
    var effectiveCsp = csp.Csp.clone(parsedCsp);
    var directive =
        csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.SCRIPT_SRC);
    var values = parsedCsp[directive] || [];

    if (effectiveCsp[directive] &&
        (csp.Csp.policyHasScriptNonces(effectiveCsp) ||
         csp.Csp.policyHasScriptHashes(effectiveCsp))) {
      if (cspVersion >= csp.Version.CSP2) {
        // Ignore 'unsafe-inline' in CSP >= v2, if a nonce or a hash is present.
        if (goog.array.contains(values, csp.Keyword.UNSAFE_INLINE)) {
          goog.array.remove(effectiveCsp[directive], csp.Keyword.UNSAFE_INLINE);
          findings.push(new csp.Finding(
              csp.Finding.Type.IGNORED,
              'unsafe-inline is ignored if a nonce or a hash is present. ' +
                  '(CSP2 and above)',
              csp.Finding.Severity.NONE, directive, csp.Keyword.UNSAFE_INLINE));
        }
      } else {
        // remove nonces and hashes (not supported in CSP < v2).
        for (let value of values) {
          if (value.startsWith('\'nonce-') || value.startsWith('\'sha')) {
            goog.array.remove(effectiveCsp[directive], value);
          }
        }
      }
    }

    if (effectiveCsp[directive] && csp.Csp.policyHasStrictDynamic(parsedCsp)) {
      // Ignore whitelist in CSP >= v3 in presence of 'strict-dynamic'.
      if (cspVersion >= csp.Version.CSP3) {
        for (let value of values) {
          // Because of 'strict-dynamic' all host-source and scheme-source
          // expressions, as well as the "'unsafe-inline'" and "'self'
          // keyword-sources will be ignored.
          // https://w3c.github.io/webappsec-csp/#strict-dynamic-usage
          if (!value.startsWith('\'') || value == csp.Keyword.SELF ||
              value == csp.Keyword.UNSAFE_INLINE) {
            goog.array.remove(effectiveCsp[directive], value);
            findings.push(new csp.Finding(
                csp.Finding.Type.IGNORED,
                'Because of strict-dynamic this entry is ignored in CSP3 and above',
                csp.Finding.Severity.NONE, directive, value));
          }
        }
      } else {
        // strict-dynamic not supported.
        goog.array.remove(effectiveCsp[directive], csp.Keyword.STRICT_DYNAMIC);
      }
    }

    if (cspVersion < csp.Version.CSP3) {
      // Remove CSP3 directives from pre-CSP3 policies.
      // https://w3c.github.io/webappsec-csp/#changes-from-level-2
      goog.object.remove(effectiveCsp, csp.Directive.REPORT_TO);
      goog.object.remove(effectiveCsp, csp.Directive.WORKER_SRC);
      goog.object.remove(effectiveCsp, csp.Directive.MANIFEST_SRC);
      goog.object.remove(effectiveCsp, csp.Directive.TRUSTED_TYPES);
      goog.object.remove(effectiveCsp, csp.Directive.REQUIRE_TRUSTED_TYPES_FOR);
    }

    return effectiveCsp;
  }

  /**
   * Returns default-src if directive is a fetch directive and is not present in
   * the provided CSP. Otherwise the provided directive is returned.
   * @param {!csp.Csp} parsedCsp CSP.
   * @param {string} directive CSP.
   * @return {string} The effective directive.
   */
  static getEffectiveDirective(parsedCsp, directive) {
    // Cannot use `in` with structs... bypass this check.
    var /** ? */ any = parsedCsp;

    // Only fetch directives default to default-src.
    if (!(directive in any) &&
        goog.array.contains(csp.FETCH_DIRECTIVES, directive)) {
      return csp.Directive.DEFAULT_SRC;
    }

    return directive;
  }

  /**
   * Returns the passed directives if present in the CSP or default-src
   * otherwise.
   * @param {!csp.Csp} parsedCsp CSP.
   * @param {!Array.<string>} directives CSP.
   * @return {!Array.<string>} The effective directives.
   */
  static getEffectiveDirectives(parsedCsp, directives) {
    var effectiveDirectives = new Set(goog.array.map(
        directives, val => csp.Csp.getEffectiveDirective(parsedCsp, val)));
    return [...effectiveDirectives];
  }

  /**
   * Checks if the CSP is using nonces for scripts.
   * @param {!csp.Csp} parsedCsp CSP.
   * @return {boolean} true, if the is using script nonces.
   */
  static policyHasScriptNonces(parsedCsp) {
    var directiveName =
        csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.SCRIPT_SRC);
    var values = parsedCsp[directiveName] || [];
    return goog.array.some(values, val => csp.isNonce(val));
  }

  /**
   * Checks if the CSP is using hashes for scripts.
   * @param {!csp.Csp} parsedCsp CSP.
   * @return {boolean} true, if the CSP is using script hashes.
   */
  static policyHasScriptHashes(parsedCsp) {
    var directiveName =
        csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.SCRIPT_SRC);
    var values = parsedCsp[directiveName] || [];
    return goog.array.some(values, val => csp.isHash(val));
  }

  /**
   * Checks if the CSP is using strict-dynamic.
   * @param {!csp.Csp} parsedCsp CSP.
   * @return {boolean} true, if the CSP is using CSP nonces.
   */
  static policyHasStrictDynamic(parsedCsp) {
    var directiveName =
        csp.Csp.getEffectiveDirective(parsedCsp, csp.Directive.SCRIPT_SRC);
    var values = parsedCsp[directiveName] || [];
    return goog.array.contains(values, csp.Keyword.STRICT_DYNAMIC);
  }
};


/**
 * CSP directive source keywords.
 * @enum {string}
 */
csp.Keyword = {
  SELF: "'self'",
  NONE: "'none'",
  UNSAFE_INLINE: "'unsafe-inline'",
  UNSAFE_EVAL: "'unsafe-eval'",
  STRICT_DYNAMIC: "'strict-dynamic'",
  UNSAFE_HASHED_ATTRIBUTES: "'unsafe-hashed-attributes'",
  UNSAFE_HASHES: "'unsafe-hashes'",
  REPORT_SAMPLE: "'report-sample'"
};


/**
 * CSP directive source keywords.
 * @enum {string}
 */
csp.TrustedTypesSink = {
  SCRIPT: "'script'"
};


/**
 * CSP v3 directives.
 * List of valid CSP directives:
 *  - http://www.w3.org/TR/CSP2/#directives
 *  - https://www.w3.org/TR/upgrade-insecure-requests/
 *
 * @enum {string}
 */
csp.Directive = {
  // Fetch directives
  CHILD_SRC: 'child-src',
  CONNECT_SRC: 'connect-src',
  DEFAULT_SRC: 'default-src',
  FONT_SRC: 'font-src',
  FRAME_SRC: 'frame-src',
  IMG_SRC: 'img-src',
  MEDIA_SRC: 'media-src',
  OBJECT_SRC: 'object-src',
  SCRIPT_SRC: 'script-src',
  SCRIPT_SRC_ATTR: 'script-src-attr',
  SCRIPT_SRC_ELEM: 'script-src-elem',
  STYLE_SRC: 'style-src',
  STYLE_SRC_ATTR: 'style-src-attr',
  STYLE_SRC_ELEM: 'style-src-elem',
  PREFETCH_SRC: 'prefetch-src',

  MANIFEST_SRC: 'manifest-src',
  WORKER_SRC: 'worker-src',

  // Document directives
  BASE_URI: 'base-uri',
  PLUGIN_TYPES: 'plugin-types',
  SANDBOX: 'sandbox',
  DISOWN_OPENER: 'disown-opener',

  // Navigation directives
  FORM_ACTION: 'form-action',
  FRAME_ANCESTORS: 'frame-ancestors',

  // Reporting directives
  REPORT_TO: 'report-to',
  REPORT_URI: 'report-uri',

  // Other directives
  BLOCK_ALL_MIXED_CONTENT: 'block-all-mixed-content',
  UPGRADE_INSECURE_REQUESTS: 'upgrade-insecure-requests',
  REFLECTED_XSS: 'reflected-xss',
  REFERRER: 'referrer',
  REQUIRE_SRI_FOR: 'require-sri-for',
  TRUSTED_TYPES: 'trusted-types', // https://github.com/WICG/trusted-types
  REQUIRE_TRUSTED_TYPES_FOR: 'require-trusted-types-for'
};

/**
 * CSP v3 fetch directives.
 * Fetch directives control the locations from which resources may be loaded.
 * https://w3c.github.io/webappsec-csp/#directives-fetch
 *
 * @const {!Array.<!csp.Directive>}
 */
csp.FETCH_DIRECTIVES = [
  csp.Directive.CHILD_SRC,
  csp.Directive.CONNECT_SRC,
  csp.Directive.DEFAULT_SRC,
  csp.Directive.FONT_SRC,
  csp.Directive.FRAME_SRC,
  csp.Directive.IMG_SRC,
  csp.Directive.MANIFEST_SRC,
  csp.Directive.MEDIA_SRC,
  csp.Directive.OBJECT_SRC,
  csp.Directive.SCRIPT_SRC,
  csp.Directive.SCRIPT_SRC_ATTR,
  csp.Directive.SCRIPT_SRC_ELEM,
  csp.Directive.STYLE_SRC,
  csp.Directive.STYLE_SRC_ATTR,
  csp.Directive.STYLE_SRC_ELEM,
  csp.Directive.WORKER_SRC
];

/**
 * CSP version.
 * @enum {number}
 */
csp.Version = {
  CSP1: 1,
  CSP2: 2,
  CSP3: 3
};


/**
 * Checks if a string is a valid CSP directive.
 * @param {string} directive value to check.
 * @return {boolean} True if directive is a valid CSP directive.
 */
csp.isDirective = function(directive) {
  return goog.object.contains(csp.Directive, directive);
};


/**
 * Checks if a string is a valid CSP keyword.
 * @param {string} keyword value to check.
 * @return {boolean} True if keyword is a valid CSP keyword.
 */
csp.isKeyword = function(keyword) {
  return goog.object.contains(csp.Keyword, keyword);
};


/**
 * Checks if a string is a valid URL scheme.
 * Scheme part + ":"
 * For scheme part see https://tools.ietf.org/html/rfc3986#section-3.1
 * @param {string} urlScheme value to check.
 * @return {boolean} True if urlScheme has a valid scheme.
 */
csp.isUrlScheme = function(urlScheme) {
  var pattern = new RegExp('^[a-zA-Z][+a-zA-Z0-9.-]*:$');
  return pattern.test(urlScheme);
};


/**
 * A regex pattern to check nonce prefix and Base64 formatting of a nonce value.
 */
csp.STRICT_NONCE_PATTERN = new RegExp('^\'nonce-[a-zA-Z0-9+/_-]+[=]{0,2}\'$');


/** A regex pattern for checking if nonce prefix. */
csp.NONCE_PATTERN = new RegExp('^\'nonce-(.+)\'$');


/**
 * Checks if a string is a valid CSP nonce.
 * See http://www.w3.org/TR/CSP2/#nonce_value
 * @param {string} nonce value to check.
 * @param {boolean=} opt_strict Check if the nonce uses the base64 charset.
 * @return {boolean} True if nonce is has a valid CSP nonce.
 */
csp.isNonce = function(nonce, opt_strict) {
  var pattern = opt_strict ? csp.STRICT_NONCE_PATTERN : csp.NONCE_PATTERN;
  return pattern.test(nonce);
};


/**
 * A regex pattern to check hash prefix and Base64 formatting of a hash value.
 */
csp.STRICT_HASH_PATTERN =
    new RegExp('^\'(sha256|sha384|sha512)-[a-zA-Z0-9+/]+[=]{0,2}\'$');


/** A regex pattern to check hash prefix. */
csp.HASH_PATTERN = new RegExp('^\'(sha256|sha384|sha512)-(.+)\'$');


/**
 * Checks if a string is a valid CSP hash.
 * See http://www.w3.org/TR/CSP2/#hash_value
 * @param {string} hash value to check.
 * @param {boolean=} opt_strict Check if the hash uses the base64 charset.
 * @return {boolean} True if hash is has a valid CSP hash.
 */
csp.isHash = function(hash, opt_strict) {
  var pattern = opt_strict ? csp.STRICT_HASH_PATTERN : csp.HASH_PATTERN;
  return pattern.test(hash);
};


/**
 * Class to represent all generic CSP errors.
 */
csp.CspError = class extends goog.debug.Error {
  /**
   * @param {*=} opt_msg An optional error message.
   */
  constructor(opt_msg) {
    super(opt_msg);
  }
};
