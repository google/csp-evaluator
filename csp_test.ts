/**
 * @fileoverview Tests for CSP Defintions.
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

import 'jasmine';

import {Directive, isDirective, isHash, isKeyword, isNonce, isUrlScheme, Keyword, Version} from './csp';
import {Finding, Severity, Type} from './finding';
import {CspParser} from './parser';

describe('Test Csp', () => {
  it('ConvertToString', () => {
    const testCsp = 'default-src \'none\'; ' +
        'script-src \'nonce-unsafefoobar\' \'unsafe-eval\' \'unsafe-inline\' ' +
        'https://example.com/foo.js foo.bar; ' +
        'img-src \'self\' https: data: blob:; ';

    const parsed = (new CspParser(testCsp)).csp;
    expect(parsed.convertToString()).toBe(testCsp);
  });

  it('GetEffectiveCspVersion1', () => {
    const testCsp =
        'default-src \'unsafe-inline\' \'strict-dynamic\' \'nonce-123\' ' +
        '\'sha256-foobar\' \'self\'; report-to foo.bar; worker-src *; manifest-src *; script-src-attr \'self\'; script-src-elem \'self\'; style-src-attr \'self\'; style-src-elem \'self\';';
    const parsed = (new CspParser(testCsp)).csp;
    const findings: Finding[] = [];
    const effectiveCsp = parsed.getEffectiveCsp(Version.CSP1, findings);

    expect(findings.length)
        .toBe(0);  // No warnings about unsafe-inline being ignored in CSP 1.
    expect(effectiveCsp.directives[Directive.DEFAULT_SRC]).toEqual([
      '\'unsafe-inline\'', '\'self\''
    ]);
    expect(effectiveCsp.directives.hasOwnProperty(Directive.REPORT_TO))
        .toBeFalse();
    expect(effectiveCsp.directives.hasOwnProperty(Directive.WORKER_SRC))
        .toBeFalse();
    expect(effectiveCsp.directives.hasOwnProperty(Directive.MANIFEST_SRC))
        .toBeFalse();
  });

  it('GetEffectiveCspVersion2', () => {
    const testCsp =
        'default-src \'unsafe-inline\' \'strict-dynamic\' \'nonce-123\' ' +
        '\'sha256-foobar\' \'self\'; report-to foo.bar; worker-src *; manifest-src *; script-src-attr \'self\'; script-src-elem \'self\'; style-src-attr \'self\'; style-src-elem \'self\';';
    const parsed = (new CspParser(testCsp)).csp;
    const findings: Finding[] = [];
    const effectiveCsp = parsed.getEffectiveCsp(Version.CSP2, findings);

    // Ignored messages are surfaced properly.
    expect(findings.length).toBe(1);  // Only nonces cause unsafe-inline to be
                                      // ignored in CSP2, not strict-dynamic.
    expect(findings[0].value).toBe('\'unsafe-inline\'');
    expect(findings[0].type).toBe(Type.IGNORED);
    expect(findings[0].severity).toBe(Severity.NONE);
    expect(findings[0].directive).toBe(Directive.DEFAULT_SRC);

    expect(effectiveCsp.directives[Directive.DEFAULT_SRC]).toEqual([
      '\'nonce-123\'', '\'sha256-foobar\'', '\'self\''
    ]);
    expect(effectiveCsp.directives.hasOwnProperty(Directive.REPORT_TO))
        .toBeFalse();
    expect(effectiveCsp.directives.hasOwnProperty(Directive.WORKER_SRC))
        .toBeFalse();
    expect(effectiveCsp.directives.hasOwnProperty(Directive.MANIFEST_SRC))
        .toBeFalse();
    expect(effectiveCsp.directives.hasOwnProperty(Directive.SCRIPT_SRC_ATTR))
        .toBeFalse();
    expect(effectiveCsp.directives.hasOwnProperty(Directive.SCRIPT_SRC_ELEM))
        .toBeFalse();
    expect(effectiveCsp.directives.hasOwnProperty(Directive.STYLE_SRC_ATTR))
        .toBeFalse();
    expect(effectiveCsp.directives.hasOwnProperty(Directive.STYLE_SRC_ELEM))
        .toBeFalse();
  });

  it('GetEffectiveCspVersion3', () => {
    const testCsp =
        'default-src \'unsafe-inline\' \'strict-dynamic\' \'nonce-123\' ' +
        '\'sha256-foobar\' \'self\'; report-to foo.bar; worker-src *; manifest-src *; script-src-attr \'self\'; script-src-elem \'self\'; style-src-attr \'self\'; style-src-elem \'self\';';
    const parsed = (new CspParser(testCsp)).csp;
    const findings: Finding[] = [];
    const effectiveCsp = parsed.getEffectiveCsp(Version.CSP3, findings);

    // Ignored messages are only on the default-src: Ignoring self and
    // unsafe-inline because of strict-dynamic and the unsafe-inline because of
    // the nonce.
    expect(findings.length).toBe(3);
    expect(findings.every(f => f.type === Type.IGNORED)).toBeTrue();
    expect(findings.every(f => f.severity === Severity.NONE)).toBeTrue();
    expect(findings.every(f => f.directive === Directive.DEFAULT_SRC))
        .toBeTrue();

    expect(effectiveCsp.directives[Directive.DEFAULT_SRC]).toEqual([
      '\'strict-dynamic\'', '\'nonce-123\'', '\'sha256-foobar\''
    ]);
    expect(effectiveCsp.directives[Directive.REPORT_TO]).toEqual(['foo.bar']);
    expect(effectiveCsp.directives[Directive.WORKER_SRC]).toEqual(['*']);
    expect(effectiveCsp.directives[Directive.MANIFEST_SRC]).toEqual(['*']);
    expect(effectiveCsp.directives[Directive.SCRIPT_SRC_ATTR]).toEqual([
      '\'self\''
    ]);
    expect(effectiveCsp.directives[Directive.SCRIPT_SRC_ELEM]).toEqual([
      '\'self\''
    ]);
    expect(effectiveCsp.directives[Directive.STYLE_SRC_ATTR]).toEqual([
      '\'self\''
    ]);
    expect(effectiveCsp.directives[Directive.STYLE_SRC_ELEM]).toEqual([
      '\'self\''
    ]);
  });


  it('GetEffectiveDirective', () => {
    const testCsp = 'default-src https:; script-src foo.bar';
    const parsed = (new CspParser(testCsp)).csp;

    const script = parsed.getEffectiveDirective(Directive.SCRIPT_SRC);
    expect(script).toBe(Directive.SCRIPT_SRC);
    const style = parsed.getEffectiveDirective(Directive.STYLE_SRC);
    expect(style).toBe(Directive.DEFAULT_SRC);
  });


  it('GetEffectiveDirectives', () => {
    const testCsp = 'default-src https:; script-src foo.bar';
    const parsed = (new CspParser(testCsp)).csp;

    const directives = parsed.getEffectiveDirectives(
        [Directive.SCRIPT_SRC, Directive.STYLE_SRC]);
    expect(directives).toEqual([Directive.SCRIPT_SRC, Directive.DEFAULT_SRC]);
  });

  it('GetEffectiveDirectives', () => {
    const testCsp = 'default-src https:; style-src-elem foo.bar';
    const parsed = (new CspParser(testCsp)).csp;

    const directives = parsed.getEffectiveDirectives([
      Directive.STYLE_SRC, Directive.STYLE_SRC_ATTR, Directive.STYLE_SRC_ELEM
    ]);
    // Both style-src and style-src-attr default to default-src.
    expect(directives).toEqual([
      Directive.DEFAULT_SRC, Directive.STYLE_SRC_ELEM
    ]);
  });

  it('GetEffectiveDirectives', () => {
    const testCsp =
        'default-src https:; script-src foo.bar; script-src-elem bar.baz; style-src foo.bar; style-src-elem bar.baz';
    const parsed = (new CspParser(testCsp)).csp;

    const directives = parsed.getEffectiveDirectives([
      Directive.SCRIPT_SRC, Directive.STYLE_SRC, Directive.SCRIPT_SRC_ATTR,
      Directive.SCRIPT_SRC_ELEM, Directive.STYLE_SRC_ATTR,
      Directive.STYLE_SRC_ELEM
    ]);
    expect(directives).toEqual([
      Directive.SCRIPT_SRC,  // Both script-src and script-src-attr
      Directive.STYLE_SRC,   // Both style-src and style-src-attr
      Directive.SCRIPT_SRC_ELEM,
      Directive.STYLE_SRC_ELEM,
    ]);
  });

  it('PolicyHasScriptNoncesScriptSrcWithNonce', () => {
    const testCsp = 'default-src https:; script-src \'nonce-test123\'';
    const parsed = (new CspParser(testCsp)).csp;

    expect(parsed.policyHasScriptNonces()).toBeTrue();
  });


  it('PolicyHasScriptNoncesNoNonce', () => {
    const testCsp =
        'default-src https: \'nonce-ignored\'; script-src nonce-invalid';
    const parsed = (new CspParser(testCsp)).csp;

    expect(parsed.policyHasScriptNonces()).toBeFalse();
  });


  it('PolicyHasScriptHashesScriptSrcWithHash', () => {
    const testCsp = 'default-src https:; script-src \'sha256-asdfASDF\'';
    const parsed = (new CspParser(testCsp)).csp;

    expect(parsed.policyHasScriptHashes()).toBeTrue();
  });


  it('PolicyHasScriptHashesNoHash', () => {
    const testCsp =
        'default-src https: \'nonce-ignored\'; script-src sha256-invalid';
    const parsed = (new CspParser(testCsp)).csp;

    expect(parsed.policyHasScriptHashes()).toBeFalse();
  });


  it('PolicyHasStrictDynamicScriptSrcWithStrictDynamic', () => {
    const testCsp = 'default-src https:; script-src \'strict-dynamic\'';
    const parsed = (new CspParser(testCsp)).csp;

    expect(parsed.policyHasStrictDynamic()).toBeTrue();
  });


  it('PolicyHasStrictDynamicDefaultSrcWithStrictDynamic', () => {
    const testCsp = 'default-src https \'strict-dynamic\'';
    const parsed = (new CspParser(testCsp)).csp;

    expect(parsed.policyHasStrictDynamic()).toBeTrue();
  });


  it('PolicyHasStrictDynamicNoStrictDynamic', () => {
    const testCsp = 'default-src \'strict-dynamic\'; script-src foo.bar';
    const parsed = (new CspParser(testCsp)).csp;

    expect(parsed.policyHasStrictDynamic()).toBeFalse();
  });


  it('IsDirective', () => {
    const directives = Object.keys(Directive).map(
        (name) => Directive[name as keyof typeof Directive]);

    expect(directives.every(isDirective)).toBeTrue();
    expect(isDirective('invalid-src')).toBeFalse();
  });


  it('IsKeyword', () => {
    const keywords = Object.keys(Keyword).map(
        (name) => (Keyword[name as keyof typeof Keyword]));

    expect(keywords.every(isKeyword)).toBeTrue();
    expect(isKeyword('invalid')).toBeFalse();
  });


  it('IsUrlScheme', () => {
    expect(isUrlScheme('http:')).toBeTrue();
    expect(isUrlScheme('https:')).toBeTrue();
    expect(isUrlScheme('data:')).toBeTrue();
    expect(isUrlScheme('blob:')).toBeTrue();
    expect(isUrlScheme('b+l.o-b:')).toBeTrue();
    expect(isUrlScheme('filesystem:')).toBeTrue();
    expect(isUrlScheme('invalid')).toBeFalse();
    expect(isUrlScheme('ht_tp:')).toBeFalse();
  });


  it('IsNonce', () => {
    expect(isNonce('\'nonce-asdfASDF=\'')).toBeTrue();
    expect(isNonce('\'sha256-asdfASDF=\'')).toBeFalse();
    expect(isNonce('\'asdfASDF=\'')).toBeFalse();
    expect(isNonce('example.com')).toBeFalse();
  });


  it('IsStrictNonce', () => {
    expect(isNonce('\'nonce-asdfASDF=\'', true)).toBeTrue();
    expect(isNonce('\'nonce-as+df/A0234SDF==\'', true)).toBeTrue();
    expect(isNonce('\'nonce-as_dfASDF=\'', true)).toBeTrue();
    expect(isNonce('\'nonce-asdfASDF===\'', true)).toBeFalse();
    expect(isNonce('\'sha256-asdfASDF=\'', true)).toBeFalse();
  });


  it('IsHash', () => {
    expect(isHash('\'sha256-asdfASDF=\'')).toBeTrue();
    expect(isHash('\'sha777-asdfASDF=\'')).toBeFalse();
    expect(isHash('\'asdfASDF=\'')).toBeFalse();
    expect(isHash('example.com')).toBeFalse();
  });

  it('IsStrictHash', () => {
    expect(isHash('\'sha256-asdfASDF=\'', true)).toBeTrue();
    expect(isHash('\'sha256-as+d/f/ASD0+4F==\'', true)).toBeTrue();
    expect(isHash('\'sha256-asdfASDF===\'', true)).toBeFalse();
    expect(isHash('\'sha256-asd_fASDF=\'', true)).toBeFalse();
    expect(isHash('\'sha777-asdfASDF=\'', true)).toBeFalse();
    expect(isHash('\'asdfASDF=\'', true)).toBeFalse();
    expect(isHash('example.com', true)).toBeFalse();
  });

  it('ParseNavigateTo', () => {
    const testCsp = 'navigate-to \'self\'; script-src \'nonce-foo\'';
    const parsed = (new CspParser(testCsp)).csp;

    expect(parsed.policyHasStrictDynamic()).toBeFalse();
    expect(parsed.policyHasScriptNonces()).toBeTrue();
  });

  it('ParseWebRtc', () => {
    const testCsp = 'web-rtc \'allow\'; script-src \'nonce-foo\'';
    const parsed = (new CspParser(testCsp)).csp;

    expect(parsed.policyHasStrictDynamic()).toBeFalse();
    expect(parsed.policyHasScriptNonces()).toBeTrue();
  });
});
