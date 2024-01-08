/**
 * @fileoverview Tests for CSP Parser.
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

import {CspParser, TEST_ONLY} from '../src/parser';


describe('Test parser', () => {
  it('CspParser', () => {
    const validCsp =  // Test policy with different features from CSP2.
        'default-src \'none\';' +
        'script-src \'nonce-unsafefoobar\' \'unsafe-eval\'   \'unsafe-inline\' \n' +
        'https://example.com/foo.js foo.bar;      ' +
        'object-src \'none\';' +
        'img-src \'self\' https: data: blob:;' +
        'style-src \'self\' \'unsafe-inline\' \'sha256-1DCfk1NYWuHMfoobarfoobar=\';' +
        'font-src *;' +
        'child-src *.example.com:9090;' +
        'upgrade-insecure-requests;\n' +
        'report-uri /csp/test';

    const parser = new (CspParser)(validCsp);
    const parsedCsp = parser.csp;

    // check directives
    const directives = Object.keys(parsedCsp.directives[0]);
    const expectedDirectives = [
      'default-src', 'script-src', 'object-src', 'img-src', 'style-src',
      'font-src', 'child-src', 'upgrade-insecure-requests', 'report-uri'
    ];
    expect(expectedDirectives)
        .toEqual(jasmine.arrayWithExactContents(directives));

    // check directive values
    expect(['\'none\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['default-src'] as string[]));

    expect([
      '\'nonce-unsafefoobar\'', '\'unsafe-eval\'', '\'unsafe-inline\'',
      'https://example.com/foo.js', 'foo.bar'
    ])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['script-src'] as string[]));

    expect(['\'none\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['object-src'] as string[]));

    expect(['\'self\'', 'https:', 'data:', 'blob:'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['img-src'] as string[]));
    expect([
      '\'self\'', '\'unsafe-inline\'', '\'sha256-1DCfk1NYWuHMfoobarfoobar=\''
    ])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['style-src'] as string[]));
    expect(['*']).toEqual(jasmine.arrayWithExactContents(
        parsedCsp.directives[0]['font-src'] as string[]));
    expect(['*.example.com:9090'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['child-src'] as string[]));
    expect([]).toEqual(jasmine.arrayWithExactContents(
        parsedCsp.directives[0]['upgrade-insecure-requests'] as string[]));
    expect(['/csp/test'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['report-uri'] as string[]));
  });

  it('CspParserDuplicateDirectives', () => {
    const validCsp = 'default-src \'none\';' +
        'default-src foo.bar;' +
        'object-src \'none\';' +
        'OBJECT-src foo.bar;';

    const parser = new (CspParser)(validCsp);
    const parsedCsp = parser.csp;

    // check directives
    const directives = Object.keys(parsedCsp.directives[0]);
    const expectedDirectives = ['default-src', 'object-src'];
    expect(expectedDirectives)
        .toEqual(jasmine.arrayWithExactContents(directives));

    // check directive values
    expect(['\'none\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['default-src'] as string[]));
    expect(['\'none\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['object-src'] as string[]));
  });

  it('CspParserMixedCaseKeywords', () => {
    const validCsp = 'DEFAULT-src \'NONE\';' +  // Keywords should be
                                                // case insensetive.
        'img-src \'sElf\' HTTPS: Example.com/CaseSensitive;';

    const parser = new (CspParser)(validCsp);
    const parsedCsp = parser.csp;

    // check directives
    const directives = Object.keys(parsedCsp.directives[0]);
    const expectedDirectives = ['default-src', 'img-src'];
    expect(expectedDirectives)
        .toEqual(jasmine.arrayWithExactContents(directives));

    // check directive values
    expect(['\'none\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['default-src'] as string[]));
    expect(['\'self\'', 'https:', 'Example.com/CaseSensitive'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['img-src'] as string[]));
  });

  it('NormalizeDirectiveValue', () => {
    expect(TEST_ONLY.normalizeDirectiveValue('\'nOnE\'')).toBe('\'none\'');
    expect(TEST_ONLY.normalizeDirectiveValue('\'nonce-aBcD\''))
        .toBe('\'nonce-aBcD\'');
    expect(TEST_ONLY.normalizeDirectiveValue('\'hash-XyZ==\''))
        .toBe('\'hash-XyZ==\'');
    expect(TEST_ONLY.normalizeDirectiveValue('HTTPS:')).toBe('https:');
    expect(TEST_ONLY.normalizeDirectiveValue('example.com/TEST'))
        .toBe('example.com/TEST');
  });

  it('ParseMultipleDirectivesSimple', () => {
    const testCsp1 = 'default-src \'self\' http://example.com http://example.net; ' +
        'connect-src \'none\'; ';

    const testCsp2 = 'connect-src http://example.com/; script-src http://example.com/; ';

    const parsed = (new CspParser([testCsp1, testCsp2])).csp;

    // check directives
    const directives1 = Object.keys(parsed.directives[0]);
    const expectedDirectives1 = [
      'default-src', 'connect-src'
    ];

    const directives2 = Object.keys(parsed.directives[1]);
    const expectedDirectives2 = [
      'connect-src', 'script-src'
    ];

    expect(expectedDirectives1).toEqual(jasmine.arrayWithExactContents(directives1));
    expect(expectedDirectives2).toEqual(jasmine.arrayWithExactContents(directives2));

    // check directive values
    expect(['\'self\'', 'http://example.com', 'http://example.net'])
        .toEqual(jasmine.arrayWithExactContents(
            parsed.directives[0]['default-src'] as string[]));

    expect(['\'none\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsed.directives[0]['connect-src'] as string[]));

    expect(['http://example.com/'])
        .toEqual(jasmine.arrayWithExactContents(
            parsed.directives[1]['connect-src'] as string[]));

    expect(['http://example.com/'])
        .toEqual(jasmine.arrayWithExactContents(
            parsed.directives[1]['script-src'] as string[]));
  });

  it('CspParserMultipleDirectivesRFC2616', () => {
    const validCsp =  // Test policy with different features from CSP2.
        'default-src \'none\', default-src \'nonce-foobar\';' +
        'script-src \'nonce-unsafefoobar\' \'unsafe-eval\'   \'unsafe-inline\' \n' +
        'https://example.com/foo.js foo.bar, script-src https:;      ' +
        'object-src \'none\';' +
        'img-src \'self\' https: data: blob:;' +
        'style-src \'self\' \'unsafe-inline\' \'sha256-1DCfk1NYWuHMfoobarfoobar=\';' +
        'font-src *;' +
        'child-src *.example.com:9090;' +
        'upgrade-insecure-requests;\n' +
        'report-uri /csp/test';

    const parser = new (CspParser)([validCsp]);
    const parsedCsp = parser.csp;

    // check directives
    const directives = Object.keys(parsedCsp.directives[0]);
    const expectedDirectives = [
        'default-src'
    ];
    expect(expectedDirectives)
        .toEqual(jasmine.arrayWithExactContents(directives));

    const directives2 = Object.keys(parsedCsp.directives[1]);
    const expectedDirectives2 = [
        'default-src', 'script-src'
    ];
    expect(expectedDirectives2)
        .toEqual(jasmine.arrayWithExactContents(directives2));

    const directives3 = Object.keys(parsedCsp.directives[2]);
    const expectedDirectives3 = [
        'script-src', 'object-src', 'img-src', 'style-src',
        'font-src', 'child-src', 'upgrade-insecure-requests', 'report-uri'
    ];
    expect(expectedDirectives3)
        .toEqual(jasmine.arrayWithExactContents(directives3));

    // check directive values
    expect(['\'none\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['default-src'] as string[]));

    expect(['\'nonce-foobar\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[1]['default-src'] as string[]));

    expect([
      '\'nonce-unsafefoobar\'', '\'unsafe-eval\'', '\'unsafe-inline\'',
      'https://example.com/foo.js', 'foo.bar'
    ])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[1]['script-src'] as string[]));

    expect(['https:'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[2]['script-src'] as string[]));

    expect(['\'none\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[2]['object-src'] as string[]));

    expect(['\'self\'', 'https:', 'data:', 'blob:'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[2]['img-src'] as string[]));
    expect([
      '\'self\'', '\'unsafe-inline\'', '\'sha256-1DCfk1NYWuHMfoobarfoobar=\''
    ])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[2]['style-src'] as string[]));

    expect(['*']).toEqual(jasmine.arrayWithExactContents(
        parsedCsp.directives[2]['font-src'] as string[]));

    expect(['*.example.com:9090'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[2]['child-src'] as string[]));

    expect([]).toEqual(jasmine.arrayWithExactContents(
        parsedCsp.directives[2]['upgrade-insecure-requests'] as string[]));

    expect(['/csp/test'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[2]['report-uri'] as string[]));
  });

  it('CspParserMultipleDirectivesMixed', () => {
    const validCsp1 =  // Test policy with different features from CSP2.
        'default-src \'none\';' +
        'script-src \'nonce-unsafefoobar\' \'unsafe-eval\'   \'unsafe-inline\' \n' +
        'https://example.com/foo.js foo.bar;      ' +
        'object-src \'none\';' +
        'img-src \'self\' https: data: blob:;' +
        'style-src \'self\' \'unsafe-inline\' \'sha256-1DCfk1NYWuHMfoobarfoobar=\';' +
        'font-src *;' +
        'child-src *.example.com:9090;' +
        'upgrade-insecure-requests;\n' +
        'report-uri /csp/test, default-src \'self\'';

    const validCsp2 =  // Test policy with different features from CSP2.
        'default-src \'nonce-foobar\';' +
        'script-src https:';

    const parser = new (CspParser)([validCsp1, validCsp2]);
    const parsedCsp = parser.csp;

    // check directives
    const directives = Object.keys(parsedCsp.directives[0]);
    const expectedDirectives = [
      'default-src', 'script-src', 'object-src', 'img-src', 'style-src',
      'font-src', 'child-src', 'upgrade-insecure-requests', 'report-uri'
    ];
    expect(expectedDirectives)
        .toEqual(jasmine.arrayWithExactContents(directives));

    const directives1 = Object.keys(parsedCsp.directives[1]);
    const expectedDirectives1 = [
      'default-src'
    ];
    expect(expectedDirectives1)
        .toEqual(jasmine.arrayWithExactContents(directives1));

    const directives2 = Object.keys(parsedCsp.directives[2]);
    const expectedDirectives2 = [
        'default-src', 'script-src'
    ];
    expect(expectedDirectives2)
        .toEqual(jasmine.arrayWithExactContents(directives2));

    // check directive values
    expect(['\'none\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['default-src'] as string[]));

    expect([
      '\'nonce-unsafefoobar\'', '\'unsafe-eval\'', '\'unsafe-inline\'',
      'https://example.com/foo.js', 'foo.bar'
    ])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['script-src'] as string[]));

    expect(['\'none\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['object-src'] as string[]));

    expect(['\'self\'', 'https:', 'data:', 'blob:'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['img-src'] as string[]));

    expect([
      '\'self\'', '\'unsafe-inline\'', '\'sha256-1DCfk1NYWuHMfoobarfoobar=\''
    ])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['style-src'] as string[]));

    expect(['*']).toEqual(jasmine.arrayWithExactContents(
        parsedCsp.directives[0]['font-src'] as string[]));

    expect(['*.example.com:9090'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['child-src'] as string[]));

    expect([]).toEqual(jasmine.arrayWithExactContents(
        parsedCsp.directives[0]['upgrade-insecure-requests'] as string[]));

    expect(['/csp/test'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[0]['report-uri'] as string[]));

    expect(['\'self\''])
        .toEqual(jasmine.arrayWithExactContents(
        parsedCsp.directives[1]['default-src'] as string[]));

    expect(['\'nonce-foobar\''])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[2]['default-src'] as string[]));

    expect(['https:'])
        .toEqual(jasmine.arrayWithExactContents(
            parsedCsp.directives[2]['script-src'] as string[]));
  });
});
