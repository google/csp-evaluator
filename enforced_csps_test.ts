/**
 * @fileoverview Tests for Enforced CSP object helper functions.
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

import 'jasmine';

import { EnforcedCsps } from './enforced_csps';
import { CspParser } from './parser';

describe('Test enforced CSPs', () => {
  it('ConvertToString with single CSP', () => {
    const testCsp = 'default-src \'none\'; ' +
        'script-src \'nonce-unsafefoobar\' \'unsafe-eval\' \'unsafe-inline\' ' +
        'https://example.com/foo.js foo.bar; ' +
        'img-src \'self\' https: data: blob:; ';

    const parsed = (new CspParser(testCsp)).csps;

    let cspStrings: string[] = parsed.convertToStrings();
    expect(cspStrings[0]).toBe(testCsp);
  });

  it('ConvertToString with multiple CSPs', () => {
    const testCsp1 = 'default-src \'self\' http://example.com http://example.net; ' +
        'connect-src \'none\'; ';

    const testCsp2 = 'connect-src http://example.com/; script-src http://example.com/; ';

    const parsed = (new CspParser([testCsp1, testCsp2])).csps;

    let cspStrings: string[] = parsed.convertToStrings();
    expect(cspStrings[0]).toBe(testCsp1);
    expect(cspStrings[1]).toBe(testCsp2);
  });
});
