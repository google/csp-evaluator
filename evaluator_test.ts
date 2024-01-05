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
 * @fileoverview Tests for CSP Evaluator.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

import 'jasmine';

import {Csp} from './csp';
import {CspEvaluator} from './evaluator';
import {Finding, Severity, Type} from './finding';
import { EnforcedCsps } from './enforced_csps';

describe('Test evaluator', () => {
  it('CspEvaluator', () => {
    const fakeCsp = new EnforcedCsps();
    const evaluator = new CspEvaluator(fakeCsp);
    expect(evaluator.csps).toBe(fakeCsp);
  });

  it('Evaluate', () => {
    const fakeFinding = new (Finding)(
        Type.UNKNOWN_DIRECTIVE, 'Fake description', Severity.MEDIUM, 'fake-directive', 'fake-directive-value');
    
    const fakeVerifier = (parsedCsp: EnforcedCsps) => {
      return [fakeFinding];
    };

    const fakeCsp = new EnforcedCsps();
    const evaluator = new (CspEvaluator)(fakeCsp);
    const findings = evaluator.evaluate([fakeVerifier, fakeVerifier], [fakeVerifier]);

    const expectedFindings = [fakeFinding, fakeFinding, fakeFinding];
    expect(findings).toEqual(expectedFindings);
  });
});
