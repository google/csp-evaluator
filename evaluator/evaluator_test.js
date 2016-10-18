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

goog.provide('csp.CspEvaluatorTest');
goog.setTestOnly('csp.CspEvaluatorTest');

goog.require('csp');
goog.require('csp.Csp');
goog.require('csp.CspEvaluator');
goog.require('csp.Finding');
goog.require('goog.testing.jsunit');

function testCspEvaluator() {
  var fakeCsp = new csp.Csp();
  var evaluator = new csp.CspEvaluator(fakeCsp);
  assertEquals(fakeCsp, evaluator.csp);
}

function testEvaluate() {
  var fakeCsp = new csp.Csp();
  var fakeFinding = new csp.Finding(
      'Fake finding', csp.Finding.Severity.MEDIUM, 'fake-directive', 0);
  var fakeVerifier = function(parsedCsp) { return [fakeFinding]; };

  var evaluator = new csp.CspEvaluator(fakeCsp);
  var findings = evaluator.evaluate(
      [fakeVerifier, fakeVerifier], [fakeVerifier]);

  var expectedFindings = [fakeFinding, fakeFinding, fakeFinding];
  assertElementsEquals(expectedFindings, findings);
}
