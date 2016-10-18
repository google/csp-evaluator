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
 * @fileoverview Tests for CSP Finding.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.FindingTest');
goog.setTestOnly('csp.FindingTest');

goog.require('csp');
goog.require('csp.Directive');
goog.require('csp.Finding');
goog.require('goog.testing.jsunit');


function testFinding() {
  var type = 'TEST';
  var description = 'description';
  var severity = csp.Finding.Severity.HIGH;
  var directive = csp.Directive.SCRIPT_SRC;
  var opt_value = csp.Keyword.NONE;

  var finding = new csp.Finding(
      type, description, severity, directive, opt_value);

  assertEquals(type, finding.type);
  assertEquals(description, finding.description);
  assertEquals(severity, finding.severity);
  assertEquals(directive, finding.directive);
  assertEquals(opt_value, finding.value);
}
