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
 * @fileoverview Tests for CSP Widget.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.ui.WidgetTest');
goog.setTestOnly('csp.WidgetTest');

goog.require('csp.CspEvaluator');
goog.require('csp.CspParser');
goog.require('csp.ui.Widget');

goog.require('goog.testing.jsunit');


/**
 * Returns text node of an element selected by a query selector.
 * @param {string} selector Query selector
 * @return {string} text
 */
function getText(selector) {
  return document.querySelector(selector).innerText;
}

function testWidget() {
  var testCsp = 'script-src * \'unsafe-eval\'; img-src *';
  var parser = new csp.CspParser(testCsp);
  var evaluator = new csp.CspEvaluator(parser.csp);
  new csp.ui.Widget(parser.csp, evaluator.evaluate());

  // Check if all expected directives are here.
  assertEquals(
      'script-src',
      getText('div.directive:nth-child(1) > a > div.col.red > b'));
  assertEquals(
      'img-src',
      getText('div.directive:nth-child(2) > a > div.col.green > b'));
  assertEquals(
      'object-src',
      getText('div.directive:nth-child(3) > a > div.col.red > b'));
  assertEquals(
      '[missing]',
      getText('div.directive:nth-child(3) > a > div.col.red > div.missing'));

  // Check if directives have expected icons set.
  assertEquals(
      'error',
      getText('div.directive:nth-child(1) > a > div.col.icon > i.red'));
  assertEquals(
      'check',
      getText('div.directive:nth-child(2) > a > div.col.icon > i.green'));
  assertEquals(
      'error',
      getText('div.directive:nth-child(3) > a > div.col.icon > i.red'));

  // Check if directive level finding has a description.
  assertEquals(
      'Missing object-src allows the injection of plugins which can execute ' +
      'JavaScript. Can you set it to \'none\'?',
      getText('div.directive:nth-child(3) > a > div > ul.descriptions > li'));

  // Check if directive values are present.
  assertEquals(
      '*', getText('div.directive-value:nth-child(1) > div.value'));
  assertEquals(
      '\'unsafe-eval\'',
       getText('div.directive-value:nth-child(2) > div.value'));

  // Check if directive values have expected icons set.
  assertEquals(
      'error', getText('div.directive-value:nth-child(1) > div > i.red'));
  assertEquals(
      'help_outline',
      getText('div.directive-value:nth-child(2) > div > i.yellow'));

  // Check if description of first finding is set.
  assertEquals(
      'script-src should not allow \'*\' as source',
      getText('div.directive-value:nth-child(1) > div > ul > li'));

}
