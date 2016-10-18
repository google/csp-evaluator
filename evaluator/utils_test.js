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
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.utilsTest');
goog.setTestOnly();

goog.require('csp.utils');

goog.require('goog.Uri');
goog.require('goog.array');
goog.require('goog.testing.jsunit');


function testGetSchemeFreeUrl() {
  assertEquals('*', csp.utils.getSchemeFreeUrl('https://*'));
  assertEquals('*', csp.utils.getSchemeFreeUrl('//*'));
  assertEquals('*', csp.utils.getSchemeFreeUrl('*'));
  assertEquals('test//*', csp.utils.getSchemeFreeUrl('test//*'));
}


TEST_BYPASSES = goog.array.map([
  '//googletagmanager.com/gtm/js',
  '//www.google.com/jsapi',
  '//ajax.googleapis.com/ajax/services/feed/load'
], url => new goog.Uri(url));


function testMatchWildcardUrlsMatchWildcardFreeHost() {
  var wildcardFreeHost = new goog.Uri('//www.google.com');
  var match = csp.utils.matchWildcardUrls(wildcardFreeHost, TEST_BYPASSES);
  assertEquals(wildcardFreeHost.getDomain(), match.getDomain());
}


function testMatchWildcardUrlsNoMatch() {
  var wildcardFreeHost = new goog.Uri('//www.foo.bar');
  var match = csp.utils.matchWildcardUrls(wildcardFreeHost, TEST_BYPASSES);
  assertNull(match);
}


function testMatchWildcardUrlsMatchWildcardHost() {
  var wildcardHost = new goog.Uri('https://*.google.com');
  var match = csp.utils.matchWildcardUrls(wildcardHost, TEST_BYPASSES);
  assertEquals('www.google.com', match.getDomain());
}


function testMatchWildcardUrlsNoMatchWildcardHost() {
  var wildcardHost = new goog.Uri('https://*.www.google.com');
  var match = csp.utils.matchWildcardUrls(wildcardHost, TEST_BYPASSES);
  assertNull(match);
}


function testMatchWildcardUrlsMatchWildcardHostWithPath() {
  var wildcardHostWithPath = new goog.Uri('//*.google.com/jsapi');
  var match = csp.utils.matchWildcardUrls(wildcardHostWithPath, TEST_BYPASSES);
  assertEquals('www.google.com', match.getDomain());
}


function testMatchWildcardUrlsNoMatchWildcardHostWithPath() {
  var wildcardHostWithPath = new goog.Uri('//*.google.com/wrongPath');
  var match = csp.utils.matchWildcardUrls(wildcardHostWithPath, TEST_BYPASSES);
  assertNull(match);
}


function testMatchWildcardUrlsMatchHostWithPathWildcard() {
  var hostWithPath = new goog.Uri('//ajax.googleapis.com/ajax/');
  var match = csp.utils.matchWildcardUrls(hostWithPath, TEST_BYPASSES);
  assertEquals('ajax.googleapis.com', match.getDomain());
}


function testMatchWildcardUrlsNoMatchHostWithoutPathWildcard() {
  var hostWithPath = new goog.Uri('//ajax.googleapis.com/ajax');
  var match = csp.utils.matchWildcardUrls(hostWithPath, TEST_BYPASSES);
  assertNull(match);
}
