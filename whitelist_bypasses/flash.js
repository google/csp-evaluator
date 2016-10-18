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
 * @fileoverview Collection of popular sites/CDNs hosting flash with user
 * provided JS.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.whitelistBypasses.flash');

goog.require('goog.Uri');
goog.require('goog.array');


/**
 * Domains that would allow a CSP bypass if whitelisted.
 * Only most common paths will be listed here. Hence there might still be other
 * paths on these domains that would allow a bypass.
 * @type {!Array.<!goog.Uri>}
 */
csp.whitelistBypasses.flash.URLS = goog.array.map([
  '//vk.com/swf/video.swf',
  '//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'
], url => new goog.Uri(url));
