/**
 * @fileoverview CSP Evaluator demo.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.Demo');
goog.require('csp.CspEvaluator');
goog.require('csp.CspParser');
goog.require('csp.ui.Widget');

/**
 * CSP Evaluator demo.
 * @export
 * @constructor
 */
csp.Demo = function() {
  var rawCsp = "script-src data: https://www.google.com;";
  var parser = new csp.CspParser(rawCsp);
  var evaluator = new csp.CspEvaluator(parser.csp, csp.Version.CSP3);
  var findings = evaluator.evaluate();
  var widget = new csp.ui.Widget(parser.csp, findings, csp.Version.CSP3);
};
