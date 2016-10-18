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
 * @fileoverview Provides a UI widget to show a CSP and corresponding findings.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

goog.provide('csp.ui');
goog.provide('csp.ui.ColoredIcon');
goog.provide('csp.ui.Directive');
goog.provide('csp.ui.DirectiveValue');
goog.provide('csp.ui.Finding');
goog.provide('csp.ui.Icon');
goog.provide('csp.ui.Widget');

goog.require('csp.Csp');
goog.require('csp.Finding');
goog.require('csp.ui.templates');
goog.require('goog.array');
goog.require('goog.debug.Console');
goog.require('goog.dom');
goog.require('goog.dom.TagName');
goog.require('goog.events');
goog.require('goog.log');
goog.require('goog.soy');
goog.require('goog.ui.AnimatedZippy');
goog.require('goog.ui.Tooltip');


/**
 * CSP widget icons.
 * @enum {string}
 */
csp.ui.Icon = {
  OK: 'check',
  INFO: 'info_outline',
  ERROR: 'error',
  MAYBE: 'help_outline',
  SYNTAX: 'clear',
  IGNORED: 'remove',
  STRICT: 'local_atm'
};


/**
 * CSP widget colors.
 * @enum {string}
 */
csp.ui.Color = {
  GREEN: 'green',
  BLUE: 'blue',
  YELLOW: 'yellow',
  RED: 'red',
  PURPLE: 'purple',
  PINK: 'pink',
  GREY: 'grey'
};


/**
 * Icon with Color.
 * @param {!csp.ui.Color} color
 * @param {!csp.ui.Icon} icon
 * @param {string} altText
 * @constructor
 * @struct
 */
csp.ui.ColoredIcon = function(color, icon, altText) {
  /** @type {!csp.ui.Color} */
  this.color = color;

  /** @type {!csp.ui.Icon} */
  this.icon = icon;

  /** @type {string} */
  this.altText = altText;
};


/**
 * UI finding object.
 * @param {string} description Description of the finding.
 * @param {!csp.ui.ColoredIcon} coloredIcon Icon and color of the finding.
 * @param {string=} opt_value The directive value this finding belongs to.
 * @constructor
 * @struct
 */
csp.ui.Finding = function(description, coloredIcon, opt_value) {
  /** @type {string} */
  this.description = description;

  /** @type {string|undefined} */
  this.value = opt_value;

  /** @type {!csp.ui.ColoredIcon} */
  this.coloredIcon = coloredIcon;
};


/**
 * CSP directive value UI element.
 * @param {string} value The directive value.
 * @param {!csp.ui.ColoredIcon} coloredIcon Icon to be rendered next to value.
 * @param {!Array.<!csp.ui.Finding>} findings Findings for this value.
 * @constructor
 * @struct
 */
csp.ui.DirectiveValue = function(value, coloredIcon, findings) {
  /** @type {string} */
  this.value = value;

  /** @type {!csp.ui.ColoredIcon} */
  this.coloredIcon = coloredIcon;

  /** @type {!Array.<!csp.ui.Finding>} */
  this.findings = findings;

  /** @type {boolean} */
  this.isIgnored = false;
};


/**
 * CSP directive value UI element.
 * @param {!csp.Directive} directive The CSP directive.
 * @param {!Array.<!csp.ui.DirectiveValue>} values Directive values.
 * @param {!csp.ui.ColoredIcon} coloredIcon Icon to be rendered next to value.
 * @param {!Array.<!csp.ui.Finding>} directiveLevelFindings Directive findings.
 * @param {boolean=} opt_isMissing Directive is missing.
 * @constructor
 * @struct
 */
csp.ui.Directive = function(
    directive, values, coloredIcon, directiveLevelFindings, opt_isMissing) {
  /** @type {!csp.Directive} */
  this.directive = directive;

  /** @type {!Array.<!csp.ui.DirectiveValue>} */
  this.values = values;

  /** @type {!csp.ui.ColoredIcon} */
  this.coloredIcon = coloredIcon;

  /** @type {!Array.<!csp.ui.Finding>} */
  this.directiveLevelFindings = directiveLevelFindings;

  /** @type {boolean} */
  this.isMissing = opt_isMissing || false;

  /** @type {boolean} */
  this.isIgnored = false;
};


/**
 * A class to hold a CSP widget.
 *
 * If no value for opt_domElement is provided the widget will be rendered in an
 * element with id "csp_widget".
 *
 * @param {!csp.Csp} parsedCsp A parsed Content Security Policy.
 * @param {!Array.<!csp.Finding>} findings CSP findings.
 * @param {!csp.Version} cspVersion CSP version.
 * @param {!Element=} opt_domElement Element where widget should be rendered.
 * @param {boolean=} opt_disableLegend If true, legend will not be shown.
 * @constructor
 * @export
 */
csp.ui.Widget = function(
  parsedCsp, findings, cspVersion, opt_domElement, opt_disableLegend) {
  goog.debug.Console.autoInstall();
  /** @private {?goog.debug.Logger} */
  this.logger_ = goog.log.getLogger('csp.CspEvaluator');

  /** @type {!csp.Csp} */
  this.csp = parsedCsp;

  /** @type {!csp.Csp} */
  this.effectiveCsp = csp.Csp.getEffectiveCsp(parsedCsp, cspVersion);

  /** @type {!Array.<!csp.Finding>} */
  this.findings = findings;

  /** @type {!csp.Version} */
  this.cspVersion = cspVersion;

  /** @type {?Element} */
  this.element = opt_domElement || goog.dom.getElement('csp_widget');

  /** @type {?boolean} */
  this.disableLegend = opt_disableLegend || false;

  /** @type {?boolean} */
  this.expand = true;

  if (!this.element) {
    goog.log.error(this.logger_, 'No DOM-Element for rendering provided.');
    return;
  }

  this.render();
};


/**
 * Renders the CSP widget.
 * @export
 */
csp.ui.Widget.prototype.render = function() {
  var uiModel = this.markIgnoredDirectivesAndValues_(this.buildModel_());

  var widgetContainer = this.element;
  goog.dom.removeChildren(widgetContainer);
  var widgetCss = goog.soy.renderAsElement(csp.ui.templates.CspWidgetCss, {});
  widgetContainer.appendChild(widgetCss);
  var widget =
      goog.soy.renderAsElement(
        csp.ui.templates.CspWidget,
        {uiModel: uiModel, cspVersion: this.cspVersion});
  widgetContainer.appendChild(widget);

  var childs = goog.dom.getChildren(
      goog.dom.getElementByClass('evaluated-csp', widget));
  var zippies = [];
  for (var child, i = 0; child = childs[i]; i++) {
    var headerElement = goog.dom.getFirstElementChild(child);
    var bodyElement = goog.dom.getLastElementChild(child);
    var zippy = new goog.ui.AnimatedZippy(headerElement, bodyElement);
    zippy.animationDuration = 200;
    zippies.push(zippy);
  }

  var expand_all = goog.dom.getElement('expand_all');
  goog.events.listen(
      expand_all, goog.events.EventType.CLICK, goog.bind(function(e) {
        zippies.forEach(zippy => zippy.setExpanded(this.expand));
        this.expand = !this.expand;
      }, this));


  // Initialize tooltips.
  var cells = goog.dom.getElementsByClass('col', widget);
  for (var cell, i = 0; cell = cells[i]; i++) {
    if (cell.hasAttribute('data-tooltip')) {
      var tooltipText = cell.getAttribute('data-tooltip');
      var tooltip = new goog.ui.Tooltip(cell, tooltipText);
    }
  }

  // Render legend if not disabled.
  if (!this.disableLegend) {
    var legendDiv = goog.dom.createElement(goog.dom.TagName.DIV);
    this.renderLegend(legendDiv);
    widgetContainer.appendChild(legendDiv);
  }
};


/**
 * Renders a legend for the CSP widget icons.
 * @param {!Element} domElement Element where legend should be rendered.
 * @export
 */
csp.ui.Widget.prototype.renderLegend = function(domElement) {
  var legendSeverities = [
    csp.Finding.Severity.HIGH,
    csp.Finding.Severity.MEDIUM,
    csp.Finding.Severity.HIGH_MAYBE,
    csp.Finding.Severity.MEDIUM_MAYBE,
    csp.Finding.Severity.SYNTAX,
    csp.Finding.Severity.INFO,
    csp.Finding.Severity.NONE
  ];
  var legendItems = goog.array.map(
      legendSeverities, this.translateSeverity_, this);
  var ignoreIcon = new csp.ui.ColoredIcon(
          csp.ui.Color.GREY, csp.ui.Icon.IGNORED,
          'Directive/value is ignored in this version of CSP');
  goog.array.insertAt(legendItems, ignoreIcon, 3);
  goog.dom.removeChildren(domElement);
  var legend = goog.soy.renderAsElement(
      csp.ui.templates.CspWidgetLegend, {items: legendItems});
  domElement.appendChild(legend);
  var zippy = new goog.ui.AnimatedZippy(
      goog.dom.getElementByClass('title', legend),
      goog.dom.getElementByClass('legend', legend),
      true);
  zippy.animationDuration = 200;
 };


/**
 * Builds a data model to render the CSP and corresponding findings in the UI.
 * Every directive in the parsed CSP is annotated with directive and value level
 * findings, corresponding icons and colors that should be displayed.
 * @return {!Array.<!csp.ui.Directive>} Data model for CSP Widget.
 * @private
 */
csp.ui.Widget.prototype.buildModel_ = function() {
  var findingsByDirective = {};
  var sortedFindings = this.findings.sort((a, b) => a.severity - b.severity);

  // Group findings by directive. Most severe findings first.
  for (let finding of sortedFindings) {
    if (!(finding.directive in findingsByDirective)) {
      findingsByDirective[finding.directive] = [];
    }
    findingsByDirective[finding.directive].push(finding);
  }

  var uiModel = [];
  var directives =
      new Set(Object.keys(this.csp).concat(Object.keys(findingsByDirective)));
  for (let directive of directives.values()) {
    var uiDirectiveValues = [];
    var findings = findingsByDirective[directive] || [];
    var directiveValues = this.csp[directive] || [];

    for (let value of directiveValues) {
      var uiFindings = [];
      var valueFindings = goog.array.filter(findings, f => f.value == value);

      // Generate findings for directive values.
      for (let finding of valueFindings) {
        var coloredIcon = this.translateSeverity_(finding.severity);
        var uiFinding =
            new csp.ui.Finding(finding.description, coloredIcon, finding.value);
        uiFindings.push(uiFinding);
      }

      // Generate UI elements for directive values
      var coloredIcon = this.translateSeverity_(
          csp.Finding.getHighestSeverity(valueFindings));
      var directiveValue =
          new csp.ui.DirectiveValue(value, coloredIcon, uiFindings);
      uiDirectiveValues.push(directiveValue);
    }

    // Generate findings for directives.
    var uiDirectiveFindings = [];
    var directiveFindings =
        goog.array.filter(findings, f => !goog.isDef(f.value));
    for (let finding of directiveFindings) {
      var coloredIcon = this.translateSeverity_(finding.severity);
      var uiFinding =
          new csp.ui.Finding(finding.description, coloredIcon, undefined);
      uiDirectiveFindings.push(uiFinding);
    }

    // Generate UI elements for directives
    var coloredIcon =
        this.translateSeverity_(csp.Finding.getHighestSeverity(findings));
    var isMissing = !(directive in this.csp);
    var uiDirective = new csp.ui.Directive(
        directive, uiDirectiveValues, coloredIcon, uiDirectiveFindings,
        isMissing);
    uiModel.push(uiDirective);
  }

  return uiModel;
};


/**
 * Marks CSP directives and values as ignored, if not present in CSP version.
 * @param {!Array.<!csp.ui.Directive>} uiModel Data model for CSP Widget.
 * @return {!Array.<!csp.ui.Directive>} Data model for CSP Widget.
 * @private
 */
csp.ui.Widget.prototype.markIgnoredDirectivesAndValues_ = function(uiModel) {
  var ignoreIcon =
      new csp.ui.ColoredIcon(
          csp.ui.Color.GREY, csp.ui.Icon.IGNORED,
          'Directive/Value is ignored in this version of CSP');
  for (let uiDirective of uiModel) {
    if (!uiDirective.isMissing &&
        !(uiDirective.directive in this.effectiveCsp)) {
      uiDirective.isIgnored = true;
      uiDirective.coloredIcon = ignoreIcon;
    }

    var effectiveValues = this.effectiveCsp[uiDirective.directive] || [];
    for (let uiValue of uiDirective.values) {
      if (!goog.array.contains(effectiveValues, uiValue.value)) {
        uiValue.isIgnored = true;
        uiValue.coloredIcon = ignoreIcon;
      }
    }
  }

  return uiModel;
};


/**
 * Translates a severity into a color and an icon.
 * @param {!csp.Finding.Severity} severity A severity.
 * @return {!csp.ui.ColoredIcon} Corresponding icon with color.
 * @private
 */
csp.ui.Widget.prototype.translateSeverity_ = function(severity) {
  if (severity == csp.Finding.Severity.NONE) {
    return new csp.ui.ColoredIcon(
        csp.ui.Color.GREEN, csp.ui.Icon.OK, 'All good');
  } else if (severity == csp.Finding.Severity.INFO) {
    return new csp.ui.ColoredIcon(
        csp.ui.Color.BLUE, csp.ui.Icon.INFO, 'Information');
  } else if (severity == csp.Finding.Severity.STRICT_CSP) {
    return new csp.ui.ColoredIcon(csp.ui.Color.PINK, csp.ui.Icon.STRICT,
        'Hints for making CSP strict and backward-compatible.');
  } else if (severity == csp.Finding.Severity.MEDIUM_MAYBE) {
    return new csp.ui.ColoredIcon(
        csp.ui.Color.YELLOW, csp.ui.Icon.MAYBE,
        'Possible medium severity finding');
  } else if (severity == csp.Finding.Severity.HIGH_MAYBE) {
    return new csp.ui.ColoredIcon(
        csp.ui.Color.RED, csp.ui.Icon.MAYBE, 'Possible high severity finding');
  } else if (severity == csp.Finding.Severity.MEDIUM) {
    return new csp.ui.ColoredIcon(
        csp.ui.Color.YELLOW, csp.ui.Icon.ERROR, 'Medium severity finding');
  } else if (severity == csp.Finding.Severity.HIGH) {
    return new csp.ui.ColoredIcon(
        csp.ui.Color.RED, csp.ui.Icon.ERROR, 'High severity finding');
  } else if (severity == csp.Finding.Severity.SYNTAX) {
    return new csp.ui.ColoredIcon(
        csp.ui.Color.PURPLE, csp.ui.Icon.SYNTAX, 'Syntax error');
  }

  // Fallback to OK.
  return new csp.ui.ColoredIcon(
      csp.ui.Color.GREEN, csp.ui.Icon.OK, 'All good');
};
