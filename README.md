# CSP Evaluator Core Library

## Introduction

--------------------------------------------------------------------------------

Please note: this is not an official Google product.

CSP Evaluator allows developers and security experts to check if a Content
Security Policy ([CSP](https://csp.withgoogle.com/docs/index.html)) serves as a
strong mitigation against [cross-site scripting
attacks](https://www.google.com/about/appsecurity/learning/xss/). It assists
with the process of reviewing CSP policies, and helps identify subtle CSP
bypasses which undermine the value of a policy. CSP Evaluator checks are based
on a [large-scale study](https://research.google.com/pubs/pub45542.html) and are
aimed to help developers to harden their CSP and improve the security of their
applications. This tool (also available as a [Chrome
extension](https://chrome.google.com/webstore/detail/csp-evaluator/fjohamlofnakbnbfjkohkbdigoodcejf))
is provided only for the convenience of developers and Google provides no
guarantees or warranties for this tool.

CSP Evaluator comes with a built-in list of common CSP whitelist bypasses which
reduce the security of a policy. This list only contains popular bypasses and is
by no means complete.

The CSP Evaluator library + frontend is deployed here:
https://csp-evaluator.withgoogle.com/

## Build Prerequisites

--------------------------------------------------------------------------------

These instructions have been tested with the following software:

*   java >= 1.7 — for running the Closure Compiler
*   ant — for building CSP-Evaluator dependencies
*   git
*   curl
*   a web server
*   a browser with HTML5 support

## CSP Evaluator Setup

--------------------------------------------------------------------------------

These instructions assume a working directory of the repository root.

CSP Evaluator includes an easy-to-use setup script called `do.sh`. It supports
the following commands:

*   Setup: `./do.sh {install_deps|check_deps}`
*   Build: `./do.sh {build|build_templates} [debug]`
*   Cleanup: `./do.sh {clean|clean_deps}`

### Build

To build CSP Evaluator, run the following commands:

1.  `./do.sh install_deps`
1.  `./do.sh build`

### Local Demo Server

To run the demo locally, you can use the Python `SimpleHTTPServer`:

1.  `cd build`
1.  `python -m SimpleHTTPServer 9000`
1.  Navigate to http://localhost:9000/demo.html in your browser

### Example usage

If you don't want to make any customization you can also just embed the
compiled JS (`build/evaluator_binary.js`) and evaluate CSP like this:

```HTML
<html>
  <div id="csp_widget"></div>
  <script src="/evaluator_binary.js"></script>
  <script>
    var rawCsp = "script-src data: https://www.google.com;";
    var parser = new csp.CspParser(rawCsp);
    var evaluator = new csp.CspEvaluator(parser.csp, csp.Version.CSP3);
    var findings = evaluator.evaluate();
    var widget = new csp.ui.Widget(parser.csp, findings, csp.Version.CSP3);
  </script>
</html>
```
