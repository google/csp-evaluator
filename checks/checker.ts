/**
 * @fileoverview Shared interfaces for functions that check CSP policies.
 */

import { EnforcedCsps } from '../enforced_csps';
import {Finding} from '../finding';

/**
 * A function that checks a list of Csps for problems and returns an unordered
 * list of Findings.
 */
export type CheckerFunction = (csps: EnforcedCsps) => Finding[];
