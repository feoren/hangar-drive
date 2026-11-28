// Compile-time check only (`pnpm exec tsc -p tools/readme-shots`): the modules run.mjs swaps in
// must offer everything the real ones of src/backend/mock offer, with the same types.

import type * as RealDevMock from "../../src/backend/mock/devMock";
import type * as RealFixtures from "../../src/backend/mock/fixtures";
import type * as RealScenarios from "../../src/backend/mock/scenarios";
import * as devMock from "./devMock";
import * as fixtures from "./fixtures";
import * as scenarios from "./scenarios";

/** A module's shape with its string constants widened: the README data may name other things. */
type Shape<M> = { readonly [K in keyof M]: M[K] extends string ? string : M[K] };

export const swaps: readonly [
  Shape<typeof RealFixtures>,
  typeof RealScenarios,
  typeof RealDevMock,
] = [fixtures, scenarios, devMock];
