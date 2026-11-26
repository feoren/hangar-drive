// Small decoders for what the Rust side answers. The window never trusts the shape of IPC data:
// every answer is checked against the expected type, so a mismatch between the two sides shows up
// as a clear "badResponse" error instead of a crash somewhere in a view.

export type Decoder<T> = (value: unknown, path: string) => T;

export class DecodeError extends Error {
  constructor(path: string, expected: string) {
    super(`${path || "value"}: expected ${expected}`);
    this.name = "DecodeError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export const str: Decoder<string> = (value, path) => {
  if (typeof value !== "string") throw new DecodeError(path, "string");
  return value;
};

export const num: Decoder<number> = (value, path) => {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new DecodeError(path, "number");
  return value;
};

export const bool: Decoder<boolean> = (value, path) => {
  if (typeof value !== "boolean") throw new DecodeError(path, "boolean");
  return value;
};

export const nothing: Decoder<null> = (value, path) => {
  if (value !== null && value !== undefined) throw new DecodeError(path, "nothing");
  return null;
};

export function literal<const T extends string>(...options: readonly T[]): Decoder<T> {
  return (value, path) => {
    const found = options.find((option) => option === value);
    if (found === undefined) throw new DecodeError(path, options.join(" | "));
    return found;
  };
}

export function nullable<T>(inner: Decoder<T>): Decoder<T | null> {
  return (value, path) => (value === null || value === undefined ? null : inner(value, path));
}

/** A field an older shell may leave out: absent (or null) reads as `fallback`. */
export function orDefault<T>(inner: Decoder<T>, fallback: T): Decoder<T> {
  return (value, path) => (value === null || value === undefined ? fallback : inner(value, path));
}

export function array<T>(inner: Decoder<T>): Decoder<T[]> {
  return (value, path) => {
    if (!Array.isArray(value)) throw new DecodeError(path, "array");
    return value.map((item: unknown, index) => inner(item, `${path}[${String(index)}]`));
  };
}

type Shape = Record<string, Decoder<unknown>>;
type Decoded<S extends Shape> = { [K in keyof S]: ReturnType<S[K]> };

export function object<S extends Shape>(shape: S): Decoder<Decoded<S>> {
  return (value, path) => {
    if (!isRecord(value)) throw new DecodeError(path, "object");
    const result: Record<string, unknown> = {};
    for (const [key, decoder] of Object.entries(shape)) {
      result[key] = decoder(value[key], path ? `${path}.${key}` : key);
    }
    return finish<Decoded<S>>(result);
  };
}

/**
 * A tagged union: `tag` names the field (usually "kind"), each variant decodes the rest.
 * The tag itself is put back on the result.
 */
export function union<const Tag extends string, V extends Record<string, Shape>>(
  tag: Tag,
  variants: V,
): Decoder<{ [K in keyof V & string]: Decoded<V[K]> & Record<Tag, K> }[keyof V & string]> {
  return (value, path) => {
    if (!isRecord(value)) throw new DecodeError(path, "object");
    const kind = value[tag];
    if (typeof kind !== "string" || !Object.hasOwn(variants, kind)) {
      throw new DecodeError(path ? `${path}.${tag}` : tag, Object.keys(variants).join(" | "));
    }
    const shape = variants[kind];
    const rest = shape ? object(shape)(value, path) : {};
    return finish({ ...rest, [tag]: kind });
  };
}

/**
 * The one place that turns a checked object into its static type. Every field was decoded by the
 * decoder of its key just before, so the cast cannot lie.
 */
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- see above
function finish<T>(checked: object): T {
  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions -- see the comment above
  return checked as T;
}
