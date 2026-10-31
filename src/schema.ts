import { SafeError } from './contracts.ts';

export type JsonSchema = {
  type?: string;
  description?: string;
  enum?: readonly (string | number | boolean)[];
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  pattern?: string;
  items?: JsonSchema;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  additionalProperties?: boolean;
};

export type Validator<T> = {
  optional?: boolean;
  parse: (value: unknown, path: string) => T;
  toJsonSchema: () => JsonSchema;
};

function failField(path: string, reason: string): never {
  throw new SafeError(`Field [${path || 'root'}] failed: ${reason}`);
}

export function str(opts: {
  description?: string;
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
} = {}): Validator<string> {
  const minLength = opts.minLength ?? 1;
  const maxLength = opts.maxLength ?? 1024;
  return {
    parse(value, path) {
      if (typeof value !== 'string') failField(path, 'expected string');
      if (value.length < minLength || value.length > maxLength) failField(path, 'length out of bounds');
      if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) failField(path, 'contains control characters');
      if (opts.pattern && !opts.pattern.test(value)) failField(path, 'invalid format');
      return value;
    },
    toJsonSchema() {
      return {
        type: 'string',
        ...(opts.description ? { description: opts.description } : {}),
        minLength,
        maxLength,
        ...(opts.pattern ? { pattern: opts.pattern.source } : {}),
      };
    },
  };
}

export function int(opts: {
  description?: string;
  min?: number;
  max?: number;
} = {}): Validator<number> {
  return {
    parse(value, path) {
      if (!Number.isSafeInteger(value)) failField(path, 'expected integer');
      const n = Number(value);
      if (opts.min !== undefined && n < opts.min) failField(path, 'below minimum');
      if (opts.max !== undefined && n > opts.max) failField(path, 'above maximum');
      return n;
    },
    toJsonSchema() {
      return {
        type: 'integer',
        ...(opts.description ? { description: opts.description } : {}),
        ...(opts.min !== undefined ? { minimum: opts.min } : {}),
        ...(opts.max !== undefined ? { maximum: opts.max } : {}),
      };
    },
  };
}

export function bool(opts: { description?: string } = {}): Validator<boolean> {
  return {
    parse(value, path) {
      if (typeof value !== 'boolean') failField(path, 'expected boolean');
      return value;
    },
    toJsonSchema() {
      return {
        type: 'boolean',
        ...(opts.description ? { description: opts.description } : {}),
      };
    },
  };
}

export function enm<const T extends readonly string[]>(
  values: T,
  opts: { description?: string } = {},
): Validator<T[number]> {
  return {
    parse(value, path) {
      if (typeof value !== 'string' || !values.includes(value)) {
        failField(path, `expected one of ${values.join(', ')}`);
      }
      return value as T[number];
    },
    toJsonSchema() {
      return {
        type: 'string',
        enum: [...values],
        maxLength: Math.max(1024, ...values.map(v => v.length)),
        ...(opts.description ? { description: opts.description } : {}),
      };
    },
  };
}

export function arr<T>(
  item: Validator<T>,
  opts: { description?: string; minItems?: number; maxItems?: number } = {},
): Validator<T[]> {
  const minItems = opts.minItems ?? 0;
  const maxItems = opts.maxItems ?? 100;
  return {
    parse(value, path) {
      if (!Array.isArray(value)) failField(path, 'expected array');
      if (value.length < minItems || value.length > maxItems) failField(path, 'array length out of bounds');
      return value.map((entry, idx) => item.parse(entry, path ? `${path}.${idx}` : String(idx)));
    },
    toJsonSchema() {
      return {
        type: 'array',
        items: item.toJsonSchema(),
        ...(opts.description ? { description: opts.description } : {}),
      };
    },
  };
}

export function opt<T>(inner: Validator<T>): Validator<T | undefined> {
  return {
    optional: true,
    parse(value, path) {
      if (value === undefined) return undefined;
      return inner.parse(value, path);
    },
    toJsonSchema() {
      return inner.toJsonSchema();
    },
  };
}

type InferShape<S extends Record<string, Validator<any>>> = {
  [K in keyof S]: S[K] extends Validator<infer V> ? V : never;
};

export function obj<S extends Record<string, Validator<any>>>(
  shape: S,
  opts: { description?: string } = {},
): Validator<InferShape<S>> {
  const keys = Object.keys(shape);
  const required = keys.filter(k => !shape[k].optional);
  return {
    parse(value, path) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) failField(path, 'expected object');
      const record = value as Record<string, unknown>;
      for (const presentKey of Object.keys(record)) {
        if (!Object.hasOwn(shape, presentKey)) failField(path ? `${path}.${presentKey}` : presentKey, 'unexpected property');
      }
      const out: Record<string, unknown> = {};
      for (const key of keys) {
        const subPath = path ? `${path}.${key}` : key;
        if (!Object.hasOwn(record, key)) {
          if (!shape[key].optional) failField(subPath, 'missing required property');
          continue;
        }
        out[key] = shape[key].parse(record[key], subPath);
      }
      return out as InferShape<S>;
    },
    toJsonSchema() {
      return {
        type: 'object',
        additionalProperties: false,
        required,
        properties: Object.fromEntries(keys.map(k => [k, shape[k].toJsonSchema()])),
        ...(opts.description ? { description: opts.description } : {}),
      };
    },
  };
}

export function validateWithSchema<T>(schema: Validator<T>, value: unknown): T {
  return schema.parse(value, '');
}

