/* eslint-disable @typescript-eslint/no-var-requires */
import * as fs from 'fs';
import * as path from 'path';
import mongoose, { Schema as MongooseSchema, SchemaTypeOptions } from 'mongoose';

type SchemaExport = {
  schema: mongoose.Schema;
  modelName: string;
  filePath: string;
};

const rootDir = path.resolve(__dirname, '..');
const srcDir = path.join(rootDir, 'src');
const outputPath = path.join(rootDir, 'data-dictionary.md');

function isSchemaInstance(value: unknown): value is mongoose.Schema {
  return value instanceof MongooseSchema;
}

function isClass(value: unknown): value is { name: string } {
  return typeof value === 'function' && value.prototype;
}

function readDirectoryRecursive(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === 'dist') {
      continue;
    }

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      files.push(...readDirectoryRecursive(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.schema.ts')) {
      files.push(fullPath);
    }
  }

  return files;
}

function collectSchemaExports(): SchemaExport[] {
  const schemaFiles = readDirectoryRecursive(srcDir);
  const exports: SchemaExport[] = [];

  for (const file of schemaFiles) {
    // eslint-disable-next-line global-require, @typescript-eslint/no-require-imports
    const moduleExports = require(file);
    const classCandidates = Object.entries(moduleExports)
      .filter(([, value]) => isClass(value))
      .map(([key, value]) => ({ exportName: key, classRef: value as { name: string } }));

    for (const [exportName, exportedValue] of Object.entries(moduleExports)) {
      if (!isSchemaInstance(exportedValue)) {
        continue;
      }

      const expectedClassName = exportName.replace(/Schema$/, '');
      const classMatch =
        classCandidates.find((candidate) => candidate.exportName === expectedClassName) ??
        classCandidates.find((candidate) => candidate.classRef.name === expectedClassName);

      const modelName =
        classMatch?.classRef?.name ??
        (expectedClassName ? expectedClassName.charAt(0).toUpperCase() + expectedClassName.slice(1) : exportName);

      exports.push({
        schema: exportedValue,
        modelName,
        filePath: path.relative(rootDir, file),
      });
    }
  }

  exports.sort((a, b) => a.modelName.localeCompare(b.modelName));

  return exports;
}

function boolToText(value: unknown): string {
  if (typeof value === 'function') {
    return 'Depende';
  }

  const normalized = Array.isArray(value) ? value[0] : value;
  return normalized ? 'Sí' : 'No';
}

function defaultToString(value: unknown): string {
  if (value === undefined) {
    return '';
  }

  if (typeof value === 'function') {
    return value.name ? `${value.name}()` : 'Función';
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

type SchemaTypeWithOptionalCaster = mongoose.SchemaType & {
  caster?: (mongoose.SchemaType & {
    options?: SchemaTypeOptions<unknown> & { ref?: string };
    instance?: string;
  }) | null;
  options?: SchemaTypeOptions<unknown> & { ref?: string };
  defaultValue?: unknown;
};

function pathTypeToString(schemaType: mongoose.SchemaType): string {
  const schemaTypeWithCaster = schemaType as SchemaTypeWithOptionalCaster;

  if (schemaType.instance === 'Array') {
    const caster = schemaTypeWithCaster.caster;
    const casterInstance = caster?.instance ?? 'Mixed';
    const arrayRef = caster?.options?.ref;
    const casterLabel = arrayRef ? `Ref:${arrayRef}` : casterInstance;
    return `Array<${casterLabel}>`;
  }

  const directRef = schemaTypeWithCaster.options?.ref;
  if (directRef) {
    return `ObjectId→${directRef}`;
  }

  if (schemaType.instance === 'ObjectID' || schemaType.instance === 'ObjectId') {
    const ref = schemaTypeWithCaster.options?.ref;
    return ref ? `ObjectId→${ref}` : 'ObjectId';
  }

  return schemaType.instance ?? 'Mixed';
}

function buildMarkdownTable(schemaExport: SchemaExport): string {
  const { schema, modelName, filePath } = schemaExport;
  const collectionName =
    schema.get('collection') ||
    (() => {
      if (mongoose.models[modelName]) {
        mongoose.deleteModel(modelName);
      }
      const tempModel = mongoose.model(modelName, schema);
      const computedName = tempModel.collection.collectionName;
      mongoose.deleteModel(modelName);
      return computedName;
    })();

  const timestampsEnabled =
    typeof schema.options.timestamps === 'object' || schema.options.timestamps === true ? 'Sí' : 'No';

  const fieldNames = Object.keys(schema.paths).filter((name) => !['__v'].includes(name));
  const rows = fieldNames.map((fieldName) => {
    const schemaType = schema.path(fieldName) as SchemaTypeWithOptionalCaster;
    const options = schemaType.options;
    const ref = options?.ref ?? schemaType.caster?.options?.ref;

    const columns = [
      fieldName,
      pathTypeToString(schemaType),
      boolToText(options?.required),
      boolToText(options?.unique),
      ref ?? '',
      defaultToString(options?.default ?? (schemaType as any).defaultValue),
    ];

    return `| ${columns.map((value) => (value ? value : '')).join(' | ')} |`;
  });

  const header = '| Campo | Tipo | Requerido | Único | Referencia | Default |';
  const divider = '| --- | --- | --- | --- | --- | --- |';

  return [
    `## ${collectionName} (\`${modelName}\`)`,
    '',
    `- Fuente del esquema: \`${filePath}\``,
    `- Timestamps automáticos: ${timestampsEnabled}`,
    '',
    header,
    divider,
    ...rows,
    '',
  ].join('\n');
}

function generateDataDictionary(): void {
  const schemas = collectSchemaExports();

  if (schemas.length === 0) {
    throw new Error('No se encontraron esquemas de Mongoose en el proyecto.');
  }

  const content = [
    '# Diccionario de Datos',
    '',
    `Generado automáticamente el ${new Date().toISOString()}.`,
    '',
    ...schemas.map((schemaExport) => buildMarkdownTable(schemaExport)),
  ].join('\n');

  fs.writeFileSync(outputPath, content, 'utf8');
  // eslint-disable-next-line no-console
  console.log(`Diccionario de datos generado en ${path.relative(process.cwd(), outputPath)}`);
}

generateDataDictionary();
