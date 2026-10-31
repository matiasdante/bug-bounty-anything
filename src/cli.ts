import { safeErrorMessage } from './contracts.ts';
import { extractLangFlag } from './i18n.ts';
import type { Lang } from './i18n.ts';
import { commandSpecs, normalizeCommandArgs, parseCliInput, renderCommandHelp, renderHelp } from './commands.ts';

async function main(rawArgs: string[]): Promise<void> {
  let lang: Lang = 'es';
  let args: string[];
  try {
    const extracted = extractLangFlag(rawArgs);
    lang = extracted.lang;
    args = extracted.rest;
  } catch {
    console.error(renderHelp('es'));
    process.exitCode = 2;
    return;
  }

  const { command, rest } = normalizeCommandArgs(args);
  if (!command || ((command === '--help' || command === '-h') && !rest.length)) {
    console.log(renderHelp(lang));
    return;
  }
  if ((command === '--help' || command === '-h') && rest.length >= 1) {
    const target = normalizeCommandArgs(rest).command;
    const specific = target ? renderCommandHelp(target, lang) : null;
    if (specific) {
      console.log(specific);
      return;
    }
  }
  if (rest.length === 1 && (rest[0] === '--help' || rest[0] === '-h')) {
    const specific = renderCommandHelp(command, lang);
    if (specific) {
      console.log(specific);
      return;
    }
  }

  const spec = commandSpecs.find(s => s.name === command);
  let parsedInput: ReturnType<typeof parseCliInput>;
  try {
    if (!spec) throw new Error('Unknown command');
    parsedInput = parseCliInput(rest, spec, lang);
  } catch {
    console.error(renderHelp(lang));
    process.exitCode = 2;
    return;
  }

  try {
    const code = await spec.execute(parsedInput);
    if (code !== undefined) process.exitCode = code;
  } catch (error) {
    if (error instanceof Error && error.message === 'InvalidUsage') {
      console.error(renderHelp(lang));
      process.exitCode = 2;
      return;
    }
    // No exponer cuerpos de request, credenciales ni contenido hostil importado.
    console.error(`BBA: ${safeErrorMessage(error)}`);
    process.exitCode = 1;
  }
}

await main(process.argv.slice(2));
