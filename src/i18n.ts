import { SafeError } from './contracts.ts';

export type Lang = 'es' | 'en';

export function parseLang(value: unknown): Lang {
  if (value === undefined || value === null || value === '' || value === 'es') return 'es';
  if (value === 'en') return 'en';
  throw new SafeError('Unsupported language; expected es or en');
}

// Extrae --lang es|en de la lista de argumentos de CLI sin alterar el resto de flags posicionales.
export function extractLangFlag(args: string[]): { lang: Lang; rest: string[] } {
  let lang: Lang = 'es';
  const rest: string[] = [];
  let seen = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--lang') {
      if (seen) throw new SafeError('Duplicate --lang flag');
      const next = args[i + 1];
      if (!next || next.startsWith('--')) throw new SafeError('Missing value for --lang; expected es or en');
      lang = parseLang(next);
      seen = true;
      i++;
    } else {
      rest.push(args[i]);
    }
  }
  return { lang, rest };
}

export function pickText(lang: Lang, es: string, en: string): string {
  return lang === 'en' ? en : es;
}

