/**
 * Valida el dígito verificador de un RUT chileno.
 * Devuelve el RUT normalizado (sin puntos y con guión) o null si es inválido.
 */
export function validateRut(rut: string): {
  normalized: string;
  number: string;
  dv: string;
} | null {
  if (typeof rut !== 'string') return null;

  const cleaned = rut.replace(/\./g, '').replace(/-/g, '').trim().toUpperCase();
  const match = cleaned.match(/^(\d{1,8})([0-9K])$/);
  if (!match) return null;

  const [, numberPart, dv] = match;
  const calculatedDv = calculateDv(numberPart);

  if (calculatedDv !== dv) return null;

  return {
    normalized: `${parseInt(numberPart, 10)}-${dv}`,
    number: numberPart,
    dv,
  };
}

function calculateDv(numberPart: string): string {
  let sum = 0;
  let multiplier = 2;

  for (let i = numberPart.length - 1; i >= 0; i--) {
    sum += parseInt(numberPart[i], 10) * multiplier;
    multiplier = multiplier === 7 ? 2 : multiplier + 1;
  }

  const remainder = 11 - (sum % 11);
  if (remainder === 11) return '0';
  if (remainder === 10) return 'K';
  return String(remainder);
}
