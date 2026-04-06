export const ROMANIA_COUNTIES = [
  'Alba',
  'Arad',
  'Arges',
  'Bacau',
  'Bihor',
  'Bistrita-Nasaud',
  'Botosani',
  'Braila',
  'Brasov',
  'Bucuresti',
  'Buzau',
  'Calarasi',
  'Caras-Severin',
  'Cluj',
  'Constanta',
  'Covasna',
  'Dambovita',
  'Dolj',
  'Galati',
  'Giurgiu',
  'Gorj',
  'Harghita',
  'Hunedoara',
  'Ialomita',
  'Iasi',
  'Ilfov',
  'Maramures',
  'Mehedinti',
  'Mures',
  'Neamt',
  'Olt',
  'Prahova',
  'Salaj',
  'Satu Mare',
  'Sibiu',
  'Suceava',
  'Teleorman',
  'Timis',
  'Tulcea',
  'Valcea',
  'Vaslui',
  'Vrancea',
];

const BUCHAREST_CITY_KEYS = [
  'bucuresti',
  'bucharest',
  'municipiul bucuresti',
  'mun bucuresti',
];

export const cityToCountyMap = {
  'alba iulia': 'Alba',
  aiud: 'Alba',
  arad: 'Arad',
  pitesti: 'Arges',
  campulung: 'Arges',
  bacau: 'Bacau',
  onesti: 'Bacau',
  oradea: 'Bihor',
  bistrita: 'Bistrita-Nasaud',
  botosani: 'Botosani',
  braila: 'Braila',
  brasov: 'Brasov',
  bucuresti: 'Bucuresti',
  bucharest: 'Bucuresti',
  buzau: 'Buzau',
  calarasi: 'Calarasi',
  resita: 'Caras-Severin',
  cluj: 'Cluj',
  'cluj-napoca': 'Cluj',
  'cluj napoca': 'Cluj',
  turda: 'Cluj',
  constanta: 'Constanta',
  'sfantu gheorghe': 'Covasna',
  targoviste: 'Dambovita',
  craiova: 'Dolj',
  galati: 'Galati',
  giurgiu: 'Giurgiu',
  'targu jiu': 'Gorj',
  'miercurea ciuc': 'Harghita',
  deva: 'Hunedoara',
  slobozia: 'Ialomita',
  iasi: 'Iasi',
  volutari: 'Ilfov',
  voluntari: 'Ilfov',
  otopeni: 'Ilfov',
  'baia mare': 'Maramures',
  drobeta: 'Mehedinti',
  'drobeta turnu severin': 'Mehedinti',
  'targu mures': 'Mures',
  'piatra neamt': 'Neamt',
  slatina: 'Olt',
  ploiesti: 'Prahova',
  zalau: 'Salaj',
  'satu mare': 'Satu Mare',
  sibiu: 'Sibiu',
  suceava: 'Suceava',
  alexandria: 'Teleorman',
  timisoara: 'Timis',
  lugoj: 'Timis',
  tulcea: 'Tulcea',
  'ramnicu valcea': 'Valcea',
  vaslui: 'Vaslui',
  focsani: 'Vrancea',
};

const COUNTY_ALIASES = {
  'mun bucuresti': 'Bucuresti',
  'municipiul bucuresti': 'Bucuresti',
  bucuresti: 'Bucuresti',
  bucharest: 'Bucuresti',
};

export function normalizeRomanianText(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/\./g, '')
    .replace(/-/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function isRomaniaCountry(country = 'Romania') {
  const key = normalizeRomanianText(country);
  return key === 'romania' || key === 'ro';
}

export function isBucharestCityName(city = '') {
  return BUCHAREST_CITY_KEYS.includes(normalizeRomanianText(city));
}

export function normalizeRomanianCounty(county = '', country = 'Romania') {
  const raw = String(county || '').trim();
  if (!raw) return '';
  if (!isRomaniaCountry(country)) return raw;

  const key = normalizeRomanianText(raw);
  if (COUNTY_ALIASES[key]) return COUNTY_ALIASES[key];
  const fromKnownCounties = ROMANIA_COUNTIES.find(
    (entry) => normalizeRomanianText(entry) === key,
  );
  if (fromKnownCounties) return fromKnownCounties;

  return raw
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(' ');
}

export function inferCountyFromCity(city = '', country = 'Romania') {
  if (!isRomaniaCountry(country)) return '';
  const key = normalizeRomanianText(city);
  if (!key) return '';
  if (BUCHAREST_CITY_KEYS.includes(key)) return 'Bucuresti';
  return cityToCountyMap[key] || '';
}

export function isCityCountyMatch(city = '', county = '', country = 'Romania') {
  const normalizedCity = normalizeRomanianText(city);
  const normalizedCounty = normalizeRomanianCounty(county, country);
  if (!normalizedCity || !normalizedCounty) return true;

  const inferredCounty = inferCountyFromCity(city, country);
  if (!inferredCounty) return true;
  return normalizeRomanianText(inferredCounty) === normalizeRomanianText(normalizedCounty);
}
