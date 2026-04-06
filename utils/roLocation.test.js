import assert from 'node:assert/strict';
import {
  inferCountyFromCity,
  isCityCountyMatch,
  normalizeRomanianCounty,
} from './roLocation.js';

assert.equal(inferCountyFromCity('Voluntari'), 'Ilfov');
assert.equal(inferCountyFromCity('Cluj-Napoca'), 'Cluj');
assert.equal(inferCountyFromCity('Timisoara'), 'Timis');
assert.equal(inferCountyFromCity('Timișoara'), 'Timis');
assert.equal(inferCountyFromCity('București'), 'Bucuresti');
assert.equal(inferCountyFromCity('Localitate Necunoscuta'), '');

assert.equal(isCityCountyMatch('Voluntari', 'Ilfov', 'Romania'), true);
assert.equal(isCityCountyMatch('Cluj Napoca', 'Cluj', 'Romania'), true);
assert.equal(isCityCountyMatch('Targu Mures', 'Mures', 'Romania'), true);
assert.equal(isCityCountyMatch('Bucharest', 'Bucuresti', 'Romania'), true);
assert.equal(isCityCountyMatch('Voluntari', 'Cluj', 'Romania'), false);
assert.equal(isCityCountyMatch('Localitate Necunoscuta', 'Ilfov', 'Romania'), true);

assert.equal(normalizeRomanianCounty('București', 'Romania'), 'Bucuresti');
assert.equal(normalizeRomanianCounty('mun. bucuresti', 'Romania'), 'Bucuresti');

console.log('roLocation tests: OK');
