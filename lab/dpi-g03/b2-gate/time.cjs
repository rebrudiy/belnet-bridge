'use strict';
// Exact UTC comparison; Date.parse alone would erase sub-millisecond ordering.
function utcNanoseconds(value) {
 if(typeof value!=='string')throw Error('UTC_TIMESTAMP_REQUIRED');
 const match=value.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/);
 if(!match)throw Error('UTC_TIMESTAMP_INVALID');
 const millis=Date.parse(match[1]+'Z');
 if(!Number.isFinite(millis)||new Date(millis).toISOString().slice(0,19)!==match[1])throw Error('UTC_TIMESTAMP_INVALID');
 return BigInt(millis)*1000000n+BigInt((match[2]||'').padEnd(9,'0'));
}
module.exports={utcNanoseconds};
