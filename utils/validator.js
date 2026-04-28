'use strict';

const { URL } = require('url');
const net = require('net');
const dns = require('dns').promises;

// ─── Private / Reserved CIDR Ranges ──────────────────────────────────────────
const BLOCKED_EXACT = [
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  'localhost',
];

/**
 * Convert an IPv4 address string to a 32-bit integer.
 */
function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * Return true if an IPv4 address falls inside a CIDR block.
 */
function inCidr(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(range) & mask);
}

// RFC-1918, link-local, loopback, documentation, carrier-grade NAT, etc.
const PRIVATE_CIDRS = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '127.0.0.0/8',
  '169.254.0.0/16',   // link-local
  '100.64.0.0/10',    // carrier-grade NAT
  '192.0.2.0/24',     // TEST-NET-1
  '198.51.100.0/24',  // TEST-NET-2
  '203.0.113.0/24',   // TEST-NET-3
  '224.0.0.0/4',      // multicast
  '240.0.0.0/4',      // reserved
];

/**
 * Return true if the given IPv4 address is private / reserved.
 */
function isPrivateIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  return PRIVATE_CIDRS.some((cidr) => inCidr(ip, cidr));
}

/**
 * Return true if the host is a blocked name or private IP.
 */
function isBlockedHost(host) {
  const lower = host.toLowerCase();

  // Exact block list
  if (BLOCKED_EXACT.includes(lower)) return true;

  // IPv4 private range
  if (net.isIPv4(lower) && isPrivateIPv4(lower)) return true;

  // IPv6 loopback / link-local
  if (net.isIPv6(lower)) {
    if (lower === '::1') return true;
    if (lower.startsWith('fe80')) return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA
  }

  return false;
}

// ─── URL Normalisation ────────────────────────────────────────────────────────

/**
 * Accept a raw domain or URL string and return a well-formed https:// URL.
 * Throws a structured error if the input is invalid.
 */
function normalizeUrl(raw) {
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    throw { statusCode: 400, message: 'Input must be a non-empty string.' };
  }

  let input = raw.trim();

  // Strip leading/trailing quotes that users sometimes paste
  input = input.replace(/^["']|["']$/g, '');

  // If no scheme is present, prepend https://
  if (!/^https?:\/\//i.test(input)) {
    input = `https://${input}`;
  }

  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    throw { statusCode: 400, message: `"${raw}" is not a valid URL or domain.` };
  }

  // Only http / https allowed
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw { statusCode: 400, message: 'Only http and https protocols are allowed.' };
  }

  // Normalise to https
  parsed.protocol = 'https:';

  // Remove default ports
  if (parsed.port === '443' || parsed.port === '80') {
    parsed.port = '';
  }

  return {
    normalizedUrl: parsed.toString(),
    domain: parsed.hostname,
    protocol: parsed.protocol,
  };
}

// ─── SSRF Guard ───────────────────────────────────────────────────────────────

/**
 * Resolve hostname DNS records and verify none of them point to a
 * private / reserved address.  Throws a structured error on block.
 *
 * This is called *after* normalizeUrl() so `hostname` is already validated.
 */
async function assertNotSSRF(hostname) {
  // Quick check on the raw hostname before DNS resolution
  if (isBlockedHost(hostname)) {
    throw {
      statusCode: 400,
      message: `Requests to "${hostname}" are not allowed (SSRF protection).`,
    };
  }

  // DNS-level check — resolve A / AAAA records and inspect them
  let addresses = [];
  try {
    const v4 = await dns.resolve4(hostname).catch(() => []);
    const v6 = await dns.resolve6(hostname).catch(() => []);
    addresses = [...v4, ...v6];
  } catch {
    // If DNS fails entirely, let the request attempt proceed;
    // the actual HTTP call will fail naturally.
    return;
  }

  for (const addr of addresses) {
    if (isBlockedHost(addr)) {
      throw {
        statusCode: 400,
        message: `"${hostname}" resolves to a private/reserved IP (SSRF protection).`,
      };
    }
  }
}

// ─── Main exported validator ──────────────────────────────────────────────────

/**
 * Validate, normalise, and SSRF-check the caller-supplied target.
 *
 * @param {*} target  Raw value from request body (expected string)
 * @returns {{ domain, normalizedUrl, protocol }}
 */
async function validateAndSanitize(target) {
  const { normalizedUrl, domain, protocol } = normalizeUrl(target);
  await assertNotSSRF(domain);
  return { normalizedUrl, domain, protocol };
}

module.exports = { validateAndSanitize };
