# Log Masking Tool

Mask IPs, emails, MACs, usernames, passwords/tokens, card numbers, IBANs and Turkish IDs in logs in your browser; prepare logs for sharing with consistent pseudonyms.

## Try it live

- [Türkçe](https://siberguvenlik.eretek.com/araclar/log-maskeleme)
- [English](https://siberguvenlik.eretek.com/en/tools/log-masking)
- [Deutsch](https://siberguvenlik.eretek.com/de/werkzeuge/log-maskierung)

![Log Masking Tool: the worked example in the English interface](docs/screenshot.png)

## What it does

Masks personal and secret data on your device before you share logs with third parties.

Logs sent to vendor support, forums or consultants often contain customer IPs, email addresses, session tokens and even passwords. The tool recognises these values; in pseudonym mode the same value gets the same name everywhere (IP-1, EMAIL-1) so the log stays analysable. Card numbers are validated with Luhn, IBANs with mod-97 and Turkish ID numbers with their checksum before masking, reducing false positives.

## Where it helps

Pseudonym mode keeps relationships for troubleshooting; prefer label mode for logs handed over as a permanent archive. Masking is not an anonymization guarantee; context (time, device name) may still identify a person.

## How to use it

1. Paste the log text.
2. Choose data types to mask and between consistent pseudonyms or plain [TYPE] labels. Add extra words (server, customer names) one per line if needed.
3. Press Run; copy the masked text and review it before sending.

### Fields

| Field | Description |
|---|---|
| Log text | Up to 2 million characters. Data does not leave the browser. |
| Use consistent pseudonyms (IP-1, EMAIL-1) |  |
| IPv4 and IPv6 addresses |  |
| Email addresses |  |
| Passwords, tokens, API keys, private keys |  |
| Usernames (DOMAIN\user, user=) |  |
| MAC addresses |  |
| Card numbers (Luhn validated) |  |
| IBAN (mod-97 validated) |  |
| Turkish ID number (checksum validated) |  |
| Extra words to mask | One word per line; case-insensitive. |

## Example input

Press **Fill in example** in the tool to load this input.

| Input | Value |
|---|---|
| Use consistent pseudonyms (IP-1, EMAIL-1) | `yes` |
| IPv4 and IPv6 addresses | `yes` |
| Email addresses | `yes` |
| Passwords, tokens, API keys, private keys | `yes` |
| Usernames (DOMAIN\user, user=) | `yes` |
| MAC addresses | `yes` |
| Card numbers (Luhn validated) | `yes` |
| IBAN (mod-97 validated) | `yes` |
| Turkish ID number (checksum validated) | `yes` |

**Log text**

```text
2026-11-20 10:15:02 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 51522 ssh2
2026-11-20 10:15:09 sshd[2211]: Accepted password for ayse from 203.0.113.45 port 51530 ssh2
[web] POST /login user=mehmet.c@example.com password=Yaz2026! ip=198.51.100.7
api call Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig12345abcd
DHCPACK on 10.20.30.40 to 00:1a:2b:3c:4d:5e via eth0
CONTOSO\ali.yilmaz logged on to FS01
```

**Expected result:** 11 values masked: the same attacker IP is IP-1 on both lines, the email EMAIL-1, password and Bearer token SECRET, plus the MAC, the SSH user names admin and ayse, and the CONTOSO\ali.yilmaz username.

## Method and assumptions

Rules are applied in order: secrets, email, IBAN, card, Turkish ID, MAC, IP, username, extra words. Already masked values are not processed again.

Card: 13–19 digits and Luhn; IBAN: country code + mod-97 = 1; Turkish ID: 11 digits, first digit not 0, 10th and 11th digit algorithm. IPv6 is masked only if it parses as a valid address.

## Limits and common mistakes

- Personal names, postal addresses and phone numbers in free text are not recognised. No field-name-based masking inside multi-line JSON/XML.

## Run it locally

The tool is plain HTML, CSS and JavaScript with no build step and no dependencies.

```bash
git clone https://github.com/eretek/log-masking.git
cd log-masking
node scripts/serve.js        # or: python3 -m http.server 8080
```

Open <http://127.0.0.1:8080/>. Add `?lang=tr` or `?lang=de` for Turkish or German; without it the page follows the browser language and falls back to English. You can also open `index.html` directly from disk.

Run the tests (Node.js 18 or later):

```bash
node test/run.js    # or: npm test
```

The tests run the tool's own fixtures and the worked examples in all three languages without a browser.

## How it works

All processing happens in your browser. The tool makes no network requests, uses no cookies or browser storage, and does not upload files you select.

No server-side component is needed. The version on the Eretek website renders the same page through a private WordPress plugin; that plugin only produces the page markup and is not part of this repository.

| Path | Purpose |
|---|---|
| `index.html` | Page shell |
| `src/app.js` | Builds the page in Turkish, English or German from `src/data.js` |
| `src/data.js` | Field definitions, examples and all texts in three languages |
| `src/core.js` | Shared runtime: validation, number formats, result rendering, CSV/ICS export |
| `src/tool.js` | The calculation or analysis for this tool |
| `docs/screenshot.png` | Screenshot used in this README |
| `src/lib/ip.js` | IPv4/IPv6 library (BigInt) |
| `src/tools.css`, `src/page.css` | Styles |
| `test/run.js`, `test/cases.json` | Headless tests |

## License and attribution

This tool is released under the [Eretek Website Attribution License](LICENSE). You may use, modify and redistribute it, including commercially. If you make it available on a website or web application, show a visible, clickable credit linking to https://eretek.com/ on every page where the tool is available, for example:

```html
<a href="https://eretek.com/">Powered by Eretek</a>
```

You may add `rel="nofollow"` to the link. Keep the copyright notice and license text in copies and redistributions.
