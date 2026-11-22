/*! Eretek Online Araçlar #74 — Log Maskeleme */
ERT.def('74', {
	luhn: function (d) { var s = 0, alt = false; for (var i = d.length - 1; i >= 0; i--) { var n = +d[i]; if (alt) { n *= 2; if (n > 9) { n -= 9; } } s += n; alt = !alt; } return s % 10 === 0; },
	tckn: function (d) { if (d.length !== 11 || d[0] === '0') { return false; } var a = d.split('').map(Number), o = a[0] + a[2] + a[4] + a[6] + a[8], e = a[1] + a[3] + a[5] + a[7]; if (((o * 7 - e) % 10 + 10) % 10 !== a[9]) { return false; } return (a.slice(0, 10).reduce(function (x, y) { return x + y; }, 0)) % 10 === a[10]; },
	iban: function (s) { s = s.replace(/\s/g, '').toUpperCase(); if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) { return false; } var r = s.slice(4) + s.slice(0, 4), m = 0; for (var i = 0; i < r.length; i++) { var ch = r[i], v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55); for (var j = 0; j < v.length; j++) { m = (m * 10 + +v[j]) % 97; } } return m === 1; },
	run: function (v, c) {
		var T = ERT.tools['74'], text = String(v.log || ''), map = {}, cnt = {}, ps = !!v.pseudo;
		if (!text.trim()) { throw c.fe('log', 'req'); }
		if (text.length > 2000000) { throw c.fe('log', 'big'); }
		var rep = function (kind, val) {
			cnt[kind] = (cnt[kind] || 0) + 1;
			if (!ps) { return '[' + kind + ']'; }
			map[kind] = map[kind] || {}; var k = val.toLowerCase();
			if (!map[kind][k]) { map[kind][k] = kind + '-' + (Object.keys(map[kind]).length + 1); }
			return map[kind][k];
		};
		var R = [];
		if (v.sec) {
			R.push(['SECRET', /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/g]);
			R.push(['SECRET', /\b(Bearer\s+)([A-Za-z0-9\-._~+/]{12,}=*)/g, 2]);
			R.push(['SECRET', /\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g]);
			R.push(['SECRET', /((?:password|passwd|pwd|parola|sifre|şifre|kennwort|passwort|secret|token|api[_-]?key|apikey|client_secret|access_key)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)/gi, 2]);
			R.push(['SECRET', /\b(AKIA[0-9A-Z]{16})\b/g]);
		}
		if (v.mail) { R.push(['EMAIL', /\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g]); }
		if (v.iban) { R.push(['IBAN', /\b([A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?)\b/g, 1, function (m) { return T.iban(m); }]); }
		if (v.card) { R.push(['CARD', /\b(\d(?:[ -]?\d){12,18})\b/g, 1, function (m) { var d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && T.luhn(d); }]); }
		if (v.tckn) { R.push(['TCKN', /\b(\d{11})\b/g, 1, function (m) { return T.tckn(m); }]); }
		if (v.mac) { R.push(['MAC', /\b((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})\b/g]); }
		if (v.ip) {
			R.push(['IP', /(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])/g]);
			R.push(['IP', /(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})(?![0-9A-Fa-f:])/g, 1, function (m) { return ERT.ip.parse6(m) !== null && /:.*:/.test(m); }]);
		}
		if (v.user) {
			R.push(['USER', /\b([A-Za-z0-9-]{2,15}\\)([A-Za-z0-9._$-]{2,64})/g, 2]);
			R.push(['USER', /((?:user(?:name)?|account|kullanici|kullanıcı|benutzer|login|uid)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)/gi, 2]);
			// sshd/PAM: "Failed password for invalid user admin from", "Accepted publickey for ayse from", "session opened for user root"
			R.push(['USER', /(\b(?:password|publickey|keyboard-interactive(?:\/pam)?|gssapi-with-mic|none) for (?:invalid user |illegal user )?)([^\s]+)(?= from )/g, 2]);
			R.push(['USER', /(\b(?:Invalid|Illegal) user )([^\s]+)(?= from )/g, 2]);
			R.push(['USER', /(\bsession (?:opened|closed) for user )([^\s(]+)/g, 2]);
		}
		if (v.extra) { c.lines(v.extra, 200, 'extra').forEach(function (w) { R.push(['TERM', new RegExp('(' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi')]); }); }
		var out = text;
		R.forEach(function (rule) {
			var kind = rule[0], re = rule[1], g = rule[2] || 1, chk = rule[3];
			out = out.replace(re, function () {
				var a = arguments, full = a[0], val = a[g];
				if (val === undefined || /^\[[A-Z]+\]$/.test(val) || /^[A-Z]+-\d+$/.test(val)) { return full; }
				if (chk && !chk(val)) { return full; }
				var pre = g === 2 ? a[1] : '';
				return pre + rep(kind, val) + (g === 2 ? full.slice(a[1].length + val.length) : full.slice(full.indexOf(val) + val.length));
			});
		});
		var tot = Object.keys(cnt).reduce(function (s, k) { return s + cnt[k]; }, 0);
		var msgs = [tot ? ['ok', c.t('done', { n: tot })] : ['warn', c.t('nothing')], ['warn', c.t('review')], ['info', c.t('local')]];
		var kv = Object.keys(cnt).map(function (k) { return [k, cnt[k]]; });
		return { big: c.t('big', { n: tot }), pre: { text: out }, kv: kv, msgs: msgs, x: { copy: out }, v: { out: out, counts: cnt } };
	}
});
