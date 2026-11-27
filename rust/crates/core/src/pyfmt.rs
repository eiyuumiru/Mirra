//! Python `repr()`/`round()` formatting used in messages and JSON output.
use std::time::Duration;

/// `repr(str)`: single quotes unless the text contains `'` and no `"`.
pub fn repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (0x80..0xa0).contains(&(c as u32)) => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `repr(list_of_str)`, e.g. `['ssh', '-T']`.
pub fn repr_list<S: AsRef<str>>(items: &[S]) -> String {
    let parts: Vec<String> = items.iter().map(|s| repr_str(s.as_ref())).collect();
    format!("[{}]", parts.join(", "))
}

/// Python `repr(float)` (shortest round-trip digits, Python's layout rules).
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let text = format!("{:e}", value);
    let (sign, text) = match text.strip_prefix('-') {
        Some(rest) => ("-", rest.to_string()),
        None => ("", text),
    };
    let (mantissa, exponent) = text.split_once('e').unwrap();
    let exponent: i32 = exponent.parse().unwrap();
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let decpt = exponent + 1;
    let body = if -4 < decpt && decpt <= 16 {
        if decpt <= 0 {
            format!("0.{}{}", "0".repeat((-decpt) as usize), digits)
        } else if decpt as usize >= digits.len() {
            format!("{}{}.0", digits, "0".repeat(decpt as usize - digits.len()))
        } else {
            format!("{}.{}", &digits[..decpt as usize], &digits[decpt as usize..])
        }
    } else {
        let (first, rest) = digits.split_at(1);
        let mantissa = if rest.is_empty() { first.to_string() } else { format!("{}.{}", first, rest) };
        let exp = decpt - 1;
        format!("{}e{}{:02}", mantissa, if exp < 0 { '-' } else { '+' }, exp.abs())
    };
    format!("{}{}", sign, body)
}

/// Python `round(x)` for floats: half-to-even, as an integer.
pub fn round(value: f64) -> i64 {
    value.round_ties_even() as i64
}

/// Milliseconds as Python's `round((monotonic() - start) * 1000)`.
pub fn elapsed_ms(start: std::time::Instant) -> i64 {
    round(start.elapsed().as_secs_f64() * 1000.0)
}

/// A duration as the number Python callers would have passed (int when whole).
pub fn duration_seconds(duration: Duration) -> String {
    if duration.subsec_nanos() == 0 {
        duration.as_secs().to_string()
    } else {
        float_repr(duration.as_secs_f64())
    }
}

/// A duration as a JSON number (int when whole seconds, else float).
pub fn duration_json(duration: Duration) -> serde_json::Value {
    if duration.subsec_nanos() == 0 {
        serde_json::Value::from(duration.as_secs())
    } else {
        serde_json::Value::from(duration.as_secs_f64())
    }
}

/// Darwin signal names as Python's `signal.Signals` reports them.
pub fn signal_name(number: i32) -> Option<&'static str> {
    Some(match number {
        1 => "SIGHUP", 2 => "SIGINT", 3 => "SIGQUIT", 4 => "SIGILL", 5 => "SIGTRAP", 6 => "SIGABRT",
        7 => "SIGEMT", 8 => "SIGFPE", 9 => "SIGKILL", 10 => "SIGBUS", 11 => "SIGSEGV", 12 => "SIGSYS",
        13 => "SIGPIPE", 14 => "SIGALRM", 15 => "SIGTERM", 16 => "SIGURG", 17 => "SIGSTOP", 18 => "SIGTSTP",
        19 => "SIGCONT", 20 => "SIGCHLD", 21 => "SIGTTIN", 22 => "SIGTTOU", 23 => "SIGIO", 24 => "SIGXCPU",
        25 => "SIGXFSZ", 26 => "SIGVTALRM", 27 => "SIGPROF", 28 => "SIGWINCH", 29 => "SIGINFO",
        30 => "SIGUSR1", 31 => "SIGUSR2",
        _ => return None,
    })
}

/// Python `str.splitlines()` (without keepends).
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let breaks = matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}');
        if breaks {
            lines.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' {
                if let Some((_, '\n')) = chars.peek() {
                    chars.next();
                    end += 1;
                }
            }
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_matches_python() {
        let cases = [(1.0, "1.0"), (0.1, "0.1"), (1e16, "1e+16"), (1e15, "1000000000000000.0"), (0.0001, "0.0001"),
            (0.00001, "1e-05"), (1.5e-7, "1.5e-07"), (1e100, "1e+100"), (-2.5, "-2.5"), (123.456, "123.456"),
            (1763712000.123456, "1763712000.123456"), (1.2345678901234568e17, "1.2345678901234568e+17")];
        for (value, expected) in cases {
            assert_eq!(float_repr(value), expected);
        }
    }

    #[test]
    fn repr_and_round() {
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_list(&["ssh", "-T"]), "['ssh', '-T']");
        assert_eq!(round(2.5), 2);
        assert_eq!(round(3.5), 4);
        assert_eq!(splitlines("a\r\nb\rc\n"), vec!["a", "b", "c"]);
    }
}
