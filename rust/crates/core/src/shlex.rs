//! Python `shlex.quote`, `shlex.join` and POSIX `shlex.split`.

fn safe(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c)
}

pub fn quote(value: &str) -> String {
    if value.is_empty() {
        return "''".into();
    }
    if value.chars().all(safe) {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub fn join<S: AsRef<str>>(arguments: &[S]) -> String {
    arguments.iter().map(|a| quote(a.as_ref())).collect::<Vec<_>>().join(" ")
}

/// POSIX-mode `shlex.split` (no comments). Errors match Python's messages.
pub fn split(text: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut in_token = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if in_token {
                    tokens.push(std::mem::take(&mut token));
                    in_token = false;
                }
            }
            '\\' => {
                in_token = true;
                match chars.next() {
                    Some(next) => token.push(next),
                    None => return Err("No escaped character".into()),
                }
            }
            '\'' => {
                in_token = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(next) => token.push(next),
                        None => return Err("No closing quotation".into()),
                    }
                }
            }
            '"' => {
                in_token = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(next @ ('"' | '\\')) => token.push(next),
                            Some(next) => {
                                token.push('\\');
                                token.push(next);
                            }
                            None => return Err("No escaped character".into()),
                        },
                        Some(next) => token.push(next),
                        None => return Err("No closing quotation".into()),
                    }
                }
            }
            c => {
                in_token = true;
                token.push(c);
            }
        }
    }
    if in_token {
        tokens.push(token);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_and_round_trip() {
        assert_eq!(quote(""), "''");
        assert_eq!(quote("a/b-c.d"), "a/b-c.d");
        assert_eq!(quote("it's"), "'it'\"'\"'s'");
        let values = ["/var/mobile/path with spaces/$(touch unwanted);'endpoint", "", "x\"y\\z"];
        assert_eq!(split(&join(&values)).unwrap(), values);
        assert_eq!(split(r#"a "b \" c" 'd e'"#).unwrap(), vec!["a", "b \" c", "d e"]);
    }
}
