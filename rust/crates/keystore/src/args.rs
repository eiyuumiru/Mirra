//! The subset of `argparse` behavior the broker and sharing commands use:
//! long options (`--name value`, `--name=value`, unique prefixes), flags,
//! required options, one mutually exclusive group, `-h/--help`, and
//! argparse's error messages (`usage` + `prog: error: ...`, exit status 2).
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Opt {
    pub name: &'static str,
    pub takes_value: bool,
    pub required: bool,
    /// `None` = `help=argparse.SUPPRESS`.
    pub help: Option<&'static str>,
    /// Members of the same group exclude each other.
    pub group: Option<u8>,
}

impl Opt {
    pub const fn value(name: &'static str) -> Self {
        Opt { name, takes_value: true, required: false, help: Some(""), group: None }
    }
    pub const fn flag(name: &'static str) -> Self {
        Opt { name, takes_value: false, required: false, help: Some(""), group: None }
    }
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }
    pub const fn suppressed(mut self) -> Self {
        self.help = None;
        self
    }
    pub const fn help(mut self, help: &'static str) -> Self {
        self.help = Some(help);
        self
    }
    pub const fn group(mut self, group: u8) -> Self {
        self.group = Some(group);
        self
    }
    fn metavar(&self) -> String {
        self.name.trim_start_matches('-').replace('-', "_").to_uppercase()
    }
}

pub struct Parser {
    pub prog: &'static str,
    pub description: &'static str,
    /// Exact usage text (argparse wraps at the terminal width).
    pub usage: &'static str,
    pub options: Vec<Opt>,
}

#[derive(Debug, Default)]
pub struct Parsed {
    values: HashMap<&'static str, String>,
    flags: Vec<&'static str>,
}

impl Parsed {
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
    pub fn flag(&self, name: &str) -> bool {
        self.flags.contains(&name)
    }
}

/// `Err(status)` after argparse printed help (0) or an error (2).
pub type Outcome = Result<Parsed, i32>;

fn looks_like_negative_number(text: &str) -> bool {
    let body = text.strip_prefix('-').unwrap_or("");
    !body.is_empty() && body.parse::<f64>().is_ok() && !body.starts_with(['+', '-'])
}

impl Parser {
    pub fn error(&self, message: &str) -> i32 {
        eprintln!("{}{}: error: {}", self.usage, self.prog, message);
        2
    }

    fn help(&self) -> String {
        let mut text = format!("{}\n{}\n\noptions:\n  -h, --help            show this help message and exit\n", self.usage, self.description);
        for option in &self.options {
            let Some(help) = option.help else { continue };
            let head = if option.takes_value { format!("{} {}", option.name, option.metavar()) } else { option.name.to_string() };
            if help.is_empty() {
                text.push_str(&format!("  {}\n", head));
            } else if head.len() <= 20 {
                text.push_str(&format!("  {:<22}{}\n", head, help));
            } else {
                text.push_str(&format!("  {}\n                        {}\n", head, help));
            }
        }
        text
    }

    fn lookup(&self, name: &str) -> Result<Option<&Opt>, String> {
        if name == "-h" || name == "--help" {
            return Ok(None);
        }
        if let Some(exact) = self.options.iter().find(|o| o.name == name) {
            return Ok(Some(exact));
        }
        let candidates = std::iter::once(&HELP).chain(self.options.iter());
        let matches: Vec<&Opt> = candidates.filter(|o| name.len() > 2 && name.starts_with("--") && o.name.starts_with(name)).collect();
        match matches.len() {
            0 => Err(String::new()),
            1 if matches[0].name == HELP.name => Ok(None),
            1 => Ok(Some(matches[0])),
            _ => Err(format!("ambiguous option: {} could match {}", name,
                matches.iter().map(|o| o.name).collect::<Vec<_>>().join(", "))),
        }
    }

    /// Parse `args` (`sys.argv[1:]`).
    pub fn parse(&self, args: &[String]) -> Outcome {
        let mut parsed = Parsed::default();
        let mut unrecognized: Vec<String> = Vec::new();
        let mut seen_groups: HashMap<u8, &'static str> = HashMap::new();
        let mut index = 0;
        let mut only_positionals = false;
        while index < args.len() {
            let argument = &args[index];
            index += 1;
            if only_positionals || !argument.starts_with('-') || argument == "-" || looks_like_negative_number(argument) {
                unrecognized.push(argument.clone());
                continue;
            }
            if argument == "--" {
                only_positionals = true;
                continue;
            }
            let (name, explicit) = match argument.split_once('=') {
                Some((name, value)) if name.starts_with("--") => (name, Some(value.to_string())),
                _ => (argument.as_str(), None),
            };
            let option = match self.lookup(name) {
                Ok(Some(option)) => Some(option),
                Ok(None) => None,
                Err(message) if message.is_empty() => {
                    unrecognized.push(argument.clone());
                    continue;
                }
                Err(message) => return Err(self.error(&message)),
            };
            let Some(option) = option else {
                print!("{}", self.help());
                return Err(0);
            };
            if let Some(group) = option.group {
                match seen_groups.get(&group) {
                    Some(other) if *other != option.name => {
                        return Err(self.error(&format!("argument {}: not allowed with argument {}", option.name, other)));
                    }
                    _ => {
                        seen_groups.insert(group, option.name);
                    }
                }
            }
            if option.takes_value {
                let value = match explicit {
                    Some(value) => value,
                    None => match args.get(index) {
                        Some(next) if !next.starts_with('-') || next == "-" || looks_like_negative_number(next) => {
                            index += 1;
                            next.clone()
                        }
                        _ => return Err(self.error(&format!("argument {}: expected one argument", option.name))),
                    },
                };
                parsed.values.insert(option.name, value);
            } else {
                if let Some(value) = explicit {
                    return Err(self.error(&format!("argument {}: ignored explicit argument {}", option.name,
                        mirra_core::pyfmt::repr_str(&value))));
                }
                if !parsed.flags.contains(&option.name) {
                    parsed.flags.push(option.name);
                }
            }
        }
        let missing: Vec<&str> = self.options.iter()
            .filter(|o| o.required && !parsed.values.contains_key(o.name)).map(|o| o.name).collect();
        if !missing.is_empty() {
            return Err(self.error(&format!("the following arguments are required: {}", missing.join(", "))));
        }
        if !unrecognized.is_empty() {
            return Err(self.error(&format!("unrecognized arguments: {}", unrecognized.join(" "))));
        }
        Ok(parsed)
    }
}

static HELP: Opt = Opt::flag("--help");

/// argparse `type=int` (`int(text)`), with its error message.
pub fn parse_int(name: &str, text: &str) -> Result<i64, String> {
    let trimmed = crate::util::strip(text);
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    let valid = !digits.is_empty() && !digits.starts_with('_') && !digits.ends_with('_') && !digits.contains("__")
        && digits.chars().all(|c| c.is_ascii_digit() || c == '_');
    let value = valid.then(|| trimmed.replace('_', "").parse::<i64>().ok()).flatten();
    value.ok_or_else(|| format!("argument {}: invalid int value: {}", name, mirra_core::pyfmt::repr_str(text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser() -> Parser {
        Parser { prog: "test.py", description: "d", usage: "usage: test.py [-h]\n", options: vec![
            Opt::value("--socket").required(), Opt::value("--state-file").required(), Opt::value("--config"),
            Opt::flag("--parent-lifeline").suppressed(),
            Opt::value("--seconds").group(1), Opt::flag("--until-stopped").group(1),
        ] }
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_like_argparse() {
        let parsed = parser().parse(&args(&["--sock=/a", "--state-file", "/b", "--parent", "--seconds", "-5"])).unwrap();
        assert_eq!(parsed.value("--socket"), Some("/a"));
        assert_eq!(parsed.value("--state-file"), Some("/b"));
        assert_eq!(parsed.value("--seconds"), Some("-5"));
        assert!(parsed.flag("--parent-lifeline"));
        assert!(!parsed.flag("--until-stopped"));
        assert_eq!(parser().parse(&args(&["--socket", "/a"])).unwrap_err(), 2);
        assert_eq!(parser().parse(&args(&["--s", "/a"])).unwrap_err(), 2);
        assert_eq!(parser().parse(&args(&["--socket", "/a", "--state-file", "/b", "--seconds", "30", "--until-stopped"])).unwrap_err(), 2);
        assert_eq!(parser().parse(&args(&["--socket", "/a", "--state-file", "/b", "extra"])).unwrap_err(), 2);
        assert_eq!(parser().parse(&args(&["--socket", "--state-file", "/b"])).unwrap_err(), 2);
        assert_eq!(parse_int("--seconds", " 1_0 "), Ok(10));
        assert_eq!(parse_int("--seconds", "x").unwrap_err(), "argument --seconds: invalid int value: 'x'");
    }
}
