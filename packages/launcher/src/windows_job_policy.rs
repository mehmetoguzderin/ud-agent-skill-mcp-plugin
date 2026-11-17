//! Windows command-line quoting and resource policy are tested on every host.
pub const WALL_TIME_MS: u32 = 300_000;
pub const MEMORY_BYTES: usize = 2 * 1024 * 1024 * 1024;
pub const PROCESS_LIMIT: u32 = 128;
pub const CPU_TIME_100NS: i64 = 300 * 10_000_000;

pub fn quote(value: &str) -> String {
    let mut output = String::from("\"");
    let mut backslashes = 0;
    for character in value.chars() {
        if character == '\\' { backslashes += 1; continue; }
        if character == '"' { output.extend(std::iter::repeat_n('\\', backslashes * 2 + 1)); }
        else { output.extend(std::iter::repeat_n('\\', backslashes)); }
        output.push(character); backslashes = 0;
    }
    output.extend(std::iter::repeat_n('\\', backslashes * 2)); output.push('"'); output
}
pub fn cpu_rate(processors: u32) -> u32 { (20_000 / processors.max(1)).clamp(1, 10_000) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quotes_spaces_quotes_and_trailing_backslashes() {
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("a b"), "\"a b\"");
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote("C:\\space dir\\"), "\"C:\\space dir\\\\\"");
        assert_eq!(quote("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote("$();` &"), "\"$();` &\"");
    }
    #[test]
    fn bounds_aggregate_cpu_and_resource_limits() {
        assert_eq!((cpu_rate(0), cpu_rate(1), cpu_rate(2), cpu_rate(8)), (10000, 10000, 10000, 2500));
        assert_eq!(WALL_TIME_MS, 300000); assert_eq!(MEMORY_BYTES, 2147483648); assert_eq!(PROCESS_LIMIT, 128); assert_eq!(CPU_TIME_100NS, 3000000000);
    }
}
