//! Exact decimal keys for SQLite JSON-number equality and ordering. JSON1's
//! native extraction rounds integers outside i64 to f64, losing distinct u64
//! values. Keep the original JSON token and return a lexicographically sortable
//! blob instead. Equal decimal values (including 30 and 30.0) have equal keys.

pub(super) fn sort_key(raw: &str) -> Option<Vec<u8>> {
    let raw = raw.trim();
    // Validate the token, but never use the parsed number: its f64 form may
    // already have rounded the original decimal value.
    serde_json::from_str::<serde_json::Number>(raw).ok()?;
    let (negative, magnitude) = raw
        .strip_prefix('-')
        .map_or((false, raw), |magnitude| (true, magnitude));
    let (mantissa, exponent) = magnitude.split_once(['e', 'E']).unwrap_or((magnitude, "0"));
    let decimal_position = mantissa.find('.').unwrap_or(mantissa.len());
    let digits: Vec<u8> = mantissa.bytes().filter(|&b| b != b'.').collect();
    let Some(first) = digits.iter().position(|&b| b != b'0') else {
        return Some(vec![1]); // Both signs of zero compare equal.
    };
    let last = digits.iter().rposition(|&b| b != b'0')? + 1;
    let exponent = exponent
        .parse::<i32>()
        .ok()?
        .checked_add(i32::try_from(decimal_position).ok()?)?
        .checked_sub(i32::try_from(first).ok()?)?;

    // Sign, biased big-endian decimal exponent, significant digits, terminator.
    // The terminator makes reversing negative keys work for prefix digits too
    // (e.g. -1.21 sorts before -1.2).
    let mut key = Vec::with_capacity(6 + last - first);
    key.push(if negative { 0 } else { 2 });
    key.extend_from_slice(&((exponent as u32) ^ (1 << 31)).to_be_bytes());
    key.extend_from_slice(&digits[first..last]);
    key.push(0);
    if negative {
        key[1..].iter_mut().for_each(|b| *b = !*b);
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::sort_key;

    #[test]
    fn equal_decimal_representations_share_a_key() {
        for equivalents in [
            ["0", "-0.0", "0e100"],
            ["30", "30.0", "3e1"],
            ["-0.0012", "-1.20e-3", "-0.0001200e1"],
        ] {
            let expected = sort_key(equivalents[0]).unwrap();
            for number in equivalents {
                assert_eq!(sort_key(number).unwrap(), expected, "{number}");
            }
        }
    }

    #[test]
    fn keys_sort_exactly_across_signs_exponents_and_integer_boundaries() {
        let ordered = [
            "-1e308",
            "-9223372036854775808",
            "-1.21",
            "-1.2",
            "-0.001",
            "0",
            "1e-308",
            "0.001",
            "1",
            "1.0000000000000001",
            "1.2",
            "1.21",
            "9223372036854775807",
            "9223372036854775808",
            "9223372036854775809",
            "9.223372036854776e18",
            "18446744073709551615",
            "1.8446744073709552e19",
            "1e308",
        ];
        for pair in ordered.windows(2) {
            assert!(
                sort_key(pair[0]).unwrap() < sort_key(pair[1]).unwrap(),
                "{} must sort before {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn non_numbers_have_no_key() {
        for raw in ["null", "true", "\"30\"", "[]", "{}", "NaN", "", "01"] {
            assert!(sort_key(raw).is_none(), "{raw}");
        }
    }
}
