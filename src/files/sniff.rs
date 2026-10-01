//! The type of an uploaded file comes from its bytes, not from the client's
//! `Content-Type`: a client could otherwise label an HTML page `image/png` and
//! have it served inline from Atom's origin.

use crate::error::AppError;

/// How many leading bytes [`sniff`] needs.
pub(crate) const SNIFF_BYTES: usize = 16;

/// Types recognised from their signature. A file declaring one of these must
/// carry its signature.
const SIGNATURES: &[(&str, &[u8])] = &[
    ("image/png", b"\x89PNG\r\n\x1a\n"),
    ("image/jpeg", b"\xff\xd8\xff"),
    ("image/gif", b"GIF87a"),
    ("image/gif", b"GIF89a"),
    ("application/pdf", b"%PDF-"),
];

/// Types a browser may render inline from Atom's origin: raster images and
/// PDF, whose type is always verified by [`sniff`]. Everything else, SVG and
/// HTML included, is served as an attachment.
const INLINE: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/pdf",
];

/// The type `head` (the first bytes of a file) proves, if any.
pub(crate) fn sniff(head: &[u8]) -> Option<&'static str> {
    if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    SIGNATURES
        .iter()
        .find(|(_, signature)| head.starts_with(signature))
        .map(|(content_type, _)| *content_type)
}

fn signed(content_type: &str) -> bool {
    content_type == "image/webp" || SIGNATURES.iter().any(|(known, _)| *known == content_type)
}

/// `type/subtype` of a `Content-Type` header, lowercased, without parameters.
fn essence(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// The type to store a file as, given its first bytes and the type the client
/// declared. A recognised signature wins over the declaration; a declaration
/// is taken only for types that have no signature, and only when the
/// deployment allows them. The result is always in `allowed`.
pub(crate) fn resolve(
    head: &[u8],
    declared: Option<&str>,
    allowed: &[String],
) -> Result<String, AppError> {
    let content_type = match sniff(head) {
        Some(sniffed) => sniffed.to_string(),
        None => {
            let declared = declared.map(essence).filter(|value| !value.is_empty());
            match declared {
                Some(declared) if signed(&declared) => {
                    return Err(AppError::bad_request(format!(
                        "the file is not the {declared} it is declared as"
                    )));
                }
                Some(declared) => declared,
                None => {
                    return Err(AppError::bad_request(
                        "the file's type could not be determined",
                    ))
                }
            }
        }
    };
    if !allowed.contains(&content_type) {
        return Err(AppError::bad_request(format!(
            "files of type {content_type} are not accepted"
        )));
    }
    Ok(content_type)
}

pub(crate) fn inline(content_type: &str) -> bool {
    INLINE.contains(&content_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(types: &[&str]) -> Vec<String> {
        types.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn signatures_are_recognised() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(sniff(b"\xff\xd8\xff\xe0"), Some("image/jpeg"));
        assert_eq!(sniff(b"GIF89a..."), Some("image/gif"));
        assert_eq!(sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff(b"%PDF-1.7"), Some("application/pdf"));
        assert_eq!(sniff(b"<svg xmlns="), None);
        assert_eq!(sniff(b""), None);
    }

    #[test]
    fn the_bytes_win_over_the_declared_type() {
        let allowed = allowed(&["image/png", "image/jpeg"]);
        let png = b"\x89PNG\r\n\x1a\n";
        assert_eq!(
            resolve(png, Some("image/jpeg"), &allowed).unwrap(),
            "image/png"
        );
        assert_eq!(resolve(png, None, &allowed).unwrap(), "image/png");
    }

    #[test]
    fn a_signed_type_without_its_signature_is_refused() {
        let allowed = allowed(&["image/png"]);
        assert!(resolve(b"<html><script>", Some("image/png"), &allowed).is_err());
        assert!(resolve(b"<html><script>", Some("IMAGE/PNG; charset=x"), &allowed).is_err());
    }

    #[test]
    fn unsigned_types_need_the_allowlist() {
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>";
        assert!(resolve(svg, Some("image/svg+xml"), &allowed(&["image/png"])).is_err());
        assert_eq!(
            resolve(
                svg,
                Some("image/svg+xml; charset=utf-8"),
                &allowed(&["image/svg+xml"])
            )
            .unwrap(),
            "image/svg+xml"
        );
        assert!(resolve(svg, None, &allowed(&["image/svg+xml"])).is_err());
    }

    #[test]
    fn only_verified_types_render_inline() {
        assert!(inline("image/png"));
        assert!(inline("application/pdf"));
        assert!(!inline("image/svg+xml"));
        assert!(!inline("text/html"));
    }
}
