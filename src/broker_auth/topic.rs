//! Topic template matching for the broker auth callout.
//!
//! A broker hands Atom a raw topic (`PUBLISH`) or topic filter (`SUBSCRIBE`).
//! Atom needs two things out of it: which tenant to resolve in, and which
//! object is being addressed. The mapping is deployment-specific — a plain
//! broker uses the first segment, Magistrala uses `m/{tenant}/c/{resource}` —
//! so the grammar is configuration, not code. Atom learns "topics bind
//! segments to a tenant and an object", never any particular topic layout.
//!
//! Template grammar, segments separated by `/`:
//!
//! | Token         | Meaning                                              |
//! |---------------|------------------------------------------------------|
//! | `{tenant}`    | optional; binds the resolution tenant                |
//! | `{resource}`  | required; binds the addressed object, one segment    |
//! | `{subtopic}`  | optional; binds the remainder, passed as PDP context |
//! | `+`           | matches one segment, discarded                       |
//! | `#`           | matches zero or more segments, terminal, discarded   |
//! | anything else | literal, must match exactly                          |
//!
//! `{tenant}` is a *resolution scope*, not a guard: it is not required to equal
//! the subject's tenant. Atom supports cross-tenant grants, so forcing equality
//! here would deny legitimate access from a hardcoded rule instead of from the
//! PDP. Resolve in the named tenant and let the engine decide.

use std::fmt;

/// One parsed template segment.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Tenant,
    Resource,
    /// Binds the remainder of the topic. Terminal.
    Subtopic,
    /// Matches exactly one segment, discarded.
    SingleWild,
    /// Matches zero or more remaining segments, discarded. Terminal.
    MultiWild,
}

impl Segment {
    /// True when the segment pins a specific value at its position — either a
    /// literal that must match or a placeholder that must bind a usable name.
    /// A broker wildcard reaching one of these makes the request unresolvable.
    fn is_pinned(&self) -> bool {
        matches!(
            self,
            Segment::Literal(_) | Segment::Tenant | Segment::Resource
        )
    }

    /// True when the segment consumes the rest of the topic and ends matching.
    fn is_terminal(&self) -> bool {
        matches!(self, Segment::Subtopic | Segment::MultiWild)
    }
}

/// A parsed, validated topic template. Built once at startup; a malformed
/// template fails the process rather than silently denying every request.
#[derive(Debug, Clone)]
pub struct TopicTemplate {
    segments: Vec<Segment>,
    raw: String,
}

/// What a template extracted from one topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicMatch {
    /// Present only when the template carries `{tenant}`. `None` means "use the
    /// subject's own tenant".
    pub tenant: Option<String>,
    pub resource: String,
    /// The remainder bound by `{subtopic}`, if the template has one. Empty
    /// remainder yields `None`.
    pub subtopic: Option<String>,
}

/// Why a template string could not be parsed. Startup-time only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateParseError {
    template: String,
    reason: String,
}

impl fmt::Display for TemplateParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid topic template {:?}: {}",
            self.template, self.reason
        )
    }
}

impl std::error::Error for TemplateParseError {}

impl TopicTemplate {
    pub fn parse(template: &str) -> Result<Self, TemplateParseError> {
        let raw = template.trim().to_string();
        let fail = |reason: &str| TemplateParseError {
            template: raw.clone(),
            reason: reason.to_string(),
        };

        if raw.is_empty() {
            return Err(fail("template must not be empty"));
        }

        let mut segments = Vec::new();
        for token in raw.split('/') {
            let segment = match token {
                "{tenant}" => Segment::Tenant,
                "{resource}" => Segment::Resource,
                "{subtopic}" => Segment::Subtopic,
                "+" => Segment::SingleWild,
                "#" => Segment::MultiWild,
                other => {
                    if other.starts_with('{') || other.ends_with('}') {
                        return Err(fail(&format!(
                            "unknown placeholder {other:?} \
                             (expected {{tenant}}, {{resource}} or {{subtopic}})"
                        )));
                    }
                    if other.contains('+') || other.contains('#') {
                        return Err(fail(&format!(
                            "literal segment {other:?} must not contain '+' or '#'"
                        )));
                    }
                    Segment::Literal(other.to_string())
                }
            };
            segments.push(segment);
        }

        let count = |wanted: &Segment| segments.iter().filter(|seg| *seg == wanted).count();
        if count(&Segment::Resource) != 1 {
            return Err(fail("template must contain exactly one {resource}"));
        }
        if count(&Segment::Tenant) > 1 {
            return Err(fail("template must contain at most one {tenant}"));
        }
        if count(&Segment::Subtopic) > 1 {
            return Err(fail("template must contain at most one {subtopic}"));
        }

        // Terminal segments consume the remainder, so anything after them is
        // unreachable and almost certainly a mistake in the operator's config.
        if let Some(index) = segments.iter().position(Segment::is_terminal) {
            if index != segments.len() - 1 {
                return Err(fail(
                    "'#' and {subtopic} consume the rest of the topic and must come last",
                ));
            }
        }

        Ok(Self { segments, raw })
    }

    /// The template as configured, for diagnostics.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Match one topic. `None` means this template does not apply, or applies
    /// but cannot yield a usable binding — the caller denies either way.
    ///
    /// `topic` may be a concrete publish topic or a subscribe filter containing
    /// `+`/`#`. A broker wildcard is only acceptable where the template does not
    /// pin the position: a filter spanning many resources cannot be authorized
    /// as one object.
    pub fn match_topic(&self, topic: &str) -> Option<TopicMatch> {
        let topic = topic.strip_prefix('/').unwrap_or(topic);
        if topic.is_empty() {
            return None;
        }
        let tokens: Vec<&str> = topic.split('/').collect();

        // MQTT allows '#' only as the final segment. Anything else is a
        // malformed filter, not something to interpret generously.
        if let Some(index) = tokens.iter().position(|token| *token == "#") {
            if index != tokens.len() - 1 {
                return None;
            }
        }

        // Every non-terminal template segment consumes exactly one token, so
        // template and topic indices line up until a terminal segment. That
        // makes the wildcard check a straight positional comparison: a broker
        // '#' at index i leaves every position from i onward unconstrained, so
        // no pinned segment may sit there.
        if let Some(hash) = tokens.iter().position(|token| *token == "#") {
            if self
                .segments
                .iter()
                .skip(hash)
                .any(|segment| segment.is_pinned())
            {
                return None;
            }
        }

        let mut tenant = None;
        let mut resource = None;
        let mut subtopic = None;
        let mut cursor = 0usize;

        for segment in &self.segments {
            match segment {
                Segment::MultiWild => {
                    cursor = tokens.len();
                    break;
                }
                Segment::Subtopic => {
                    let rest = tokens[cursor.min(tokens.len())..].join("/");
                    subtopic = (!rest.is_empty()).then_some(rest);
                    cursor = tokens.len();
                    break;
                }
                _ => {
                    let token = *tokens.get(cursor)?;
                    match segment {
                        Segment::Literal(literal) => {
                            if token != literal {
                                return None;
                            }
                        }
                        Segment::Tenant | Segment::Resource => {
                            // Already excluded '#' positionally above; '+' is
                            // still possible and is equally unresolvable.
                            if token == "+" || token.is_empty() {
                                return None;
                            }
                            if matches!(segment, Segment::Tenant) {
                                tenant = Some(token.to_string());
                            } else {
                                resource = Some(token.to_string());
                            }
                        }
                        Segment::SingleWild => {}
                        Segment::Subtopic | Segment::MultiWild => unreachable!("handled above"),
                    }
                    cursor += 1;
                }
            }
        }

        // Without a terminal segment the template must consume the whole topic;
        // a longer topic addresses something the template does not describe.
        if cursor != tokens.len() {
            return None;
        }

        Some(TopicMatch {
            tenant,
            resource: resource?,
            subtopic,
        })
    }
}

/// The configured templates, tried in order. First one that yields a binding
/// wins; if none do, the caller denies.
#[derive(Debug, Clone)]
pub struct TopicTemplateSet {
    templates: Vec<TopicTemplate>,
}

impl TopicTemplateSet {
    pub fn parse_list(templates: &[String]) -> Result<Self, TemplateParseError> {
        let templates = templates
            .iter()
            .map(|template| TopicTemplate::parse(template))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { templates })
    }

    pub fn match_topic(&self, topic: &str) -> Option<TopicMatch> {
        self.templates
            .iter()
            .find_map(|template| template.match_topic(topic))
    }

    pub fn iter(&self) -> impl Iterator<Item = &TopicTemplate> {
        self.templates.iter()
    }
}

/// Topics allowed without consulting the PDP.
///
/// **This is an authorization bypass**, and the only one in the callout. It
/// exists because brokers carry operational topics that address no object at
/// all — a health probe such as `hc/<tenant>` names nothing Atom can resolve, so
/// there is no policy that could describe it and every request for it would be
/// denied. Defaults to empty; a deployment that does not need it never gets one.
///
/// Patterns use ordinary MQTT filter syntax — `+` for one segment, `#` for the
/// remainder — so `hc/+` admits a per-tenant health topic without also admitting
/// `hc/a/b`. Prefer the narrowest pattern that covers the operational topic;
/// `#` alone would hand the broker unconditional access to everything.
///
/// The broker's topic is matched literally, so a subscription to `hc/#` is
/// admitted only by a pattern that itself covers `#` at that position.
#[derive(Debug, Clone, Default)]
pub struct TopicAllowList {
    filters: Vec<Vec<String>>,
}

impl TopicAllowList {
    pub fn parse_list(patterns: &[String]) -> Result<Self, TemplateParseError> {
        let mut filters = Vec::new();
        for pattern in patterns {
            let raw = pattern.trim();
            let fail = |reason: &str| TemplateParseError {
                template: raw.to_string(),
                reason: reason.to_string(),
            };
            if raw.is_empty() {
                return Err(fail("allow pattern must not be empty"));
            }
            let segments: Vec<String> = raw.split('/').map(ToOwned::to_owned).collect();
            if let Some(index) = segments.iter().position(|segment| segment == "#") {
                if index != segments.len() - 1 {
                    return Err(fail("'#' must be the last segment"));
                }
            }
            filters.push(segments);
        }
        Ok(Self { filters })
    }

    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    pub fn allows(&self, topic: &str) -> bool {
        let topic = topic.strip_prefix('/').unwrap_or(topic);
        if topic.is_empty() {
            return false;
        }
        let tokens: Vec<&str> = topic.split('/').collect();
        self.filters
            .iter()
            .any(|filter| filter_matches(filter, &tokens))
    }
}

fn filter_matches(filter: &[String], tokens: &[&str]) -> bool {
    let mut index = 0;
    while index < filter.len() {
        // A broker '#' covers this position *and everything below it*, so only
        // a pattern that is itself '#' here is broad enough to admit it. Letting
        // '+' match it would widen the bypass past what the operator wrote —
        // `hc/+` would admit a subscription to the whole `hc` subtree.
        if filter[index] != "#" && tokens.get(index) == Some(&"#") {
            return false;
        }
        match filter[index].as_str() {
            "#" => return true,
            "+" => {
                if index >= tokens.len() {
                    return false;
                }
            }
            literal => {
                if tokens.get(index) != Some(&literal) {
                    return false;
                }
            }
        }
        index += 1;
    }
    index == tokens.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(template: &str) -> TopicTemplate {
        TopicTemplate::parse(template).expect("template should parse")
    }

    fn matched(template: &str, topic: &str) -> TopicMatch {
        parse(template)
            .match_topic(topic)
            .unwrap_or_else(|| panic!("{template:?} should match {topic:?}"))
    }

    fn denied(template: &str, topic: &str) {
        assert!(
            parse(template).match_topic(topic).is_none(),
            "{template:?} should not match {topic:?}"
        );
    }

    #[test]
    fn default_template_binds_the_first_segment() {
        let result = matched("{resource}/#", "sensors/eu/temp");
        assert_eq!(result.resource, "sensors");
        assert_eq!(result.tenant, None);
        assert_eq!(result.subtopic, None);
    }

    #[test]
    fn default_template_matches_a_bare_resource() {
        assert_eq!(matched("{resource}/#", "sensors").resource, "sensors");
    }

    #[test]
    fn magistrala_shaped_template_binds_tenant_and_resource() {
        let result = matched("m/{tenant}/c/{resource}/#", "m/acme/c/telemetry/eu/1");
        assert_eq!(result.tenant.as_deref(), Some("acme"));
        assert_eq!(result.resource, "telemetry");
    }

    #[test]
    fn literal_segments_must_match() {
        denied("m/{tenant}/c/{resource}/#", "x/acme/c/telemetry");
        denied("m/{tenant}/c/{resource}/#", "m/acme/d/telemetry");
    }

    #[test]
    fn subtopic_binds_the_remainder() {
        let result = matched("{resource}/{subtopic}", "telemetry/eu/rack1/temp");
        assert_eq!(result.resource, "telemetry");
        assert_eq!(result.subtopic.as_deref(), Some("eu/rack1/temp"));
    }

    #[test]
    fn empty_subtopic_remainder_is_none() {
        assert_eq!(matched("{resource}/{subtopic}", "telemetry").subtopic, None);
    }

    #[test]
    fn single_wildcard_segment_is_discarded() {
        let result = matched("{tenant}/+/{resource}", "acme/ignored/telemetry");
        assert_eq!(result.tenant.as_deref(), Some("acme"));
        assert_eq!(result.resource, "telemetry");
    }

    // ── Broker wildcards ─────────────────────────────────────────────────────

    #[test]
    fn wildcard_past_the_resource_is_allowed() {
        assert_eq!(
            matched("{resource}/#", "telemetry/+/temp").resource,
            "telemetry"
        );
        assert_eq!(matched("{resource}/#", "telemetry/#").resource, "telemetry");
    }

    #[test]
    fn wildcard_on_the_resource_is_denied() {
        denied("{resource}/#", "+/temp");
        denied("{resource}/#", "#");
        denied("m/{tenant}/c/{resource}/#", "m/acme/c/+/temp");
    }

    #[test]
    fn wildcard_on_the_tenant_is_denied() {
        denied("m/{tenant}/c/{resource}/#", "m/+/c/telemetry");
        denied("m/{tenant}/c/{resource}/#", "m/#");
    }

    #[test]
    fn wildcard_on_a_literal_is_denied() {
        denied("m/{tenant}/c/{resource}/#", "+/acme/c/telemetry");
        denied("m/{tenant}/c/{resource}/#", "m/acme/+/telemetry");
    }

    #[test]
    fn hash_before_a_single_wildcard_still_denies_a_later_resource() {
        // '#' at index 1 leaves the {resource} at index 2 unconstrained even
        // though the template segment at index 1 is itself a wildcard.
        denied("{tenant}/+/{resource}", "acme/#");
    }

    #[test]
    fn non_terminal_hash_is_a_malformed_filter() {
        denied("{resource}/#", "telemetry/#/temp");
    }

    // ── Length handling ──────────────────────────────────────────────────────

    #[test]
    fn topic_longer_than_a_template_without_a_terminal_is_denied() {
        denied("{tenant}/{resource}", "acme/telemetry/extra");
    }

    #[test]
    fn topic_shorter_than_the_template_is_denied() {
        denied("m/{tenant}/c/{resource}/#", "m/acme/c");
        denied("{tenant}/{resource}", "acme");
    }

    #[test]
    fn multi_wildcard_matches_zero_remaining_segments() {
        assert_eq!(
            matched("{tenant}/{resource}/#", "acme/telemetry").resource,
            "telemetry"
        );
    }

    #[test]
    fn empty_and_leading_slash_topics() {
        denied("{resource}/#", "");
        assert_eq!(
            matched("{resource}/#", "/telemetry/x").resource,
            "telemetry"
        );
    }

    #[test]
    fn empty_bound_segment_is_denied() {
        denied("{tenant}/{resource}", "acme/");
    }

    // ── Template validation ──────────────────────────────────────────────────

    #[test]
    fn template_requires_exactly_one_resource() {
        assert!(TopicTemplate::parse("{tenant}/#").is_err());
        assert!(TopicTemplate::parse("{resource}/{resource}").is_err());
    }

    #[test]
    fn template_rejects_repeated_optional_placeholders() {
        assert!(TopicTemplate::parse("{tenant}/{tenant}/{resource}").is_err());
        assert!(TopicTemplate::parse("{resource}/{subtopic}/{subtopic}").is_err());
    }

    #[test]
    fn template_rejects_unknown_placeholders() {
        assert!(TopicTemplate::parse("{domain}/{resource}").is_err());
        assert!(TopicTemplate::parse("{resource}/{}").is_err());
    }

    #[test]
    fn template_rejects_wildcards_inside_literals() {
        assert!(TopicTemplate::parse("m+/{resource}").is_err());
    }

    #[test]
    fn template_rejects_segments_after_a_terminal() {
        assert!(TopicTemplate::parse("{resource}/#/tail").is_err());
        assert!(TopicTemplate::parse("{resource}/{subtopic}/tail").is_err());
    }

    #[test]
    fn template_rejects_empty_input() {
        assert!(TopicTemplate::parse("   ").is_err());
    }

    // ── Template set ─────────────────────────────────────────────────────────

    #[test]
    fn template_set_uses_the_first_binding_match() {
        let set = TopicTemplateSet::parse_list(&[
            "m/{tenant}/c/{resource}/#".to_string(),
            "{resource}/#".to_string(),
        ])
        .expect("set should parse");

        assert_eq!(
            set.match_topic("m/acme/c/telemetry")
                .unwrap()
                .tenant
                .as_deref(),
            Some("acme")
        );
        // Falls through to the second template rather than denying outright.
        let plain = set.match_topic("telemetry/eu").unwrap();
        assert_eq!(plain.resource, "telemetry");
        assert_eq!(plain.tenant, None);
    }

    #[test]
    fn template_set_denies_when_no_template_binds() {
        let set = TopicTemplateSet::parse_list(&["m/{tenant}/c/{resource}".to_string()])
            .expect("set should parse");
        assert!(set.match_topic("telemetry/eu").is_none());
    }

    #[test]
    fn template_set_rejects_a_bad_member() {
        assert!(TopicTemplateSet::parse_list(&["{resource}/#".into(), "{tenant}".into()]).is_err());
    }

    // ── Allow list ───────────────────────────────────────────────────────────

    fn allow(patterns: &[&str]) -> TopicAllowList {
        TopicAllowList::parse_list(&patterns.iter().map(ToString::to_string).collect::<Vec<_>>())
            .expect("patterns should parse")
    }

    #[test]
    fn the_allow_list_is_empty_by_default() {
        let list = TopicAllowList::default();
        assert!(list.is_empty());
        assert!(!list.allows("hc/acme"));
    }

    #[test]
    fn a_single_segment_wildcard_admits_a_per_tenant_health_topic() {
        let list = allow(&["hc/+"]);
        assert!(list.allows("hc/acme"));
        assert!(list.allows("hc/00000000-0000-0000-0000-000000000001"));
    }

    #[test]
    fn a_single_segment_wildcard_does_not_admit_deeper_topics() {
        let list = allow(&["hc/+"]);
        assert!(!list.allows("hc/acme/extra"));
        assert!(!list.allows("hc"));
    }

    #[test]
    fn an_unrelated_topic_is_never_admitted() {
        let list = allow(&["hc/+"]);
        assert!(!list.allows("m/acme/c/telemetry"));
        assert!(!list.allows("telemetry"));
        assert!(!list.allows(""));
    }

    #[test]
    fn a_multi_segment_wildcard_admits_the_whole_subtree() {
        let list = allow(&["$sys/#"]);
        assert!(list.allows("$sys"));
        assert!(list.allows("$sys/broker/uptime"));
        assert!(!list.allows("sys/broker"));
    }

    #[test]
    fn an_exact_pattern_admits_only_itself() {
        let list = allow(&["hc"]);
        assert!(list.allows("hc"));
        assert!(!list.allows("hc/acme"));
    }

    #[test]
    fn any_pattern_in_the_list_may_admit() {
        let list = allow(&["hc/+", "$sys/#"]);
        assert!(list.allows("hc/acme"));
        assert!(list.allows("$sys/uptime"));
        assert!(!list.allows("m/acme/c/telemetry"));
    }

    #[test]
    fn a_leading_slash_is_ignored_as_it_is_for_templates() {
        assert!(allow(&["hc/+"]).allows("/hc/acme"));
    }

    #[test]
    fn broker_wildcards_are_matched_literally() {
        // A subscription to `hc/#` spans more than `hc/+` describes, so only a
        // pattern that itself covers the position admits it.
        assert!(!allow(&["hc/+"]).allows("hc/#"));
        assert!(allow(&["hc/#"]).allows("hc/#"));
    }

    #[test]
    fn allow_patterns_reject_a_non_terminal_hash_and_empty_input() {
        assert!(TopicAllowList::parse_list(&["hc/#/tail".to_string()]).is_err());
        assert!(TopicAllowList::parse_list(&["  ".to_string()]).is_err());
    }
}
