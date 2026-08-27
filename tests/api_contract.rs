use std::collections::BTreeSet;

#[test]
fn openapi_path_inventory_matches_the_live_router() {
    let documented = openapi_paths();
    let mounted = mounted_paths();

    assert_eq!(
        documented, mounted,
        "apidocs/openapi.yaml must describe every mounted HTTP path and no dead REST routes"
    );
}

#[test]
fn custom_endpoint_methods_are_frozen() {
    let document: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../apidocs/openapi.yaml")).expect("valid OpenAPI YAML");
    let operations = document["paths"]["/api/custom/{path}"]
        .as_mapping()
        .expect("custom endpoint path item")
        .keys()
        .filter_map(serde_yaml::Value::as_str)
        .filter(|key| *key != "parameters")
        .collect::<BTreeSet<_>>();

    assert_eq!(
        operations,
        BTreeSet::from(["delete", "get", "patch", "post", "put"])
    );
    assert!(!include_str!("../src/routes.rs").contains("any(api_endpoints::custom_endpoint)"));
}

fn openapi_paths() -> BTreeSet<String> {
    let document: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../apidocs/openapi.yaml")).expect("valid OpenAPI YAML");
    document["paths"]
        .as_mapping()
        .expect("OpenAPI paths map")
        .keys()
        .map(|path| path.as_str().expect("string OpenAPI path").to_string())
        .collect()
}

fn mounted_paths() -> BTreeSet<String> {
    include_str!("../src/routes.rs")
        .split(".route(")
        .skip(1)
        .map(|tail| {
            let start = tail.find('"').expect("route path starts with a quote") + 1;
            let end = tail[start..]
                .find('"')
                .map(|offset| start + offset)
                .expect("route path ends with a quote");
            openapi_path(&tail[start..end])
        })
        .collect()
}

fn openapi_path(axum_path: &str) -> String {
    axum_path
        .split('/')
        .map(|segment| match segment.as_bytes().first() {
            Some(b':') | Some(b'*') => format!("{{{}}}", &segment[1..]),
            _ => segment.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}
