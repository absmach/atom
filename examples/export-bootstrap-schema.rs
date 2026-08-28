fn main() -> anyhow::Result<()> {
    let schema = atom::bootstrap::v1_json_schema()?;
    let rendered = format!("{}\n", serde_json::to_string_pretty(&schema)?);

    if let Some(path) = std::env::args_os().nth(1) {
        std::fs::write(path, rendered)?;
    } else {
        print!("{rendered}");
    }

    Ok(())
}
