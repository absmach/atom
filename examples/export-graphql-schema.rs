use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: export-graphql-schema <output-path>")?;
    fs::write(output, format!("{}\n", atom::graphql::schema_sdl()))?;
    Ok(())
}
