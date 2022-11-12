use anyhow::Context;
use std::io;
use std::io::{BufReader, BufWriter, Read, Write};
use textencoding::hex;

fn read_stdin() -> Result<Vec<u8>, io::Error> {
    let mut reader = BufReader::new(std::io::stdin());

    let mut output: Vec<u8> = Vec::new();
    reader.read_to_end(&mut output)?;

    Ok(output)
}

fn run_hex(args: &clap::ArgMatches) -> anyhow::Result<()> {
    let input: Vec<u8> = match args.get_one::<String>("input") {
        None => read_stdin()?,
        Some(input) => {
            if input == "-" {
                read_stdin()?
            } else {
                input.as_bytes().to_vec()
            }
        }
    };
    let should_decode = args.get_one::<bool>("decode").copied().unwrap_or(false);

    let mut writer = BufWriter::new(std::io::stdout());

    if should_decode {
        let input = String::from_utf8(input)?;
        let decoded = hex::decode(&input)
            .map_err(Into::<anyhow::Error>::into)
            .context("unable to hex decode input")?;

        writer.write_all(&decoded)?;
    } else {
        let upper = args.get_one::<bool>("upper").copied().unwrap_or_default();

        let encoded = if upper {
            hex::encode_upper(&input)
        } else {
            hex::encode_lower(&input)
        };

        writer.write_all(encoded.as_bytes())?;
        writer.write_all(b"\n")?;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let root_command = clap::Command::new("tenc")
        .version(clap::crate_version!())
        .about("Text encoding and decoding tool")
        .subcommand_required(true)
        .subcommand(
            clap::Command::new("hex")
                .about("Encode or decode base16 (hexadecimal)-encoded data")
                .arg(
                    clap::Arg::new("input")
                        .help("The input text to encode or decode")
                        .action(clap::ArgAction::Set)
                        .default_value("-")
                        .value_name("INPUT"),
                )
                .arg(
                    clap::Arg::new("decode")
                        .help("Decode the input instead of encoding")
                        .short('d')
                        .long("decode")
                        .action(clap::ArgAction::SetTrue),
                ),
        )
        .arg(
            clap::Arg::new("upper")
                .help("Encode using the uppercase alphabet")
                .short('u')
                .long("upper")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        );

    let matches = root_command.get_matches();

    match matches.subcommand() {
        Some(("hex", hex_matches)) => {
            if let Err(err) = run_hex(hex_matches) {
                println!("unable to serve, got err {}", err);
                std::process::exit(1);
            }
        }
        _ => unreachable!("should never happen because of subcommand_required"),
    }

    Ok(())
}
