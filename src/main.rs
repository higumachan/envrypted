#[macro_use] extern crate hex_literal;
extern crate aes_soft as aes;
extern crate block_modes;

use std::str::FromStr;
use argparse::{ArgumentParser, Store, List, StoreTrue};
use std::collections::HashMap;
use serde_json::Value;
use std::error::Error;
use std::fs::File;
use std::io::{BufWriter, Write, Read};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use aes::Aes128;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;


#[allow(non_camel_case_types)]
#[derive(Debug)]
enum Command {
    export,
    set,
}

impl FromStr for Command {
    type Err = ();
    fn from_str(src: &str) -> Result<Command, ()> {
        return match src {
            "set" => Ok(Command::set),
            "export" => Ok(Command::export),
            _ => Err(()),
        };
    }
}


struct State {
    pub variables: HashMap<String, String>,
}

#[derive(Debug)]
enum EnvryptedError {
    Value,
}

impl State {
    fn load() -> Result<State, String> {
        let mut file = File::open("environ.json.enc").unwrap();

        let cipher = load_cipher();
        let mut bytes = [0u8; 1024];
        let pos = file.read(&mut bytes).unwrap();
        let dec_bytes = cipher.decrypt_vec(&mut bytes[..pos]).unwrap();

        let v: Value = serde_json::from_slice(dec_bytes.as_slice()).unwrap();
        let key_values = match v {
            Value::Object(envs) => {
                Some(envs)
            }
            _ => None,
        }.unwrap();

        let variables :HashMap<String, String> = key_values.iter().map(|x: (&String, &Value)| (x.0.to_string(), x.1.as_str().unwrap().to_string())).collect();

        Result::Ok(State { variables })
    }
    fn set_env(&mut self, name: &String, value: &String) {
        self.variables.insert(name.clone(), value.clone());
    }
    fn save(&self) {
        let cipher = load_cipher();
        let s = serde_json::to_string(&self.variables).unwrap();
        let mut bytes = [0u8; 1024];
        let pos = s.len();
        bytes[..pos].copy_from_slice(s.as_bytes());
        let enc_bytes = cipher.encrypt(&mut bytes, pos).unwrap();

        let mut file = File::create("environ.json.enc").unwrap();
        file.write_all(enc_bytes);
        file.flush().unwrap();
    }
}

fn load_cipher() -> Aes128Cbc {
    let key = hex!("000102030405060708090a0b0c0d0e0f");
    let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    Aes128Cbc::new_var(&key, &iv).unwrap()
}


fn parse_set_env_expr(set_env_expr: &String) -> (String, String)
{
    let splitted: Vec<_> = set_env_expr.split("=").collect();
    (splitted[0].to_string(), splitted[1].to_string())
}

fn set_command(verbose: bool, args: Vec<String>) {
    let mut envs_str: Vec<String> = vec!();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Set variables");

        ap.refer(&mut envs_str).add_argument("set_environ_expressions", List, "");
        ap.parse_args_or_exit();
    }

    let mut state = State::load().unwrap();

    for (name, value) in envs_str.iter().skip(1).map(parse_set_env_expr) {
        state.set_env(&name, &value);
    }

    state.save();
}

fn export_command(verbose: bool, args: Vec<String>) {
    let mut state = State::load().unwrap();

    for (name, value) in state.variables.iter() {
        println!("{}={}", name, value);
    }
}


fn main() {
    let mut subcommand = Command::export;
    let mut verbose = false;
    let mut args = vec!();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("This command is manage encrypted env variables.");
        ap.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue,
                        "Be verbose");
        ap.refer(&mut subcommand).required()
            .add_argument("command", Store, r#"Command to run"#);
        ap.refer(&mut args)
            .add_argument("arguments", List, r#"Arguments for command"#);
        ap.stop_on_first_argument(true);
        ap.parse_args_or_exit();
    }

    args.insert(0, format!("subcommand {:?}", subcommand));
    match subcommand {
        Command::set => set_command(verbose, args),
        Command::export => export_command(verbose, args),
    }
}
