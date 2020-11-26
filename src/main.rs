extern crate restson;
#[macro_use]
extern crate serde_derive;

use chrono::{DateTime, NaiveDateTime};
use process::exit;
use restson::{Error, RestClient, RestPath};
use std::collections::HashMap;
use std::io::Write;
use std::{env, io, process};

const CM_URL: &str = "CRYPTOMOVE_URL";
const CM_USER: &str = "CRYPTOMOVE_USERNAME";
const CM_PASS: &str = "CRYPTOMOVE_PASSWORD";
const TIME_FMT: &str = "%m/%d/%y %H:%M";

// Structures and methods for Tokens
#[derive(Serialize, Debug)]
struct Login<'a> {
    email: &'a str,
    password: &'a str,
}
#[derive(Deserialize, Debug)]
struct LoginToken {
    access_token: String,
    expires_in: i32,
    id_token: String,
    refresh_token: String,
    scope: String,
    token_type: String,
}
impl RestPath<()> for Login<'_> {
    fn get_path(_: ()) -> Result<String, Error> {
        Ok(String::from("api/v1/user/login"))
    }
}

fn get_token(url: &str, email: &str, password: &str) -> Result<RestClient, Error> {
    let mut client = RestClient::new(url)?;

    let data = Login { email, password };

    let res: LoginToken = client.post_capture((), &data).expect("failed to get token");

    client
        .set_header("authorization", &res.access_token)
        .expect("failed to set headers");
    client
        .set_header("content-type", "application/json")
        .expect("failed to set headers");

    Ok(client)
}

// Structures and methods for Showing secrets
#[derive(Serialize, Debug)]
struct Show<'a> {
    email: &'a str,
}

#[derive(Debug, serde_derive::Deserialize)]
struct ShowKeys {
    keys: HashMap<String, KeyInfo>,
    status: String,
}

#[derive(Debug, serde_derive::Deserialize)]
struct KeyInfo {
    is_link: bool,
    last_saved_time: String,
    total_versions: u32,
    metadata: KeyMetadata,
}
#[derive(Debug, serde_derive::Deserialize)]
struct KeyMetadata {
    application_type: String,
    classification: String,
    cloud_type: String,
    description: String,
    environment_type: String,
    expiration_time: String,
}

impl RestPath<()> for Show<'_> {
    fn get_path(_: ()) -> Result<String, Error> {
        Ok(String::from("api/v1/user/secret/list_no_dup"))
    }
}

fn show_keys(client: &mut RestClient, username: &str) {
    let data = Show { email: username };
    let res: ShowKeys = client.post_capture((), &data).unwrap();

    // Default to the column header size
    let mut max = 5;
    for key in res.keys.keys() {
        if key.len() > max {
            max = key.len();
        }
    }

    println!(
        "{0:1$} {2:>14} {3:>5}",
        "Name", max, "Creation Time", "Link"
    );
    let header_width = max + 1 + 14 + 1 + 5;
    println!("{0:->1$}", "-", header_width);

    // XXX Added time here, we will come back to it and re-work this.
    // I think I want to make a big list of all keys, links, shared, etc
    // put files on that as well.
    for (key, value) in res.keys {
        let time = match DateTime::parse_from_rfc3339(&value.last_saved_time) {
            Ok(t) => t.timestamp(),
            Err(e) => {
                println!("Error finding time: {}", e);
                0
            }
        };
        let sec = NaiveDateTime::from_timestamp(time, 0);
        println!(
            "{0:1$} {2:>14} {3}",
            key,
            max,
            sec.format(TIME_FMT).to_string(),
            value.is_link,
        );
    }
}

// Structures and methods for listing files
#[derive(Serialize, Debug)]
struct File<'a> {
    email: &'a str,
}
#[derive(Debug, serde_derive::Deserialize)]
struct ShowFiles {
    // files returns an array of FileInfo structs
    files: Vec<FileInfo>,
    status: String,
    user_id: String,
}
#[derive(Debug, serde_derive::Deserialize)]
struct FileInfo {
    created_at: i64,
    filename: String,
    num_chunks: u32,
    size: String,
    stream_available: bool,
    version: u32,
}
impl RestPath<()> for File<'_> {
    fn get_path(_: ()) -> Result<String, Error> {
        Ok(String::from("api/v1/user/list_file"))
    }
}

fn show_files(client: &mut RestClient, username: &str) {
    let data = File { email: username };
    let res: ShowFiles = client.post_capture((), &data).unwrap();

    let all_files = res.files;
    if all_files.is_empty() {
        println!("No files found");
        return;
    }

    let mut max = 5;
    for file in &all_files {
        if file.filename.len() > max {
            max = file.filename.len();
        }
    }
    println!("{0:1$}  Creation Time Chk     Size Stream V", "Name", max);
    let header_width = max + 1 + 14 + 1 + 3 + 1 + 8 + 1 + 6 + 1 + 1;
    println!("{0:->1$}", "-", header_width);
    for file in &all_files {
        let sec = NaiveDateTime::from_timestamp(file.created_at, 0);
        println!(
            "{0:1$} {2} {3:>3} {4:>8} {5:>6} {6}",
            file.filename,
            max,
            sec.format(TIME_FMT).to_string(),
            file.num_chunks,
            file.size,
            file.stream_available,
            file.version,
        );
    }
}

// Structures and methods for putting secrets
#[derive(Serialize, Debug)]
struct Put<'a> {
    email: &'a str,
    key_name: &'a str,
    key_value: String,
}

impl RestPath<()> for Put<'_> {
    fn get_path(_: ()) -> Result<String, Error> {
        Ok(String::from("api/v1/user/secret/protect"))
    }
}

fn put_key(client: &mut RestClient, username: &str, key: &str) {
    println!("Enter the value for secret {:?}", key);
    let mut secret = String::new();
    io::stdin().read_line(&mut secret).unwrap();
    if secret.len() <= 1 {
        println!("Failed to read any data for secret");
        return;
    }
    secret.truncate(secret.len() - 1);

    let data = Put {
        email: username,
        key_name: key,
        key_value: secret,
    };
    let result = client.post((), &data);
    match result {
        Ok(_) => {
            println!("Put secret at name {:?}", key);
        }
        Err(error) => {
            println!("Error with put for secret {}\n{}", key, error);
        }
    }
}

// Structures and methods for deleting secrets
#[derive(Serialize, Debug)]
struct Delete<'a> {
    email: &'a str,
    key_name: &'a str,
}

impl RestPath<()> for Delete<'_> {
    fn get_path(_: ()) -> Result<String, Error> {
        Ok(String::from("api/v1/user/secret/delete"))
    }
}

fn delete_key(client: &mut RestClient, username: &str, key: &str) {
    let data = Delete {
        email: username,
        key_name: key,
    };
    let result = client.post((), &data);
    match result {
        Ok(_) => {
            println!("Deleted {:?}", key);
        }
        Err(error) => {
            println!("Error deleting secret {}\n{}", key, error);
        }
    }
}

// Structures and methods for getting keys
#[derive(Serialize, Debug)]
struct Get<'a> {
    email: &'a str,
    key_name: &'a str,
}

#[derive(Debug, serde_derive::Deserialize)]
struct GetResult {
    key_name: String,
    key_value: String,
    status: String,
}

impl RestPath<()> for Get<'_> {
    fn get_path(_: ()) -> Result<String, Error> {
        Ok(String::from("api/v1/user/secret/expose"))
    }
}

fn get_key(client: &mut RestClient, username: &str, key: &str) {
    let data = Get {
        email: username,
        key_name: key,
    };
    let result: std::result::Result<GetResult, restson::Error> = client.post_capture((), &data);
    match result {
        Ok(success) => {
            println!("{}", success.key_value);
        }
        Err(error) => {
            println!("Could not find secret {}\n{}", key, error);
        }
    }
}

// Check the env variables for what we need to connect to
// the REST API server.
fn read_env(env_name: &str) -> String {
    let env_val = match env::var_os(env_name) {
        Some(val) => val,
        None => {
            println!("{} is not defined in the environment.", env_name);
            exit(1);
        }
    };

    match env_val.clone().into_string() {
        Ok(val) => val,
        Err(e) => {
            println!("{:?} is not valid string. {:?}", env_val, e);
            exit(1);
        }
    }
}

// from: https://stackoverflow.com/questions/38447780,
// updated to use nth().
fn crop_letters(s: &str, pos: usize) -> &str {
    match s.char_indices().nth(pos) {
        Some((pos, _)) => &s[pos..],
        None => "",
    }
}

fn show_help() {
    println!("Valid commands are:");
    println!("-------------------------------------------------------------------");
    println!("show                 | Show all secrets");
    println!("file                 | Show file secrets");
    println!("get <SECRET_NAME>    | Get the value of the secret name provided");
    println!("put <SECRET_NAME>    | Put a secret at the name provided,");
    println!("                     | you will be asked for the secrets contents");
    println!("delete <SECRET_NAME> | Delete the value of the secret name provided");
    println!("q | quit             | Quit the program");
    println!("-------------------------------------------------------------------");
}

fn cli(client: &mut RestClient, username: &str) {
    show_help();
    loop {
        print!("cmcli> ");
        io::stdout().flush().unwrap();

        let mut line = String::new();
        io::stdin().read_line(&mut line).unwrap();
        let line = line.trim();

        let cmd = match line.split_ascii_whitespace().next() {
            Some(val) => val,
            None => {
                println!("Enter a command, q for quit");
                continue;
            }
        };

        // First comes the command, if there is anythign else, it's the
        // name of a secret to get, put, or delete.  We want whatever comes
        // after the command as a whole string including any spaces.
        // Though, I'm pretty sure I still need to deal with leading
        // spaces.  Still need to figure out how to allow a leading space
        // in a secret name.
        let cmdl = cmd.len();
        let args = crop_letters(&line, cmdl).trim();

        match cmd {
            "show" => {
                show_keys(client, &username);
            }
            "file" => {
                show_files(client, &username);
            }
            "get" => {
                if args.is_empty() {
                    println!("Missing secret name to get");
                    continue;
                };
                get_key(client, &username, &args);
            }
            "put" => {
                if args.is_empty() {
                    println!("Missing secret name to put");
                    continue;
                };
                println!("go put {:?}", args);
                put_key(client, &username, &args);
            }
            "delete" => {
                if args.is_empty() {
                    println!("Missing secret name to delete");
                    continue;
                };
                delete_key(client, &username, &args);
            }
            "q" | "quit" => {
                println!("quit");
                break;
            }
            _ => {
                println!("Unknown command {:?}", cmd);
                show_help();
            }
        };
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cm_url = read_env(CM_URL);
    let cm_username = read_env(CM_USER);
    let cm_password = read_env(CM_PASS);

    println!(
        "Using cm_url:{:?} with cm_username:{:?}",
        cm_url, cm_username
    );

    let mut client = get_token(&cm_url, &cm_username, &cm_password)?;

    cli(&mut client, &cm_username);

    Ok(())
}
