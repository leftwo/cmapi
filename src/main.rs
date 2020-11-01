extern crate restson;
#[macro_use]
extern crate serde_derive;
use process::exit;
use restson::{Error, RestClient, RestPath};
use std::collections::HashMap;
use std::{env, process};

const CM_URL: &'static str = "CRYPTOMOVE_URL";
const CM_USER: &'static str = "CRYPTOMOVE_USERNAME";
const CM_PASS: &'static str = "CRYPTOMOVE_PASSWORD";

// Requesting a token is done using these

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

// Show secrets is done using these
#[derive(Serialize, Debug)]
struct Show<'a> {
    email: &'a String,
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

// Put secrets uses these
#[derive(Serialize, Debug)]
struct Put {
    email: String,
    key_name: String,
    key_value: String,
}

impl RestPath<()> for Put {
    fn get_path(_: ()) -> Result<String, Error> {
        Ok(String::from("api/v1/user/secret/protect"))
    }
}

// Get secrets uses these
#[derive(Serialize, Debug)]
struct Get {
    email: String,
    key_name: String,
}

#[derive(Debug, serde_derive::Deserialize)]
struct GetResult {
    key_name: String,
    key_value: String,
    status: String,
}

impl RestPath<()> for Get {
    fn get_path(_: ()) -> Result<String, Error> {
        Ok(String::from("api/v1/user/secret/expose"))
    }
}

fn show_keys(client: &mut RestClient, username: &String) {
    let data = Show { email: username };
    let res: ShowKeys = client.post_capture((), &data).unwrap();

    println!("{:25} {:5} {}", "Date Created", "Link", "Name");
    for (key, value) in res.keys {
        println!("{} {:5} {}", value.last_saved_time, value.is_link, key);
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

fn read_env(env_name: &str) -> String {
    let env_val = match env::var_os(env_name) {
        Some(val) => val,
        None => {
            println!("{} is not defined in the environment.", env_name);
            exit(1);
        }
    };

    let env_val = match env_val.clone().into_string() {
        Ok(val) => val,
        Err(e) => {
            println!("{:?} is not valid string. {:?}", env_val, e);
            exit(1);
        }
    };
    env_val
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

    show_keys(&mut client, &cm_username);
    /*
        let data = Put {
            email: String::from("cmtest002@cryptomove.com"),
            key_name: String::from("rust"),
            key_value: String::from("tsur"),
        };
        let res = client.post((), &data).expect("Failed to put secret");
        println!("{:?}", res);
    */
    let data = Get {
        email: cm_username,
        key_name: String::from("rust"),
    };
    // let res = client.post_capture((), &data).context("Failed to find secret")?;
    let result: std::result::Result<GetResult, restson::Error> = client.post_capture((), &data);
    match result {
        Ok(success) => println!("Success {:?}", success),
        Err(error) => {
            println!("Could not find secret rust:\n{}", error);
        }
    }

    Ok(())
}
