mod client;
mod server;
mod shared;

use std::env;

pub type BoxedError = Box<dyn std::error::Error>;
pub type BoxedResult<T> = Result<T, BoxedError>;

fn main() -> BoxedResult<()> {
    let args: Vec<String> = env::args().collect();

    match
    if args.contains(&String::from("--server")) {server::start()}
    else {client::start()}
    {
        Ok(_) => (),
        Err(e) => println!("Program encountered an error: {e:?}"),
    }

    Ok(())
}
