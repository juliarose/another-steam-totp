use another_steam_totp::{Error, get_steam_server_time_offset_sync};

fn main() -> Result<(), Error> {
    let time_offset = get_steam_server_time_offset_sync()?;
    
    if time_offset == 0 {
        println!("Your system's time is the same as Steam's.");
    } else {
        println!("Your system's time is {time_offset} second(s) behind Steam's.");
    }
    
    Ok(())
}