use another_steam_totp::get_steam_server_time_offset;

#[tokio::main]
async fn main() {
    let time_offset = get_steam_server_time_offset().await.unwrap();
    
    println!("Your system's time is {time_offset} second(s) behind Steam's.");
}