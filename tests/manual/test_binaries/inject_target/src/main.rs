use std::str::FromStr;

fn main() {
    std::hint::black_box(add_five);
    std::hint::black_box(create_player);
    std::hint::black_box(uses_player);

    let value = std::hint::black_box(add_five(60 * 1_000_000));

    // This process just waits, so it can be injected into.
    //std::thread::sleep(std::time::Duration::from_secs(60 * 5));
    //std::thread::sleep(std::time::Duration::from_secs(60 * 1_000_000));
    std::thread::sleep(std::time::Duration::from_secs(value as u64));
}

// static gives us a global address rather than in-lining the value
#[used]
static FIVE: u32 = 5;

static mut MUTATED: u32 = 0;


#[repr(C)]
pub struct Pet {
    name: String,
    health: f32,
}

#[repr(C)]
pub struct Player {
    pub ammo: u32,
    pub health: f32,
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub pet: Pet
}

impl Player {
    #[no_mangle]
    pub fn new() -> Player {
        Player {
            ammo: 100,
            health: 100.0,
            x: 250.0,
            y: -250.0,
            z: 0.0,
            pet: Pet { name: String::from_str("Test").unwrap(), health: 200.0 }
        }
    }
}

// TODO: keep these from getting compiled away
#[no_mangle]
extern "C" fn add_five(value: u32) -> u32 {
    value + FIVE
}

#[no_mangle]
extern "C" fn create_player() -> () {
    let player = Player::new();

    uses_player(&player);
}

#[no_mangle]
extern "C" fn uses_player(player: &Player) -> () {
    // cmp with object offset
    if player.health > 100.0 {
        let new_value = add_five(player.ammo);

        unsafe { MUTATED += new_value; }
    }
}
