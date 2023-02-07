use processes::{self, Process};

pub fn main() {
    let current_bitness = processes::current();

    for process in processes::all() {
        println!("{}", process.base_name().unwrap());
        for module in process.modules().unwrap() {
            println!("\t{}", module.base_name().unwrap());
        }
        println!();
    }
}
