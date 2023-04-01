use processes::{self, Process};

pub fn main() {
    for process in processes::all().unwrap() {
        println!("{}", process.base_name().unwrap());
        for module in process.modules().unwrap() {
            println!("\t{}", module.base_name().unwrap());
        }
        println!();
    }
}
