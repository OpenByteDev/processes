use processes::{self, Process};

pub fn main() {
    let process = processes::find_first_by_name("firefox").unwrap().unwrap();
    for module in process.modules().unwrap() {
        println!("\t{}", module.base_name().unwrap());
    }
}
