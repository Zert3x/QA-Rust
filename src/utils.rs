
use sysinfo::SystemExt;

pub fn get_id() -> std::string::String {
    let system = sysinfo::System::new_all();

    let disk_count = system.get_disks().len();
    let cpu_count = system.get_physical_core_count().unwrap_or(4);
    let ram_count = system.get_total_memory();
    let os_name = system
        .get_long_os_version()
        .unwrap_or_else(|| String::from(""));
    let host_name = system.get_host_name().unwrap_or_else(|| String::from(""));
    let payload = format!(
        "{}-{}-{}-{}-{}",
        disk_count, cpu_count, ram_count, os_name, host_name
    );
    let dig = md5::compute(payload);
    hex::encode(dig.0.iter().map(|x| *x as char).collect::<String>())
}
