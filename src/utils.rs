use machineid_rs::{Encryption, IdBuilder};

pub(crate) fn get_id() -> std::string::String {
    let mut builder = IdBuilder::new(Encryption::SHA256);
    builder.add_cpu_cores().add_machine_name()
    .add_os_name().add_system_id().add_cpu_id();
    builder.build("QuartzAuth")
}
