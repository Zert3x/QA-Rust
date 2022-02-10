use machineid_rs::{Encryption, HWIDComponent, IdBuilder};

pub(crate) fn get_id() -> std::string::String  {
    let mut builder = IdBuilder::new(Encryption::SHA256);
    builder.add_component(HWIDComponent::CPUCores);
    builder.add_component(HWIDComponent::DriveSerial);
    builder.add_component(HWIDComponent::MacAddress);
    builder.add_component(HWIDComponent::CPUID);
    builder.add_component(HWIDComponent::OSName);
    builder.add_component(HWIDComponent::SystemID);
    builder.add_component(HWIDComponent::Username);
    builder.add_component(HWIDComponent::MachineName);
    builder.build("QuartzAuth").unwrap_or_else(|_| String::new())
}
