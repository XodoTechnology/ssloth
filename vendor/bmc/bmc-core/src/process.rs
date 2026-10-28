//! Background command helpers for the native desktop application.

pub fn command(program: &str) -> std::process::Command {
    #[allow(unused_mut)]
    let mut command = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Keep IPMI/Redfish helpers from opening a console behind the GUI.
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    command
}
