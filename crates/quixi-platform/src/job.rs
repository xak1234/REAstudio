//! Process-tree ownership. On Windows a child is placed in a Job Object configured with
//! KILL_ON_JOB_CLOSE, so dropping (or terminating) the job ends every descendant, including
//! grandchildren that outlive their parent (Ghidra JVMs, MSBuild nodes, Start-Process).
use anyhow::Result;
use std::process::Child;

pub struct ProcessJob {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

// The job handle is a kernel object reference; Win32 permits use from any thread.
unsafe impl Send for ProcessJob {}
unsafe impl Sync for ProcessJob {}

impl ProcessJob {
    /// Place `child` in a new kill-on-close job. Descendants created after this call inherit it.
    #[cfg(windows)]
    pub fn assign(child: &Child) -> Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                anyhow::bail!("CreateJobObjectW failed: {}", std::io::Error::last_os_error());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 || AssignProcessToJobObject(handle, child.as_raw_handle() as _) == 0 {
                let error = std::io::Error::last_os_error();
                CloseHandle(handle);
                anyhow::bail!("Job Object assignment failed: {error}");
            }
            Ok(Self { handle })
        }
    }

    #[cfg(not(windows))]
    pub fn assign(_child: &Child) -> Result<Self> {
        Ok(Self {})
    }

    /// Terminate every process in the job immediately. Safe to call more than once.
    pub fn terminate(&self) {
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle, 1);
        }
    }
}

impl Drop for ProcessJob {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            // Closing the last handle applies KILL_ON_JOB_CLOSE to any survivors.
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn dropping_job_kills_descendants() {
        // PowerShell starts a detached grandchild; the job must still reach it.
        let mut child = crate::background_command("powershell.exe")
            .args(["-NoProfile", "-Command", "$p = Start-Process ping -ArgumentList '-n','30','127.0.0.1' -PassThru -WindowStyle Hidden; $p.Id; Start-Sleep 30"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let job = ProcessJob::assign(&child).unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(child.stdout.take().unwrap()), &mut line).unwrap();
        let grandchild: u32 = line.trim().parse().unwrap();
        drop(job);
        let _ = child.wait();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let listing = crate::background_command("tasklist.exe")
            .args(["/FI", &format!("PID eq {grandchild}"), "/NH"])
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&listing.stdout).contains(&grandchild.to_string()));
    }
}
