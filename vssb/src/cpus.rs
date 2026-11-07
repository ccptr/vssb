//! Picking CPUs to pin a sandbox to: the cpus limit without a cgroup.
//! Runs in the parent, before clone; the child only applies the mask.

use crate::config::CpuChoice;
use crate::error::{Error, Result};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Whole CPUs for a cpus limit: rounded, at least 1.
pub(crate) fn count(cpus: f64) -> usize {
    (cpus.round() as usize).max(1)
}

/// The CPUs the calling thread may run on.
fn allowed() -> Result<Vec<u32>> {
    let mut mask = vec![0u64; 128]; // 8192 CPUs
    let r = unsafe { libc::syscall(libc::SYS_sched_getaffinity, 0, mask.len() * 8, mask.as_mut_ptr()) };
    if r < 0 {
        return Err(Error::io("sched_getaffinity", std::io::Error::last_os_error()));
    }
    Ok((0..mask.len() as u32 * 64).filter(|&c| mask[(c / 64) as usize] & (1 << (c % 64)) != 0).collect())
}

/// Identifies the physical core of a CPU: the CPUs it shares the core
/// with, as the kernel lists them.
fn core_of(cpu: u32) -> String {
    let t = format!("/sys/devices/system/cpu/cpu{cpu}/topology");
    std::fs::read_to_string(format!("{t}/core_cpus_list"))
        .or_else(|_| std::fs::read_to_string(format!("{t}/thread_siblings_list")))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| cpu.to_string())
}

/// Where the rotation starts: random per process, so separate processes
/// spread too, then advancing with each sandbox.
fn next_start(step: usize) -> usize {
    static BASE: OnceLock<usize> = OnceLock::new();
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let base = *BASE.get_or_init(|| {
        let mut b = [0u8; 8];
        unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
        usize::from_ne_bytes(b) % 4096
    });
    base.wrapping_add(NEXT.fetch_add(step, Ordering::Relaxed))
}

/// The CPUs for a cpus limit of `cpus`, chosen as `choice` says.
pub(crate) fn choose(cpus: f64, choice: &CpuChoice) -> Result<Vec<u32>> {
    let allowed = allowed()?;
    let n = count(cpus);
    if let CpuChoice::List(list) = choice {
        return from_list(n, &allowed, list);
    }
    let cores = group(&allowed, core_of);
    let start = next_start(0);
    let (mut picked, used) = pick(n, &cores, choice, start);
    next_start(used);
    picked.sort_unstable();
    Ok(picked)
}

fn from_list(n: usize, allowed: &[u32], list: &[u32]) -> Result<Vec<u32>> {
    let mut out: Vec<u32> = Vec::new();
    for &c in list {
        if !allowed.contains(&c) {
            return Err(Error::Config(format!("CPU {c} is not one this thread may run on ({allowed:?})")));
        }
        if !out.contains(&c) {
            out.push(c);
        }
    }
    if out.is_empty() {
        return Err(Error::Config("the CPU list is empty".into()));
    }
    out.truncate(n);
    Ok(out)
}

/// Groups CPUs by physical core, cores in order of their lowest CPU.
fn group(cpus: &[u32], core: impl Fn(u32) -> String) -> Vec<Vec<u32>> {
    let mut keys: Vec<String> = Vec::new();
    let mut cores: Vec<Vec<u32>> = Vec::new();
    for &c in cpus {
        let k = core(c);
        match keys.iter().position(|x| *x == k) {
            Some(i) => cores[i].push(c),
            None => {
                keys.push(k);
                cores.push(vec![c]);
            }
        }
    }
    cores
}

/// Picks `n` CPUs from `cores`, starting at core `start` (modulo their
/// number). Returns them and the number of cores they cover.
fn pick(n: usize, cores: &[Vec<u32>], choice: &CpuChoice, start: usize) -> (Vec<u32>, usize) {
    let k = cores.len();
    if k == 0 {
        return (Vec::new(), 0);
    }
    let order: Vec<&Vec<u32>> = (0..k).map(|i| &cores[(start + i) % k]).collect();
    let mut out = Vec::new();
    match choice {
        CpuChoice::Pack => {
            for core in &order {
                out.extend(core.iter().copied());
            }
        }
        _ => {
            let depth = cores.iter().map(Vec::len).max().unwrap_or(0);
            for t in 0..depth {
                out.extend(order.iter().filter_map(|core| core.get(t).copied()));
            }
        }
    }
    out.truncate(n);
    let used = order.iter().filter(|core| core.iter().any(|c| out.contains(c))).count();
    (out, used)
}

/// An affinity mask for `cpus`, as sched_setaffinity takes it.
pub(crate) fn mask(cpus: &[u32]) -> Vec<u64> {
    let words = cpus.iter().max().map_or(1, |&m| m as usize / 64 + 1);
    let mut v = vec![0u64; words];
    for &c in cpus {
        v[c as usize / 64] |= 1 << (c % 64);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 4 cores with 2 hyperthreads each, numbered like most x86 machines:
    /// CPU c and c+4 share a core.
    fn smt() -> Vec<Vec<u32>> {
        group(&(0..8).collect::<Vec<_>>(), |c| (c % 4).to_string())
    }

    #[test]
    fn rounding() {
        assert_eq!([0.2, 0.5, 1.4, 1.5, 2.6].map(count), [1, 1, 1, 2, 3]);
    }

    #[test]
    fn spread_uses_separate_cores_first() {
        assert_eq!(pick(2, &smt(), &CpuChoice::Spread, 0), (vec![0, 1], 2));
        assert_eq!(pick(4, &smt(), &CpuChoice::Spread, 0), (vec![0, 1, 2, 3], 4));
        assert_eq!(pick(6, &smt(), &CpuChoice::Spread, 0), (vec![0, 1, 2, 3, 4, 5], 4));
        assert_eq!(pick(2, &smt(), &CpuChoice::Spread, 2), (vec![2, 3], 2));
    }

    #[test]
    fn pack_fills_cores_first() {
        assert_eq!(pick(2, &smt(), &CpuChoice::Pack, 0), (vec![0, 4], 1));
        assert_eq!(pick(3, &smt(), &CpuChoice::Pack, 0), (vec![0, 4, 1], 2));
        assert_eq!(pick(2, &smt(), &CpuChoice::Pack, 3), (vec![3, 7], 1));
    }

    #[test]
    fn rotation_wraps_and_never_exceeds_the_cpus() {
        assert_eq!(pick(3, &smt(), &CpuChoice::Spread, 3), (vec![3, 0, 1], 3));
        assert_eq!(pick(20, &smt(), &CpuChoice::Pack, 1).0.len(), 8);
    }

    #[test]
    fn explicit_lists() {
        let allowed: Vec<u32> = (0..8).collect();
        assert_eq!(from_list(2, &allowed, &[5, 5, 1, 2]).unwrap(), [5, 1]);
        assert_eq!(from_list(4, &allowed, &[3]).unwrap(), [3]);
        assert!(from_list(1, &allowed, &[9]).is_err());
        assert!(from_list(1, &allowed, &[]).is_err());
    }

    #[test]
    fn masks() {
        assert_eq!(mask(&[0, 3]), [0b1001]);
        assert_eq!(mask(&[65]), [0, 0b10]);
    }
}
