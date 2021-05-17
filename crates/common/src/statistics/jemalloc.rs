use anyhow::anyhow;
use std::fmt::Write;
use thread_id;

pub fn dump_jemalloc_statistics() -> anyhow::Result<String> {
    jemalloc_ctl::epoch::advance().map_err(|e| anyhow!("{}", e))?;

    let mut s = String::new();

    if let Ok(allocated) = jemalloc_ctl::stats::allocated::read() {
        write!(s, "{} bytes of total allocated data\n", allocated)?;
    }

    if let Ok(resident) = jemalloc_ctl::stats::resident::read() {
        write!(s, "{} bytes of total resident data\n", resident)?;
    }
    if let Ok(active) = jemalloc_ctl::stats::active::read() {
        write!(s, "{} bytes of total active data\n", active)?;
    }

    if let Ok(mapped) = jemalloc_ctl::stats::mapped::read() {
        write!(s, "{} bytes of total mapped data\n", mapped)?;
    }

    if let Ok(metadata) = jemalloc_ctl::stats::metadata::read() {
        write!(s, "{} bytes of jemalloc metadata\n", metadata)?;
    }

    if let Ok(retained) = jemalloc_ctl::stats::retained::read() {
        write!(s, "{} bytes of total retained data\n", retained)?;
    }

    write!(s, "thread id {}\n", thread_id::get())?;

    if let Ok(thread_allocated) = jemalloc_ctl::thread::allocatedp::read() {
        write!(
            s,
            "{} bytes of current thread allocated data\n",
            thread_allocated.get()
        )?;
    }

    if let Ok(thread_deallocated) = jemalloc_ctl::thread::deallocatedp::read() {
        write!(
            s,
            "{} bytes of thread deallocated data\n",
            thread_deallocated.get()
        )?;
    }

    if let Ok(bg) = jemalloc_ctl::background_thread::read() {
        write!(s, "background_threads enabled: {}\n", bg)?;
    }

    if let Ok(version_mib) = jemalloc_ctl::version::read() {
        write!(s, "version mib: {}\n", version_mib)?;
    }

    if let Ok(m) = jemalloc_ctl::max_background_threads::read() {
        write!(s, "max_background_threads: {}\n", m)?;
    }

    if let Ok(arenas) = jemalloc_ctl::arenas::narenas::read() {
        write!(s, "number of arenas: {}", arenas)?
    }

    if let Ok(malloc_conf) = jemalloc_ctl::config::malloc_conf::read() {
        write!(s, "default malloc conf: {}\n", malloc_conf)?;
    }

    if let Ok(abort) = jemalloc_ctl::opt::abort::read() {
        write!(s, "abort on warning: {}\n", abort)?;
    }

    if let Ok(background_thread) = jemalloc_ctl::opt::background_thread::read() {
        write!(
            s,
            "background threads since initialization: {}\n",
            background_thread
        )?;
    }

    if let Ok(dss) = jemalloc_ctl::opt::dss::read() {
        write!(s, "dss priority: {}\n", dss)?;
    }

    if let Ok(junk) = jemalloc_ctl::opt::junk::read() {
        write!(s, "junk filling: {}\n", junk)?;
    }

    if let Ok(lg_tcache_max) = jemalloc_ctl::opt::lg_tcache_max::read() {
        write!(s, "max cached allocation size: {}\n", 1 << lg_tcache_max)?;
    }

    if let Ok(narenas) = jemalloc_ctl::opt::narenas::read() {
        write!(s, "number of arenas: {}\n", narenas)?;
    }

    if let Ok(tcache) = jemalloc_ctl::opt::tcache::read() {
        write!(s, "thread-local caching: {}\n", tcache)?;
    }

    if let Ok(zero) = jemalloc_ctl::opt::zero::read() {
        write!(s, "zeroing: {}\n", zero)?;
    }

    Ok(s)
}
