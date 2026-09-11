use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use crate::{Result, TraceConfig};

use super::types::TraceJob;
use super::worker::execute_job;

pub(crate) struct JobOutcome {
    pub job: TraceJob,
    pub result: Result<dns_core::response::QueryResult>,
}

struct PoolState {
    pending: VecDeque<TraceJob>,
    shutdown: bool,
}

/// Fixed-size worker pool; workers never touch `TraceProgress`.
pub(crate) struct WorkerPool {
    state: Arc<(Mutex<PoolState>, Condvar)>,
    result_rx: Receiver<JobOutcome>,
    workers: Vec<JoinHandle<()>>,
}

impl WorkerPool {
    pub fn new(config: TraceConfig, worker_count: usize) -> Self {
        let config = Arc::new(config);
        let state = Arc::new((
            Mutex::new(PoolState {
                pending: VecDeque::new(),
                shutdown: false,
            }),
            Condvar::new(),
        ));
        let (result_tx, result_rx) = mpsc::channel();

        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let state = state.clone();
            let config = config.clone();
            let result_tx = result_tx.clone();
            workers.push(thread::spawn(move || worker_loop(state, config, result_tx)));
        }

        Self {
            state,
            result_rx,
            workers,
        }
    }

    pub fn submit(&self, job: TraceJob) {
        let (lock, cvar) = &*self.state;
        let mut guard = lock.lock().expect("worker pool lock");
        guard.pending.push_back(job);
        cvar.notify_one();
    }

    pub fn recv(&self) -> JobOutcome {
        self.result_rx
            .recv()
            .expect("worker pool result channel closed")
    }

    pub fn shutdown(self) {
        {
            let (lock, cvar) = &*self.state;
            let mut guard = lock.lock().expect("worker pool lock");
            guard.shutdown = true;
            cvar.notify_all();
        }
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}

fn worker_loop(
    state: Arc<(Mutex<PoolState>, Condvar)>,
    config: Arc<TraceConfig>,
    result_tx: Sender<JobOutcome>,
) {
    loop {
        let job = {
            let (lock, cvar) = &*state;
            let mut guard = lock.lock().expect("worker pool lock");
            loop {
                if let Some(job) = guard.pending.pop_front() {
                    break job;
                }
                if guard.shutdown {
                    return;
                }
                guard = cvar.wait(guard).expect("worker pool wait");
            }
        };

        let result = execute_job(&job, config.as_ref());
        if result_tx.send(JobOutcome { job, result }).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerTarget;
    use crate::job_queue::types::{JobId, JobKind};
    use dns_core::name::DomainName;
    use hickory_proto::rr::RecordType;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct SlowCountingExchange {
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    impl crate::DnsExchange for SlowCountingExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &dns_core::QueryOptions,
        ) -> dns_core::Result<dns_core::response::QueryResult> {
            let current = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            loop {
                let observed = self.max_active.load(Ordering::SeqCst);
                if current <= observed {
                    break;
                }
                if self
                    .max_active
                    .compare_exchange(observed, current, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(25));
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(dns_core::response::QueryResult {
                server,
                transport: options.transport,
                qname: options.qname.clone(),
                qtype: options.qtype.to_string(),
                rtt: Duration::from_millis(25),
                response: dns_core::response::DnsResponse {
                    id: 1,
                    rcode: 0,
                    rcode_text: "NOERROR".into(),
                    authoritative: true,
                    truncated: false,
                    recursion_desired: false,
                    recursion_available: false,
                    authentic_data: false,
                    checking_disabled: false,
                    answers: vec![dns_core::response::DnsRecord {
                        name: options.qname.clone(),
                        rtype: "A".into(),
                        rclass: "IN".into(),
                        ttl: 300,
                        rdata: "93.184.216.34".into(),
                    }],
                    authorities: vec![],
                    additionals: vec![],
                    edns: dns_core::EdnsMeta::default(),
                },
                from_cache: false,
            })
        }
    }

    fn parallel_job(id: u64) -> TraceJob {
        TraceJob {
            id: JobId(id),
            kind: JobKind::Trace,
            server: ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(1, 0, 0, id as u8))),
            qname: DomainName::parse("example.com.").expect("qname"),
            qtype: RecordType::A,
            zone: DomainName::parse(".").expect("zone"),
            path: vec![id as usize],
            fallback_servers: vec![],
            visited_zones: std::collections::HashSet::new(),
        }
    }

    #[test]
    fn never_exceeds_configured_worker_cap() {
        let exchange = StdArc::new(SlowCountingExchange {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let mut config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );
        config.exchange = exchange.clone();
        let pool = WorkerPool::new(config, 3);

        for id in 1..=13 {
            pool.submit(parallel_job(id));
        }

        for _ in 0..13 {
            let _ = pool.recv();
        }
        pool.shutdown();

        assert!(
            exchange.max_active.load(Ordering::SeqCst) <= 3,
            "max concurrent workers was {}",
            exchange.max_active.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn runs_multiple_jobs_concurrently() {
        let exchange = StdArc::new(SlowCountingExchange {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let mut config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );
        config.exchange = exchange.clone();
        let pool = WorkerPool::new(config, 8);

        for id in 1..=13 {
            pool.submit(parallel_job(id));
        }

        for _ in 0..13 {
            let _ = pool.recv();
        }
        pool.shutdown();

        assert!(
            exchange.max_active.load(Ordering::SeqCst) >= 2,
            "expected overlapping execution, saw {}",
            exchange.max_active.load(Ordering::SeqCst)
        );
    }
}
