use criterion::{black_box, criterion_group, criterion_main, Criterion};
use udcn_transport::{TcpTransport, UdpTransport, UnixTransport};

fn benchmark_transport_creation(c: &mut Criterion) {
    c.bench_function("tcp_transport_new", |b| {
        b.iter(|| {
            let _transport = TcpTransport::new();
        })
    });

    c.bench_function("udp_transport_new", |b| {
        b.iter(|| {
            let _transport = UdpTransport::new();
        })
    });

    c.bench_function("unix_transport_new", |b| {
        b.iter(|| {
            let _transport = UnixTransport::new();
        })
    });
}

criterion_group!(benches, benchmark_transport_creation);
criterion_main!(benches);
