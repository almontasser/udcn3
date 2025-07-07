use criterion::{black_box, criterion_group, criterion_main, Criterion};
use udcn_core::{NetworkManager, NetworkNode};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn benchmark_network_manager(c: &mut Criterion) {
    c.bench_function("network_manager_add_node", |b| {
        b.iter(|| {
            let mut manager = NetworkManager::new();
            let node = NetworkNode {
                id: "test_node".to_string(),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                capabilities: vec!["test".to_string()],
            };
            manager.add_node(black_box(node));
        })
    });

    c.bench_function("network_manager_get_node", |b| {
        let mut manager = NetworkManager::new();
        let node = NetworkNode {
            id: "test_node".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            capabilities: vec!["test".to_string()],
        };
        manager.add_node(node);
        
        b.iter(|| {
            let _ = manager.get_node(black_box("test_node"));
        })
    });
}

criterion_group!(benches, benchmark_network_manager);
criterion_main!(benches);