use criterion::{Criterion, criterion_group, criterion_main};
use smpc_core::{PartyId, SessionId};
use smpc_testing::test_sessions;

fn bench_dot(c: &mut Criterion) {
    c.bench_function("simulator dot 1024", |b| {
        b.iter(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let [mut p0, mut p1, mut p2] =
                    test_sessions(SessionId::from_u64_for_testing(555)).unwrap();
                let lhs: Vec<_> = (0..1024).collect();
                let rhs: Vec<_> = (0..1024).map(|value| value * 3).collect();
                let t0 = tokio::spawn(async move {
                    let x = p0.private_inputs(PartyId::P0, &lhs).await?;
                    let y = p0.private_inputs(PartyId::P1, &vec![0; 1024]).await?;
                    let z = p0.dot(&x, &y).await?;
                    p0.open(&z).await
                });
                let t1 = tokio::spawn(async move {
                    let x = p1.private_inputs(PartyId::P0, &vec![0; 1024]).await?;
                    let y = p1.private_inputs(PartyId::P1, &rhs).await?;
                    let z = p1.dot(&x, &y).await?;
                    p1.open(&z).await
                });
                let t2 = tokio::spawn(async move {
                    let x = p2.private_inputs(PartyId::P0, &vec![0; 1024]).await?;
                    let y = p2.private_inputs(PartyId::P1, &vec![0; 1024]).await?;
                    let z = p2.dot(&x, &y).await?;
                    p2.open(&z).await
                });
                let _ = tokio::try_join!(t0, t1, t2).unwrap();
            });
        });
    });
}

criterion_group!(benches, bench_dot);
criterion_main!(benches);
