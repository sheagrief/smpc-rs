use smpc_core::{PartyId, Result, SessionId};
use smpc_testing::test_sessions;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let [mut p0, mut p1, mut p2] = test_sessions(SessionId::from_u64_for_testing(100))?;

    let party0 = tokio::spawn(async move {
        let xs = p0.private_inputs(PartyId::P0, &[1, 2, 3, 4]).await?;
        let ys = p0.private_inputs(PartyId::P1, &[0, 0, 0, 0]).await?;
        let dot = p0.dot(&xs, &ys).await?;
        p0.open(&dot).await
    });
    let party1 = tokio::spawn(async move {
        let xs = p1.private_inputs(PartyId::P0, &[0, 0, 0, 0]).await?;
        let ys = p1.private_inputs(PartyId::P1, &[5, 6, 7, 8]).await?;
        let dot = p1.dot(&xs, &ys).await?;
        p1.open(&dot).await
    });
    let party2 = tokio::spawn(async move {
        let xs = p2.private_inputs(PartyId::P0, &[0, 0, 0, 0]).await?;
        let ys = p2.private_inputs(PartyId::P1, &[0, 0, 0, 0]).await?;
        let dot = p2.dot(&xs, &ys).await?;
        p2.open(&dot).await
    });

    let (party0, party1, party2) = tokio::join!(party0, party1, party2);
    let opened = [party0.unwrap()?, party1.unwrap()?, party2.unwrap()?];
    println!("opened dot product: {opened:?}");
    Ok(())
}
